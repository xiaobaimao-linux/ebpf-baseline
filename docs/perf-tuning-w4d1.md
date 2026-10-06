# W4 D1 吞吐调优记录（任务 2：10k/s × 5min 高优零丢失）

日期：2026-10-05。前置：任务 1 对账通过（`tests/perf/reconcile_drops.sh`，误差 0.000%）。
测试口径：除注明外均为 `run_tput_10k.sh` 同口径——300,000 ops / 30s / 10,000 ops/s，
每 op = open+write+close 产生 1 条 file 事件（W3 报告"每 op 约 2 条"的预期是错的，
实测 `kernel.file.emitted / ops = 1.000`）。每轮跑前 `rm -f events.db*`。
机器：8 核（共享开发机，存在 CPU 放置抽签，见"双模态"节）。

## 瓶颈定位

对账数据：30 万应发中 ~15 万丢在 `bus.queue_full.hi.p0_file`（EventBus hi 队列满，
用户态），内核背压全程 NORMAL、`backpressure_drop=0`——瓶颈在用户态消费速度。

pidstat -t（压测期，30s）：消费线程 TID 稳定 ~98% 单核（usr 83% + sys 13%），
主线程（ring poll→入队）仅 3-8%。即**消费线程单核打满**，消费速率 ~5.3-7.3k/s < 10k/s。

perf record 栈归并（消费线程 = 98.1% 总采样）：

| 路径 | 占比 |
|---|---|
| nlohmann JSON DOM 构建/销毁/dump（render_file_event + j.dump + map 节点） | ~45-50% |
| spdlog 同步日志（VIOLATION warn + "File access detected" 每事件 2 行写文件） | ~8.4% |
| SQLite WriteBatch/Flush（含 wal_checkpoint） | ~13% |
| 进程上下文/祖先链（build_file_actor + ancestors_of，R6 前每事件 2 次走树） | ~10-39% |
| 内核 syscall | ~12% |

## 调优轮次（一次一个变量，每轮 reconcile 复测，误差均 0.000%）

| 轮 | 改动 | 高优丢失 bus.hi.p0 | reserve_failed | stored | 结论 |
|---|---|---|---|---|---|
| R1 | （任务1 计数器补全后基线） | 152,369 | — | 147,631 | 对账基线 |
| R2 | getpwuid 结果进程内缓存（`cached_user_name`） | 噪声内 | — | — | 保留 |
| R3 | "File access detected"/"Alert throttled" 日志 warn→debug | 175,179 / 158,551 | 332 / 0 | 120,489 / 140,449 | **无效**：main.cpp:224 全局 `set_level(debug)`，debug 照样同步打印；保留降级（日志本就冗余） |
| R4a | `SendDingTalk` 节流判定前移到函数开头，节流期跳过 md/JSON 构建 | 145,792 | 214 | 153,994 | 栈占比 6.4%→1.1%，微效 |
| R4b | 落库渲染复用 `build_file_actor` 已算的祖先链，不再二次 `enrich` | 120,707 | 0 | 179,293 | 有效 |
| R5 | 落库 batch 500/200→2000/500 | 132,677 | 64 | 167,259 | **无效，已还原**（SQLite 不是瓶颈） |
| R6 | 祖先链按 (pid,start_time) 缓存（`cached_ancestors_of`，4096 上限清空） | 49,880 | 52 | 250,068 | 显著，~8.3k/s |
| R7 | `on_violation_detected` 节流窥探（`ThrottledNow`）跳过 AlertEvent 构建 | **0** | 304 | 299,696 | 单次双零；复跑证明是 CPU 放置运气（见双模态） |
| R8 | 主循环水位/ustats 同步由按循环次数改按时间（1s）触发 | 136,962 / 146,022 | 0 | 162,038 | 修复高压下周期任务饿死/过频抖动；bus 丢失双模态未解 |
| R9a | gen_load 钉 core7（仅测试 harness，非产品改动） | 80,614 | 123 | 219,263 | 减轻未消；消费线程仍 ~98% |
| R10 | **CAT_FILE payload 手写 JSON 直写**（替代 nlohmann DOM，逐字节一致，含同一 UTF-8 DFA）；祖先链缓存附带预序列化串（`ancestors_json`），告警路径不再 per-event dump | **0 / 0 / 0（3 连跑）** | 346 / 0 / 0 | 300,000 | 达成 30s 双零 |
| R11 | `FileActorContext.ancestors` 由 json 深拷贝改缓存指针（`const json*`，仅白名单路径解引用），消除每事件 DOM 拷贝/析构（R10 后栈上 ~15%） | 0 | 0 | 300,000 | 消费线程 CPU 降至 **~31%**（usr 22% + sys 9%），余量 ~3.2× |

同二进制不钉核 3 连跑（R8 后）：133,512 / 123,715 / 119,576——与 R7 的 0 构成
**双模态**。归因：消费线程单核打满时对 CFS 放置敏感，与 gen_load 等同核即降级；
R10+R11 把每事件成本降到 ~31µs 后，即使放置不佳也有 3 倍余量，双模态消失
（多轮 30s/5min 复跑验证）。

## R10 细节（最大单项收益）

- `src/baseline/monitor.cpp`：新增 `render_file_payload()`，直写 `std::string`（键序同
  nlohmann map 序：container/event_type/file/process/ts，子键同字母序）；
  转义用与 nlohmann `dump_escaped` 同一 Höhrmann UTF-8 DFA 状态表，无效字节替换
  U+FFFD、控制字符 `\u00xx`、`\b\t\n\f\r\"\\` 短转义——与旧 payload 逐字节一致。
  已验证：落库 299,654/299,654 条 `json_extract(payload,'$.file.path')` 全部命中、
  `json_valid=0` 为零、抽样肉眼比对键序一致。
- `FileActorContext`（`alert_manager.hpp`）：`ancestors` 改为 `const json*` 缓存指针
  + `ancestors_json` 预序列化串（缓存命中零拷贝零 dump）；
  `on_violation_detected` / `on_check_mismatch_detected` / `HandleBaselineDeviation`
  的 `ancestors.dump()` 全部改用预序列化串；白名单路径解引用指针（空链传空数组）。
- 语义红线保持：VIOLATION 日志、告警落库、events 表形状均未变；`tests/unit` 全过。

## 残余风险（留 D2 决策，未现场动手）

1. **ring buffer 256KB 偏小（5 分钟验收唯一残余丢失）**：约容纳 840 条
   `struct event`，即 10k/s 下 ~84ms 缓冲窗口。主线程 poll 消费能力远超
   10k/s（实测 ~3% CPU），reserve_failed 只发生在共享开发机调度抖动
   >84ms 的瞬间。实测：30s 口径 0 / 304 / 346 / 0；5 分钟口径 1,114 /
   2,990,000（0.037%），时间线采样呈阶跃（stall 窗口触发）。已确认未用
   `BPF_RB_NO_WAKEUP`（唤醒机制正常），用户态无解。若 PRD 要求内核侧也
   绝对零丢失，需扩 ring（建议 2-4MB，或 per-CPU buffer）——属内核侧改动，
   按约定留 D2。
2. **消费线程模型**：单线程串行 归一化→告警→落库。R11 后 10k/s 下仅 ~31%
   单核（余量 ~3.2×，hi 队列 32768 可吸收 ~3.3s 全停 stall）；若未来 rate
   目标翻倍，考虑渲染/落库拆线程（注意 ProcessTree 单线程无锁假设）。
3. **spdlog 同步日志**：VIOLATION 每事件 1 行同步写（R10 后栈上 ~18%）。
   改异步 logger 可再省，但属日志语义变更（崩溃时尾部丢失），未动。
4. `main.cpp:224` 全局 `set_level(debug)` 使 R3 的日志降级在默认运行下不生效；
   是否把日志级别做成配置项留 D2 定。

## 最终验收（R11 后，不钉核）

```
sudo bash tests/perf/reconcile_drops.sh 3000000 300 10000
```

| 指标 | 结果 |
|---|---|
| gen_load ops | 2,990,000（9,967 ops/s × 300s） |
| **bus.queue_full.hi.p0_file（高优总线丢弃）** | **0** |
| backpressure_drop / batch_overflow / store_failed | 0 / 0 / 0 |
| stored（落库成功） | 2,988,886 |
| kernel.file.reserve_failed（内核侧，留 D2） | 1,114（0.037%） |
| 对账误差 | 0.000% PASS（2,990,000 = 1,114 + 2,988,886） |
| 消费线程 CPU | ~31% 单核（余量 ~3.2×） |

## 复现

```bash
# 对账（默认 30 万 ops/30s/1 万 ops；PIN_CORE=7 可消除开发机 CPU 放置抽签）
rm -f events.db* && sudo bash tests/perf/reconcile_drops.sh
# 5 分钟验收
rm -f events.db* && sudo bash tests/perf/reconcile_drops.sh 3000000 300 10000
```

## R12（W4 D2）：file ring buffer 256KB → 2MB，reserve_failed 清零

日期：2026-10-05。针对"残余风险 1"。唯一改动：`bpf/bpf_common.h:86`
`__uint(max_entries, 256 * 1024)` → `2 * 1024 * 1024`（仅 file 探针的 rb；
proc/net/priv 本就是各自独立的 4MB ring `1 << 22`）。`struct event`=328B，
ringbuf 记录按 8B 对齐 ≈336B/条：256KB≈780 条≈84ms@10k/s → 2MB≈6,240 条
≈640ms@10k/s，吸收调度抖动能力 ×8。编译后 bpftool 自检：rb
max_entries=2,097,152、memlock=2,117,952B，探针加载正常。

### 选型对比（用数据选型）

| 方案 | 缓冲窗口@10k/s | 内存增量 | 全局有序 | 结论 |
|---|---|---|---|---|
| A：单 ring 2MB | ~640ms（×8） | +1.75MB | 保持（仅扩容量） | **采用**，3 轮 reserve_failed 全零 |
| B：per-CPU 512KB×8 | 每核 ~1.2s（按 1.25k/s/核摊） | +4MB | **丢失**：跨核到达乱序，消费端单线程串行做告警/基线偏差/进程树关联均带时序状态 | 排除 |
| A′：单 ring 4MB | ~1.28s | +3.75MB | 保持 | 备选，A 已达标未启用 |

B 另有一个历史佐证：W3 已记录 perf buffer（per-CPU 传输）静默丢失且计数
缺口的问题，ringbuf 是为此引入的；退回 per-CPU 传输属开倒车。

### 3 轮验收（`reconcile_drops.sh 3000000 300 10000`，不钉核，每轮 rm events.db*）

| 轮 | gen_load ops | emitted | reserve_failed | bp_drop | bus.hi.p0_file | batch/store_failed | stored | 对账误差 |
|---|---|---|---|---|---|---|---|---|
| 1 | 2,997,000 | 2,997,000 | **0** | 0 | 0 | 0 / 0 | 2,997,000 | 0.000% |
| 2 | 2,995,000 | 2,995,000 | **0** | 0 | 0 | 0 / 0 | 2,995,000 | 0.000% |
| 3 | 2,993,000 | 2,993,000 | **0** | 0 | 0 | 0 / 0 | 2,993,000 | 0.000% |

bus.hi.p1_ctrl / bus.lo.p2_net 三轮均 0（参考域）。对比 D1 同口径：
reserve_failed 1,114（0.037%）→ 0。

### 副作用（预算内）

| 指标 | D1 基线 | R12 后 | 判定 |
|---|---|---|---|
| monitor RSS（10k/s 负载中） | 252MB | 256.1MB（262,272kB） | +4.1MB ≤ +5MB ✓（ringbuf 双映射 mmap 所致） |
| 主线程 poll CPU（pidstat -t 20s×3） | ~3% | 3.0%（usr 1.18 + sys 1.83） | ≤5% ✓ |
| 消费线程 CPU | ~31% | 31.1% | 不变 ✓ |

### 回归

- `make` 全量绿；`cd tests && make unit` 55 项全过。
- FIM 冒烟：`test_snapshot.sh` 过；`test_check.sh` 16/16 过（需 sudo，
  非 root 下 `/var/log/baseline-guard/` 不可写会 abort，为环境前置非本次
  回归）；`baseline-guard alerts` 实时读出压测期 CRITICAL 告警，链路正常。
- 计数器命名未动；内核按探针 emitted/reserve_failed/backpressure_drop/
  discarded 与用户态 bus/store 系列全部保留。

**残余风险 1 至此关闭**：10k/s × 5min 内核侧零丢失达成。

## R13（W4 D2）：四指标收口——内存 / CPU / 延迟归因 / 多规则缺陷

日期：2026-10-06。对应 W4 D2 任务 1~4。测量机：8 核，kernel 7.0.0-30，
`sudo ./baseline-guard monitor --db baseline.db -c {config.yaml|tests/perf/config.yaml}`。
注意：本机空闲环境噪声高于 W3 测量时（同口径复测 W3 CPU 基线 3.48% → 本机
4.60%），本节所有"前 → 后"均为同机同口径对比。

### R13-1 内存：EventRecord 槽位瘦身 252MB → ~125MB ✓

**归因**（smaps_rollup + 映射聚合）：RSS 大头是 EventBus 队列槽位预分配——
定长 POD `EventRecord` 2,376B/槽（其中 `payload_json[2048]` 占 86%），
hi 32,768 槽 + lo 65,536 槽 ≈ **224MB**，基本解释了 252MB 的全部。进程树
（本机进程量级 <<10 万上限，实测个位数 MB）、SQLite（默认 cache_size 2MB×3
连接 ≈6MB）、批缓冲（~1MB）均非大头，未动。

**关键事实**：slot 内 payload 在路由前只承载 BPF 原始事件字节（最大结构
`priv_event` mount 变体 608B）；渲染 JSON 是消费线程 pop 出本地副本后才生成
的，**队列槽从不需要 2KB**。改动：

| 措施 | 文件:行 | 效果 |
|---|---|---|
| `payload_json[2048]` → `payload_raw[640]`（≥最大原始事件结构，4 处 static_assert 守护）；渲染 JSON 改由 `EventStore::Append(rec, payload, len)` 直传，不再写回槽位 | `src/telemetry/event_record.hpp:48-80`、`src/storage/event_store.{hpp,cpp}`、`src/baseline/monitor*.cpp` | sizeof(EventRecord) 2,376→**968B**；hi+lo 队列常驻 224MB→**92MB** |
| 消费线程 60s tick 加 `malloc_trim(0)`，归还压测峰值后 glibc arena 空闲页 | `src/baseline/monitor.cpp`（tombstone sweep 同 tick） | 压测后 RSS 不滞留峰值 |
| `EventStore::pending_` Flush 后容量 >4×batch 时 swap 收缩 | `src/storage/event_store.cpp` Flush | 峰值批缓冲不常驻 |

**数据**（VmRSS，30s 稳态 / 30s 10k/s 压测后）：

| 口径 | 前 | 后 |
|---|---|---|
| VmRSS 稳态 | 258,624 kB | **123,516 kB** |
| VmRSS 压测后 | 261,584 kB | **126,400 kB** |

改后分布（smaps 聚合）：anon（≈EventBus 槽位）91.2MB、bpf-map（内核 ringbuf
mmap）12.0MB、二进制+共享库 ~11MB、heap 1.8MB，其余零散；Pss 108MB。
**验收：≤150MB 达标（余量 ~25MB），无折中申报。**

### R13-2 CPU：消费线程空闲自适应退避 4.60% → 1.15% ✓

**口径**：遥测全开（config.yaml）、无负载，pidstat 5s×60 均值（同 W3）。
perf record 60s 空闲采样 Top2 均指向消费线程 200µs 空转退避循环：
`finish_task_switch←do_nanosleep←telemetry_consumer_main` 26.5%、
`clock_gettime←telemetry_consumer_main` 8.8%（每空转轮 2 次 try_pop +
1 次 clock_gettime + 1 次 nanosleep，~5,000 轮/s）。

**措施**（仅 1 处即达标，未做第 2/3 处）：空闲退避 200µs 固定 → 指数自适应
200µs→2ms（连续空转每轮 ×2，有事件即复位）。压测下循环从不空转，吞吐路径
零影响；代价是空闲/轻载时事件出队最多多等 ~2ms（batch_ms=200ms 落库口径下
可忽略）。`src/baseline/monitor.cpp` telemetry_consumer_main。

**数据**（pidstat 5s×60 均值，%CPU 单核）：

| 口径 | user | sys | 合计 |
|---|---|---|---|
| 前 | 1.83 | 2.77 | **4.60** |
| 后 | 0.60 | 0.54 | **1.15** |

**验收：≤3% 达标**（对 W3 记录的 3.48% 基线亦成立：本机改前复测即 4.60%，
改后 1.15%，降幅 3.45 个百分点）。

### R13-3 延迟归因：P99 +34.6μs = 调试代码（已修）+ 实时 wakeup 固有尾（降级记录）

**方法**：①LAT_LEVEL 分级对比（0=空探针 / 1=+map 查询 / 2=+emit 无调试 /
3=当前完整，各级强制重编 + 5 轮 bench_lat 取中位）；②探针内 bpf_ktime 分段
计时（L4=L2+计时、L5=L3+计时，per-CPU map 累加，bpftool dump 汇总）——
本机 syscall 级噪声 ±30μs，分级差值被淹没，归因以探针内计时为准。

**探针内分段测量**（每次 file_permission 调用，ns；30,100 次命中样本）：

| 阶段 | L4（无调试） | L5（含调试） | 说明 |
|---|---|---|---|
| 未命中路径 pre（全系统每次文件操作都付） | 129~162 | 216 | dentry/ino CORE 读 + map 查询 |
| 命中路径 pre | 125~147 | 1,032 | L5 多出 fname 256B 预读 + 1 次 trace_printk |
| emit 合计 | 3,489 | 6,060 | 背压 + reserve + 填充 + submit |
| emit 内：reserve+memset 328B | 74 | — | |
| emit 内：字段填充 + comm + 256B path 读 | 151 | — | |
| emit 内：**submit（实时 wakeup）** | **3,218** | — | 跨核唤醒消费线程的调度成本 |

**结论（二选一：两者皆有，分别处置）**：
1. **实现问题 → 已修复**：`file_permission` 及 chmod/chown/unlink/rename/mmap
   五个 hook 中的调试 bpf_printk 与 fname 预读全部移除（`bpf/lsm_file.bpf.c`）。
   收益：命中路径 -0.9μs/事件、全系统未命中路径 -87ns/次、emit 段 -1.2μs。
2. **挂载/传输固有开销 → 降级记录**（PRD 允许）：clean 逻辑下探针内
   ≈3.6μs/事件，其中 ringbuf 实时 submit 的 wakeup 占 ~3.2μs——这是
   "事件实时送达告警"的固有成本，非实现缺陷。

**修复后复测**（15 轮 ×10,000 次 open+write+close，中位数）：

| 口径 | OFF | ON | 差值 | W3 同口径 |
|---|---|---|---|---|
| P50 | 2,524 | 5,426 | **+2.9μs** | +4.2μs |
| avg | 2,716 | 8,994 | **+6.3μs**（≈2 事件/轮 × 3.6μs，与探针内测量吻合） | — |
| P99 | 4,562 | 35,021 | **+30.5μs** | +34.6μs |
| P999 | 25,939 | 63,253 | +37.3μs | — |

P99 尾部开销远超探针内稳态成本（均值仅 +6.3μs）：实时 wakeup 唤醒消费线程
与被测线程争抢 CPU 的调度干扰尾，非探针内耗时。**P99 ≤5μs 目标未达，按 PRD
"归因 + 降级记录"收口**：候选方向（如需进一步推进）为 NORMAL 水位也走
BPF_RB_NO_WAKEUP 批量通知（代价：告警可见延迟 ≤100ms poll 周期，语义变化
需评审），或 per-CPU ring（丢失全局有序，R12 已否决）。

### R13-4【缺陷单】同文件多规则 inode map 碰撞 → 规则集合合并，各自独立生效

**复现现场**（修复前，`tests/integration/test_multi_rule.sh`）：同一文件挂
read/write/chmod 三条规则，仅 YAML 中最后注册的 chmod 规则存活——read 与
write 事件 BPF 侧根本不上报（`read告警=0`，仅 chmod 产生 1 条告警且因
`mask=0` 被误标为 "-> write"）；同文件两条 write 规则仅 1 条告警。
MR-101/103/104 FAIL。

**根因**：`monitor_actions` map 以 inode 为 key、单 `monitor_rule` 为 value，
`common_monitor_init` 对同 inode 逐条 `BPF_ANY` 更新 → 后写覆盖先写；用户态
`FileRuleTable::Build` 的 `inode_to_rule[ino] = rule` 同样 last-wins。

**修复选型**：选"用户态按 inode 合并 + map value 改规则集合"，理由——
单 key 单查找不变，热路径只多 ≤4 次内存比较（verifier 有界 unroll）；
value 3B→13B ×8,192 项，map 内存增量可忽略；告警按规则独立生成天然在用户态
一对多展开，无需 BPF 侧多发事件。未选"单规则多 action 合并"：单 value 无法
表达"read=ALERT / write=BLOCK"的按事件类型分粒度动作（合并后会误 BLOCK
read）。改动：

| 层 | 措施 | 文件 |
|---|---|---|
| BPF | value `monitor_rule` → `monitor_rule_set{count, rules[4]}`；`match_rule_set()` 逐条匹配取最强 action/最高 severity；6 个 hook（file_permission/chmod/chown/unlink/rename/mmap）全部切换 | `bpf/event.h`、`bpf/bpf_common.h`、`bpf/lsm_file.bpf.c` |
| BPF | kprobe 降级路径同步切换；**顺带修复遗留 bug**：`mask & EVENT_READ(1)` 误判（MAY_READ=4，原码 read 永不命中）并归一化 mask 与 LSM 路径一致 | `bpf/lsm_kprobe.bpf.c` |
| 用户态 | `common_monitor_init` 按 inode 分组构建 rule_set 一次写入；>4 条保留最强 4 条并 warn；基线伪规则保持"YAML 规则优先"语义 | `src/baseline/monitor.cpp` |
| 用户态 | `FileRuleTable::inode_to_rules` 一对多；`process_event_core` 逐规则独立走白名单抑制与告警；`inode_to_hashes` 同理多值 | `src/baseline/monitor.cpp` |

**回归**：新增 `tests/integration/test_multi_rule.sh`（MR-101~104：read/
write/chmod 三规则各自独立 + 同事件类型双规则各告警）修复后 **4/4 PASS**；
`make` 全绿；unit 55/55 PASS；`test_snapshot.sh` 过；`test_check.sh` 16/16
过（sudo）；`test_monitor.sh` INT-011~015 全过（含 BLOCK 拦截）；30s 10k/s
吞吐冒烟 bus.queue_full.hi.* 全 0。

**已知边界（记录，非本次范围）**：①SIGHUP 热加载只更新用户态规则表，不刷
BPF map（新增/删除规则需重启 monitor 才在 BPF 侧生效，为既有缺口）；
②map key 仅 i_ino 无 st_dev，跨文件系统同 inode 号仍会碰撞（修复需 key
扩至 16B，影响面大，单独立项）。

### R13-1 验收补充：30 分钟 RSS 运行（任务 1 验收口径）

同 W3 基线口径（tests/perf/config.yaml，VmRSS 每 60s 采样 ×30，第 15 分钟
注入 30s 10k/s 压测；原始序列 `/tmp/bg-perf/results/rss30_series.txt`）：

| 口径 | W3 基线 | R13 后 |
|---|---|---|
| RSS 30min 均值 | —（30min 点位 252.5MB） | **125,247 kB（122.3MB）** |
| RSS 30min 峰值 | 260,944 kB（VmHWM） | **126,788 kB（123.8MB）** |
| 压测后驻留 | 261,584 kB | 126,476 kB（malloc_trim 生效，不滞留峰值） |
| bus.queue_full.hi.* | 0 | 0 |

**判定：≤150MB 达标（峰值余量 ~26MB），全时段平稳无爬升。**
