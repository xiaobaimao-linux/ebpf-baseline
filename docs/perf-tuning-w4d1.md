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
