# W3 性能基线实测报告

> 测量日期：2026-10-03 23:35 ~ 2026-10-04 00:15
> 环境：Ubuntu 24.04.3 LTS，内核 7.0.0-30-generic（128 线程），baseline-guard v0.4（本仓库构建）
> 探针模式：LSM (ring buffer)，`stats --drop` 丢弃计数可用
> 方法：对比法（同一 open+write+close 微基准，Agent 关/开各 10,000 次）；吞吐用自研 C 压测器（`tests/perf/gen_load.c`）；CPU 用 `pidstat -p <pid> 5 60`；RSS 取 `/proc/<pid>/status` VmRSS（monitor 就绪满 30 分钟）
> 复现：`sudo bash tests/perf/run_perf.sh`（主测量）+ `sudo bash tests/perf/run_tput_10k.sh`（吞吐验收口径补测）

## 结论总表

| 指标 | 目标 | 实测 | 判定 |
|---|---|---|---|
| 系统调用额外延迟 | P99 ≤ 5μs | P99 额外 **+34.6μs**（开 39.1μs / 关 4.5μs）；P50 额外 +4.2μs；稳态复测 P99 额外 +25.9μs | **未达标** |
| 常态 CPU 占用 | ≤ 3% 单核 | **3.48%**（5 分钟均值，us 2.90 + sys 0.59；pidstat 60×5s） | **未达标**（略超） |
| 内存 RSS | ≤ 150MB | **252.5MB**（VmRSS 258,608 kB，运行 30 分钟；VmHWM 260,944 kB；稳态复测 255,864 kB） | **未达标** |
| 事件吞吐 | 10,000 事件/s 不丢高优先级 | 10,000 ops/s（约 2 万事件/s）下：入库 121,889，**event_store 丢弃高优 file 事件 156,746**，持续入库速率仅 ~4,063 事件/s | **未达标** |

四个指标全部有实测数据；均未达标。按任务约定不做现场优化，每项给出降级方案记录如下。

## 1. 系统调用额外延迟（未达标）

微基准 `bench_lat`：对单文件 `open(O_WRONLY|O_CREAT|O_APPEND)+write+close` 逐次计时（`CLOCK_MONOTONIC`），前 100 次预热不计，样本 10,000。

| 场景 | P50 | P90 | P99 | avg |
|---|---|---|---|---|
| Agent OFF | 2,555 ns | 2,803 ns | 4,520 ns | 2,719 ns |
| Agent ON（受监控文件，压测即刻） | 6,741 ns | 25,289 ns | 39,137 ns | 11,753 ns |
| Agent ON（稳态：monitor 空闲 30s 后复测） | 6,506 ns | 20,672 ns | 30,378 ns | 9,340 ns |

- 额外延迟：P50 +4.2μs，P99 +34.6μs（稳态 +25.9μs）。P90 抬升到 20~25μs，呈重尾。
- 开销构成（按代码路径推断，未做 perf 火焰图）：LSM `file_open` 钩子全文件系统 attach（即便不监控的文件也过钩子，内核态规则匹配后放行）+ 命中规则的 ringbuf 提交（NORMAL 水位为 REALTIME，每事件唤醒消费者）。
- 注意：ON 组每操作产生 1 条 file.write 事件，测量本身在给管道施压，数字偏悲观；P50 的 +4.2μs 更接近常态感知。

**降级方案（记录，不实施）**：
1. NORMAL 水位改 `BPF_RB_NO_WAKEUP` + 定时唤醒，把每事件 IPI 摊薄成批量（背压机制已有 BATCH 档，可直接复用）。
2. 评估把监控面缩到 kprobe 按需 attach（只 hook 受监控 inode 的 open 路径）的可行性，换取非监控文件零开销。
3. 出正式报告前补一轮 `perf record` 火焰图，确认 25μs 重尾是唤醒开销还是批处理锁竞争。

## 2. 常态 CPU（未达标，3.48% vs 3%）

- monitor 稳定运行 5 分钟（遥测全开、无攻击负载），`pidstat -p <pid> 5 60`：user 2.90% + system 0.59% = **3.48%** 单核。
- 单样本波动区间 3.0%~3.8%。

**降级方案**：主循环 `ring_buffer__poll(100)` 每 100ms 必醒一次，空转也占 CPU；水位计算每 100 次 poll 一次。可增大 poll 超时、空闲时退避到 500ms~1s，预计可压到 2% 以内。

## 3. 内存 RSS（未达标，252.5MB vs 150MB）

- monitor 就绪满 30 分钟：VmRSS **258,608 kB**（≈252.5MB），VmHWM 260,944 kB；稳态复测 255,864 kB。30 分钟内基本平稳（就绪即高位，非缓慢泄漏）。
- 疑点：ringbuf 映射、事件批量缓冲、store 队列、SQLite（events.db WAL/page cache）、进程树缓存（`g_inode_to_baseline` 等全局表）。

**降级方案**：用 heaptrack/valgrind massif 分离匿名映射与堆；给 store 队列和进程树设容量上限；ringbuf 256KB 是常量、可控。若大头是 SQLite page cache，可限制 `PRAGMA cache_size` 或 mmap 上限。

## 4. 事件吞吐（未达标：10k 事件/s 丢高优）

压测器 30 秒窗口固定 9,987 ops/s（每 op = open+write+close，约 2 条 file 事件，共约 60 万内核事件）：

| 环节 | 数值 |
|---|---|
| 生成 | 300,000 ops（9,987 ops/s） |
| 入库（events 表） | 121,889（~4,063 事件/s 的持续入库速率） |
| event_store 丢弃 | **hi(file)=156,746 + ctrl=1 = 156,747**（高优先级被丢） |
| ringbuf drop_stats（`stats --drop`） | 0 → 0 |

- **未达标**：验收口径"10,000 事件/s 不丢高优先级"——高优事件在 store 队列被丢 15.6 万条。
- **计数缺口（实测发现）**：内核态 ringbuf `reserve` 失败（ring 满）不记入 `drop_stats` map（该 map 只记显式背压丢弃），60 万事件与"入库+store丢弃"之间约 32 万条无账可查；水位全程 NORMAL（final utilization=0.0%），背压没有介入，属于静默丢失。
- 补充观测：全速压测（348,472 ops/s，无节流）时，events 表 0 入库、drop 计数 0——极限负载下事件几乎全丢且无计数，与上一条同源。

**降级方案**：
1. store 是明确瓶颈（~4k 事件/s）：调大 batch（500→5000）、事务合并、或 store 独立线程 + 有界队列超限采样。
2. 补计数：`reserve` 失败与 event_batch（1024/轮）溢出都计入 `drop_stats`，让"静默丢失"可观测（小改动，W4 优先）。
3. 若业务确需 2 万事件/s，先按水位背压把低优事件丢在内核态（现机制只对显式背压生效），保住高优。

## 5. 测量工具与产物

- `tests/perf/bench_lat.c` / `gen_load.c`（已编译：同目录无后缀二进制）、`config.yaml`、`run_perf.sh`（主测量）、`run_tput_10k.sh`（吞吐验收口径）
- 原始数据：`/tmp/bg-perf/results/`（lat_off/lat_on/lat_on_steady/tput/tput10k/cpu/rss/drop*.txt、monitor_perf.log、monitor_10k.log）

## 6. 对 W4 的输入

1. 背压 BATCH 档下沉到 NORMAL 水位（延迟与 CPU 可能双降）。
2. drop_stats 补 reserve 失败/批溢出计数（观测性缺口，一天工作量）。
3. store 吞吐优化（batch/独立线程）。
4. RSS 归因（massif 一轮）。
