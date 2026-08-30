# Ring Buffer 与水位背压机制

本文档说明 baseline-guard 选择 Ring Buffer 作为内核态→用户态事件传输通道的依据，以及四级水位梯度降级策略的设计思路，帮助阅读代码时建立整体认知。

---

## 1. 为什么选择 Ring Buffer

### 1.1 候选方案对比

eBPF 向用户态传递数据主要有两种方式：

| 特性 | `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | `BPF_MAP_TYPE_RINGBUF` |
|------|----------------------------------|------------------------|
| 数据通道 | per-CPU perf event fd | 共享内存环形缓冲区 |
| 拷贝次数 | 每个事件需 1 次内核→用户态拷贝 | 零拷贝（用户态直接映射） |
| 多 CPU 合并 | 不支持，每个 CPU 独立 fd 轮询 | 天然支持，所有 CPU 共享一个 ring |
| 事件顺序 | 无法保证跨 CPU 顺序 | 大致按提交顺序 |
| 内存开销 | per-CPU 独立分配，CPU 数 × buffer 大小 | 全局一份，按需分配 |
| 背压能力 | 无内建机制 | 支持 `BPF_RB_NO_WAKEUP` / `BPF_RB_FORCE_WAKEUP` |

### 1.2 选择 Ring Buffer 的理由

1. **零拷贝**：用户态通过 `ring_buffer__poll()` 直接读取共享内存中的事件，无需额外拷贝，对高频文件访问监控场景至关重要。

2. **单 fd 多 CPU**：perf event 方式每个 CPU 需要独立的 fd 和轮询线程，Ring Buffer 所有 CPU 共享一个 ring，只需一个 poll 线程，简化了用户态架构。

3. **内建背压支持**：`bpf_ringbuf_submit()` 的 flags 参数允许内核态控制唤醒策略（`BPF_RB_NO_WAKEUP` 延迟唤醒 → 批量提交），这是实现水位梯度降级的基础。

4. **内存效率**：当前配置 `max_entries = 256 * 1024`（256KB），所有 CPU 共享这一份内存，而 perf event 方式需要 `N × per_cpu_size`。

### 1.3 代码位置

```
bpf/lsm_file.bpf.c:14-17    → Ring Buffer map 定义（256KB）
src/monitor/monitor.cpp:525   → ring_buffer__new() 创建用户态消费者
src/monitor/monitor.cpp:547   → ring_buffer__poll(rb, 100) 主循环轮询
```

---

## 2. 事件传输全链路

```
┌─────────────────────────────────────────────────────────────────────┐
│  内核态 (eBPF LSM Hook)                                            │
│                                                                     │
│  file_permission / chmod / chown / unlink                           │
│       │                                                             │
│       ▼                                                             │
│  monitor_actions map 查规则 → 命中？                                │
│       │ 是                                                          │
│       ▼                                                             │
│  check_backpressure(severity) → 读 watermark_level map              │
│       │                                                             │
│       ├── BACKPRESSURE_DROP  → inc_drop_count(), return             │
│       ├── BACKPRESSURE_BATCH → bpf_ringbuf_submit(BPF_RB_NO_WAKEUP)│
│       └── BACKPRESSURE_REALTIME → bpf_ringbuf_submit(0)            │
│                                                                     │
│                    ┌──────────────────────┐                         │
│                    │   Ring Buffer (256KB) │                        │
│                    └──────────┬───────────┘                         │
└───────────────────────────────┼─────────────────────────────────────┘
                                │ 共享内存
┌───────────────────────────────┼─────────────────────────────────────┐
│  用户态                       │                                     │
│                               ▼                                     │
│  ring_buffer__poll(100ms) → handle_event() 回调                    │
│                               │                                     │
│                               ▼                                     │
│                      event_batch 缓冲区（≤1024 条）                 │
│                               │                                     │
│                               ▼                                     │
│                      FlushEventBatch()                              │
│                               │                                     │
│                               ▼                                     │
│                      process_event_core()                           │
│                       ├── chmod/chown/unlink → 基线偏差告警          │
│                       ├── YAML 规则匹配 → 违规告警                  │
│                       └── 基线比对 → 偏差告警                       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. 四级水位梯度降级策略

### 3.1 设计动机

当系统负载激增时，如果所有事件都实时提交到用户态，Ring Buffer 会迅速填满导致事件丢失。简单粗暴的"超过阈值就丢弃"策略会导致服务断崖式降级——高优先级告警也可能丢失。

**四级水位**的设计思路是：随着利用率升高，**逐步降低低优先级事件的处理质量**，确保高优先级事件始终实时可达。

### 3.2 水位定义

水位常量由 `bpf/event.h` 统一定义，内核态和用户态共用同一份：

```c
// bpf/event.h
#define WATERMARK_NORMAL   0   // 0%  ~ 70%   正常水位
#define WATERMARK_WARNING  1   // 70% ~ 85%   预警水位
#define WATERMARK_HIGH     2   // 85% ~ 95%   高水位
#define WATERMARK_OVERLOAD 3   // 95% ~ 100%  过载水位
```

阈值定义在 `src/monitor/watermark_backpressure.hpp`：

```cpp
static constexpr double kWarningThreshold  = 70.0;
static constexpr double kHighThreshold     = 85.0;
static constexpr double kOverloadThreshold = 95.0;
```

### 3.3 水位计算

用户态 `WatermarkBackpressure` 类负责计算当前水位：

```
遍历所有 per-CPU ring 实例
  → 累加 total_avail（已用空间）和 total_size（总空间）
  → utilization = total_avail / total_size × 100
  → 根据阈值确定水位等级
```

计算周期：每 100 次 `ring_buffer__poll()`（约 10 秒）执行一次。

代码位置：`src/monitor/watermark_backpressure.cpp`

### 3.4 背压策略矩阵

内核态 `check_backpressure()` 根据 **当前水位 × 事件严重等级** 做出三级决策：

| | NORMAL (0~70%) | WARNING (70~85%) | HIGH (85~95%) | OVERLOAD (95~100%) |
|---|---|---|---|---|
| **LOW(0)** | 实时 | 批量 | **丢弃** | **丢弃** |
| **MEDIUM(1)** | 实时 | 实时 | 批量 | **丢弃** |
| **HIGH(2)** | 实时 | 实时 | 实时 | 批量 |
| **CRITICAL(3)** | 实时 | 实时 | 实时 | 实时 |

三级决策的含义：

| 决策 | eBPF 行为 | 说明 |
|------|-----------|------|
| `BACKPRESSURE_REALTIME` | `bpf_ringbuf_submit(e, 0)` | 立即唤醒用户态消费，延迟最低 |
| `BACKPRESSURE_BATCH` | `bpf_ringbuf_submit(e, BPF_RB_NO_WAKEUP)` | 写入 ring 但不发送 consumer wakeup 通知，用户态靠下一次 poll 超时才读到，自然形成批量消费 |
| `BACKPRESSURE_DROP` | 不写入 ring，`inc_drop_count()` | 直接丢弃，计入 per-CPU 丢弃统计 |

代码位置：`bpf/lsm_file.bpf.c:75-111`

### 3.5 梯度降级的核心思想

以一次典型的负载飙升为例：

```
时间线 →

利用率:  50% ─── 75% ─── 90% ─── 97%
水位:    NORMAL   WARNING   HIGH    OVERLOAD

LOW 事件:    实时 → 批量 → 丢弃 → 丢弃
MEDIUM 事件: 实时 → 实时 → 批量 → 丢弃
HIGH 事件:   实时 → 实时 → 实时 → 批量
CRITICAL:    实时 → 实时 → 实时 → 实时
```

**关键特性**：
- CRITICAL 事件在任何水位下都保持实时提交
- 低优先级事件先经历"批量"（软背压，减少用户态唤醒次数），再经历"丢弃"（硬背压）
- 避免断崖式切换，每个水位层级都有缓冲过渡

### 3.6 水位数据流

```
用户态计算水位 ──写──→ watermark_level map ──读──→ 内核态背压决策
     ↑                       │
     └────── 每 ~10s 更新 ───┘
```

- `watermark_level` map 类型：`BPF_MAP_TYPE_ARRAY`，1 个元素（key=0）
- 用户态写入：`bpf_map_update_elem(fd_watermark, &key, &value, BPF_ANY)`
- 内核态读取：`bpf_map_lookup_elem(&watermark_level, &key)`
- map 未初始化时默认返回 `BACKPRESSURE_REALTIME`（全部实时提交）

---

## 4. 用户态批量处理

### 4.1 设计思路

`ring_buffer__poll()` 在 100ms 超时内会消费 ring 中所有可用事件，每个事件触发一次 `handle_event` 回调。如果直接在回调中处理（告警发送、hash 计算、数据库写入等），会导致：

- 每个事件独立获取锁/访问共享资源，竞争开销大
- 无法利用 CPU 缓存局部性
- 高频事件时上下文切换频繁

改为**批量缓冲 + 统一处理**：回调只做内存拷贝入队（无锁、无 I/O），poll 返回后在主线程中集中处理所有事件，避免每个事件单独触发告警发送、hash 计算、数据库写入等重操作。

### 4.2 处理流程

```
ring_buffer__poll(100ms)
    │
    ├── handle_event() → 拷贝 event 到 event_batch（≤1024 条）
    ├── handle_event() → 拷贝 event 到 event_batch
    ├── ...
    ├── handle_event() → 若 batch 已满，dropped_count++
    │
    ▼ poll 返回
FlushEventBatch()
    │
    ├── process_event_core(event[0])
    ├── process_event_core(event[1])
    ├── ...
    └── event_batch.clear()
```

### 4.3 溢出保护

- `kMaxBatchSize = 1024`：单次 poll 周期内最多缓冲 1024 条事件
- 超出部分计入 `dropped_count`，程序退出时输出 warn 日志
- 由于 ring buffer 本身只有 256KB，单周期内事件数量有自然上限

### 4.4 代码位置

```
src/monitor/monitor.cpp:266   → kMaxBatchSize 常量
src/monitor/monitor.cpp:268   → MonitorContext 结构体（含 event_batch）
src/monitor/monitor.cpp:279   → handle_event() 回调（入队）
src/monitor/monitor.cpp:384   → FlushEventBatch() 批量处理
src/monitor/monitor.cpp:554   → 主循环中调用 FlushEventBatch
src/monitor/monitor.cpp:574   → 退出时 flush 残余事件
```

---

## 5. 关键文件索引

| 文件 | 职责 |
|------|------|
| `bpf/event.h` | 水位常量、严重等级、事件结构体定义（内核态/用户态共用唯一源头） |
| `bpf/lsm_file.bpf.c` | eBPF LSM hook、Ring Buffer map、背压决策 `check_backpressure()` |
| `src/monitor/watermark_backpressure.hpp/cpp` | 用户态水位计算控制器 |
| `src/monitor/monitor.cpp` | 主循环、批量缓冲、事件处理逻辑 |
| `src/stats/stats.cpp` | 读取 `drop_stats` map 展示丢弃统计 |
