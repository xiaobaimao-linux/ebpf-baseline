/*
 * stats_slots.h — 丢弃/对账计数器槽位定义（内核 BPF 与用户态共用，纯宏）
 *
 * 两类 map：
 *   1. drop_stats / proc_drop_stats / net_drop_stats / priv_drop_stats
 *      （PERCPU_ARRAY<__u64>，内核态累加，stats --drop 按 CPU 求和）
 *   2. user_stats（ARRAY<__u64>，monitor 用户态周期写入，stats 命令读取）
 */
#ifndef STATS_SLOTS_H
#define STATS_SLOTS_H

/* ── drop_stats 系列 map 槽位 ───────────────────────────────────── */
#define DROP_SLOT_BACKPRESSURE  0   /* 水位背压主动 DROP（仅 lsm_file） */
#define DROP_SLOT_RESERVE_FAIL  1   /* ringbuf reserve / perf output 失败（传输层丢） */
#define DROP_SLOT_EMITTED       2   /* 成功提交到 ring/perf buffer（对账基准） */
#define DROP_SLOT_DISCARDED     3   /* reserve 后主动 discard（如 DNS 解析失败） */
#define DROP_STATS_SLOTS        4

/* ── user_stats map 槽位 ────────────────────────────────────────── */
#define USTAT_BUS_DROP_HI_P0    0   /* EventBus hi 队列满丢弃，按 priority 0..3 */
#define USTAT_BUS_DROP_HI_P1    1
#define USTAT_BUS_DROP_HI_P2    2
#define USTAT_BUS_DROP_HI_P3    3
#define USTAT_BUS_DROP_LO_P0    4   /* lo 队列满丢弃，按 priority 0..3 */
#define USTAT_BUS_DROP_LO_P1    5
#define USTAT_BUS_DROP_LO_P2    6
#define USTAT_BUS_DROP_LO_P3    7
#define USTAT_BATCH_OVERFLOW    8   /* perf 降级路径批缓冲溢出（kMaxBatchSize） */
#define USTAT_STORE_FAILED      9   /* event_store 事务写入失败丢弃的行数 */
#define USTAT_BUS_PUSHED        10  /* 成功入队总数（对账用） */
#define USTAT_STORE_STORED      11  /* 落库成功总数（对账用） */
#define USTAT_BUS_HI_DEPTH      12  /* 当前 hi 队列深度（排干判定用） */
#define USTAT_BUS_LO_DEPTH      13  /* 当前 lo 队列深度 */
#define USER_STATS_SLOTS        16

/* ── pinned map 路径（monitor pin，stats 命令读取）───────────────── */
#define BG_PIN_DIR               "/sys/fs/bpf/baseline-guard"
#define DROP_STATS_PIN_PATH      BG_PIN_DIR "/drop_stats"
#define PROC_DROP_STATS_PIN_PATH BG_PIN_DIR "/proc_drop_stats"
#define NET_DROP_STATS_PIN_PATH  BG_PIN_DIR "/net_drop_stats"
#define PRIV_DROP_STATS_PIN_PATH BG_PIN_DIR "/priv_drop_stats"
#define USER_STATS_PIN_PATH      BG_PIN_DIR "/user_stats"

#endif /* STATS_SLOTS_H */
