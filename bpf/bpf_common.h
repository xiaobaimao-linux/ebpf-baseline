/*
 * bpf_common.h — lsm_file.bpf.c 和 lsm_kprobe.bpf.c 的共享定义
 *
 * 包含：公共 BPF map、丢包计数、事件提交、事件填充逻辑。
 * 两个 BPF 程序通过条件编译区分差异：
 *   - lsm_file.bpf.c: 定义 USE_PERF_BUFFER 或 USE_RINGBUF（含水位背压）
 *   - lsm_kprobe.bpf.c: 定义 USE_KPROBE（始终 perf buffer，无背压）
 */
#ifndef BPF_COMMON_H
#define BPF_COMMON_H

#include "event.h"
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* ── 监控规则 map ─────────────────────────────────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, unsigned long);
    __type(value, struct monitor_rule);
} monitor_actions SEC(".maps");

/* ── per-CPU 丢包/对账统计（槽位定义见 stats_slots.h）────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, DROP_STATS_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} drop_stats SEC(".maps");

static __always_inline void inc_drop_slot(__u32 slot)
{
    __u64 *cnt = bpf_map_lookup_elem(&drop_stats, &slot);
    if (cnt)
        (*cnt)++;
}

/* 背压主动 DROP（保持原计数语义不变） */
static __always_inline void inc_drop_count(void)
{
    inc_drop_slot(DROP_SLOT_BACKPRESSURE);
}

/* ── 用户态计数器中转 map：monitor 周期写入，stats 命令经 pin 读取 ── */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, USER_STATS_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} user_stats SEC(".maps");

/* ══════════════════════════════════════════════════════════════════
 * 事件传输层：根据编译模式选择 ring buffer 或 perf buffer
 * ══════════════════════════════════════════════════════════════════ */

#ifdef USE_PERF_BUFFER
/* ── perf event buffer（5.7 LSM / 5.4 kprobe 共用）────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

/* per-CPU 事件缓冲区（避免 struct event 溢出 BPF 512 字节栈） */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event);
} perf_event_buf SEC(".maps");

static __always_inline int submit_event(void *ctx, struct event *e, int bp_decision)
{
    (void)bp_decision;
    return bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e, sizeof(*e));
}

#else /* USE_RINGBUF */
/* ── ring buffer（5.8+ LSM 专用）─────────────────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");
#endif

/* ── 背压决策常量（两种模式都用，perf buffer 模式固定 REALTIME）── */
#define BACKPRESSURE_REALTIME  0
#define BACKPRESSURE_BATCH     1
#define BACKPRESSURE_DROP      2

/* ══════════════════════════════════════════════════════════════════
 * 水位背压（仅 ring buffer 模式，即 lsm_file.bpf.c 非 PERF 模式）
 * ══════════════════════════════════════════════════════════════════ */

#ifndef USE_PERF_BUFFER

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} watermark_level SEC(".maps");

static __always_inline int check_backpressure(unsigned char severity)
{
    __u32 key = 0;
    __u32 *level = bpf_map_lookup_elem(&watermark_level, &key);
    if (!level)
        return BACKPRESSURE_REALTIME;

    switch (*level) {
    case WATERMARK_NORMAL:
        return BACKPRESSURE_REALTIME;
    case WATERMARK_WARNING:
        return (severity == SEVERITY_LOW) ? BACKPRESSURE_BATCH : BACKPRESSURE_REALTIME;
    case WATERMARK_HIGH:
        if (severity == SEVERITY_LOW)    return BACKPRESSURE_DROP;
        if (severity == SEVERITY_MEDIUM) return BACKPRESSURE_BATCH;
        return BACKPRESSURE_REALTIME;
    case WATERMARK_OVERLOAD:
        if (severity == SEVERITY_LOW || severity == SEVERITY_MEDIUM) return BACKPRESSURE_DROP;
        if (severity == SEVERITY_HIGH)   return BACKPRESSURE_BATCH;
        return BACKPRESSURE_REALTIME;
    default:
        return BACKPRESSURE_REALTIME;
    }
}

#endif /* !USE_PERF_BUFFER */

/* ══════════════════════════════════════════════════════════════════
 * 公共事件填充 + 提交（LSM 和 kprobe 共用）
 * ══════════════════════════════════════════════════════════════════ */

static __always_inline int emit_attr_event(void *ctx,
                                           unsigned long ino,
                                           struct dentry *dentry,
                                           unsigned char event_type,
                                           int mask,
                                           unsigned int new_mode,
                                           unsigned int new_uid,
                                           unsigned int new_gid,
                                           unsigned char action,
                                           int bp_decision)
{
#ifdef USE_PERF_BUFFER
    __u32 _zero = 0;
    struct event *e = bpf_map_lookup_elem(&perf_event_buf, &_zero);
    if (!e) { inc_drop_slot(DROP_SLOT_RESERVE_FAIL); return -1; }
    __builtin_memset(e, 0, sizeof(*e));
#else
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) { inc_drop_slot(DROP_SLOT_RESERVE_FAIL); return -1; }
    __builtin_memset(e, 0, sizeof(*e));
#endif

    e->pid        = bpf_get_current_pid_tgid() >> 32;
    e->ino        = ino;
    e->action     = action;
    e->event_type = event_type;
    e->mask       = mask;
    e->new_mode   = new_mode;
    e->new_uid    = new_uid;
    e->new_gid    = new_gid;

    // 进程上下文：uid/gid 拆分自 bpf_get_current_uid_gid()；start_time 取
    // 当前任务 task_struct.start_time（ns，与进程树 / 进程事件同时钟域），
    // 用户态按 (pid, start_time) 关联进程树节点（pid 复用防护）。
    // 注：BPF_CORE_READ 首参需左值（内部对 src 取址），先落本地指针；
    // 用 bpf_get_current_task()（4.8+）：btf 变体 5.11 才合入，5.4~5.10
    // 降级路径 verifier 拒绝 unknown helper，文件监控探针必须走通用版。
    unsigned long long uid_gid = bpf_get_current_uid_gid();
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->uid        = (__u32)(uid_gid & 0xffffffff);
    e->gid        = (__u32)(uid_gid >> 32);
    e->start_time = BPF_CORE_READ(task, start_time);

    bpf_get_current_comm(e->comm, sizeof(e->comm));

    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
    if (name_ptr)
        bpf_core_read_str(e->path, sizeof(e->path), name_ptr);

#ifdef USE_PERF_BUFFER
    /* perf output 失败（buffer 满等）即传输层丢失，计入 reserve_fail 槽 */
    if (submit_event(ctx, e, bp_decision) == 0)
        inc_drop_slot(DROP_SLOT_EMITTED);
    else
        inc_drop_slot(DROP_SLOT_RESERVE_FAIL);
#else
    bpf_ringbuf_submit(e, bp_decision == BACKPRESSURE_BATCH ? BPF_RB_NO_WAKEUP : 0);
    inc_drop_slot(DROP_SLOT_EMITTED);
#endif
    return 0;
}

#endif /* BPF_COMMON_H */
