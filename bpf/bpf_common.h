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

/* ── per-CPU 丢包统计 ─────────────────────────────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_stats SEC(".maps");

static __always_inline void inc_drop_count(void)
{
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&drop_stats, &key);
    if (cnt)
        (*cnt)++;
}

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
    if (!e) { inc_drop_count(); return -1; }
    __builtin_memset(e, 0, sizeof(*e));
#else
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) { inc_drop_count(); return -1; }
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

    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
    if (name_ptr)
        bpf_core_read_str(e->path, sizeof(e->path), name_ptr);

#ifdef USE_PERF_BUFFER
    submit_event(ctx, e, bp_decision);
#else
    bpf_ringbuf_submit(e, bp_decision == BACKPRESSURE_BATCH ? BPF_RB_NO_WAKEUP : 0);
#endif
    return 0;
}

#endif /* BPF_COMMON_H */
