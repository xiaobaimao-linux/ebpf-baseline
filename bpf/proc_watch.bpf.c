/*
 * proc_watch.bpf.c — 进程生命周期遥测：fork / exec / exit
 *
 * 挂点（全部 tracepoint，sched_process_* 系列）：
 *   - tracepoint/sched/sched_process_fork  父进程创建子进程，pid=child_pid，
 *                                          ppid=parent_pid，comm 取子进程名
 *                                          （__data_loc_child_comm，读不到回退父 comm）
 *   - tracepoint/sched/sched_process_exec  进程映像替换，pid=当前进程，
 *                                          exe 尽力读 tracepoint filename（未解析
 *                                          相对路径），start_time 取 task start_time
 *   - tracepoint/sched/sched_process_exit  进程退出，pid=ctx->pid，
 *                                          start_time 取 task start_time
 *
 * 事件经独立 ring buffer（proc_events）上报，丢包计数在 proc_drop_stats。
 *
 * 已知限制：
 *   - fork 事件触发时当前任务仍是父进程，子任务的 start_time 内核侧无法
 *     便捷获得，填 0，由消费线程读 /proc/<pid>/stat 补齐（尽力）。
 *   - exec 事件的 exe 为 tracepoint filename 原文（可能是相对路径或未解析
 *     的 /dev/fd/ 之类），真实路径由消费线程读 /proc/<pid>/exe 解析。
 *   - exit 事件在进程退出路径上触发，/proc/<pid>/exe 已不可读，exe 留空。
 *   - ppid 一律取 real_parent 的 tgid（fork 事件直接取 tracepoint 的
 *     parent_pid），不追溯祖先进程。
 */
#include "proc_event.h"
/* vmlinux.h 内含内核 struct proc_event（proc connector 事件，见 include/linux/
 * proc_connector.h），与 proc_event.h 的用户态事件定义重名冲突；包含 vmlinux.h
 * 前宏改名为 kern_proc_event 规避（内核侧仅此一处定义，无其他引用点，安全）。 */
#define proc_event kern_proc_event
#include "vmlinux.h"
#undef proc_event

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* ── 进程事件 ring buffer（独立于网络/权限事件 rb，1<<22 = 4MB）── */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} proc_events SEC(".maps");

/* ── per-CPU 丢包统计 ─────────────────────────────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} proc_drop_stats SEC(".maps");

static __always_inline void inc_proc_drop_count(void)
{
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&proc_drop_stats, &key);
    if (cnt)
        (*cnt)++;
}

static __always_inline struct proc_event *reserve_proc_event(void)
{
    struct proc_event *e = bpf_ringbuf_reserve(&proc_events, sizeof(*e), 0);
    if (!e) {
        inc_proc_drop_count();
        return NULL;
    }
    __builtin_memset(e, 0, sizeof(*e));
    return e;
}

static __always_inline void fill_task_meta(struct proc_event *e)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    unsigned long long uid_gid = bpf_get_current_uid_gid();

    e->ts_ns       = bpf_ktime_get_ns();
    e->pid         = bpf_get_current_pid_tgid() >> 32;
    e->ppid        = BPF_CORE_READ(task, real_parent, tgid);
    e->uid         = (__u32)(uid_gid & 0xffffffff);
    e->gid         = (__u32)(uid_gid >> 32);
    e->start_time  = BPF_CORE_READ(task, start_time);
    bpf_get_current_comm(e->comm, sizeof(e->comm));
}

/* ── fork：父进程创建子进程 ──────────────────────────────────────
 * 注意：tracepoint 触发时当前任务仍是父进程，fill_task_meta 填的是父进程
 * 的 pid/ppid/comm，随后按 fork 语义改写为子进程视角：
 * pid=child_pid、ppid=parent_pid；comm 优先取 __data_loc_child_comm
 * 子进程名，读不到回退为 fill_task_meta 已填的父 comm。
 * 子任务 start_time 内核侧无法便捷获得，保持 0（待消费线程 /proc 补）。
 */
SEC("tracepoint/sched/sched_process_fork")
int tp_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct proc_event *e;
    __u32 off;

    e = reserve_proc_event();
    if (!e)
        return 0;

    fill_task_meta(e);
    e->kind = PROC_KIND_FORK;
    e->pid  = (__u32)ctx->child_pid;
    e->ppid = (__u32)ctx->parent_pid;

    /* 子进程名：__data_loc_child_comm 低 16 位为相对条目起始的偏移；
     * 读到即覆盖父 comm，失败保留 fill_task_meta 已填的父 comm */
    off = ctx->__data_loc_child_comm & 0xFFFF;
    if (off) {
        if (bpf_probe_read_kernel_str(e->comm, sizeof(e->comm),
                                      (void *)ctx + off) < 0)
            bpf_get_current_comm(e->comm, sizeof(e->comm));
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── exec：进程映像替换 ──────────────────────────────────────────
 * exe 尽力读 tracepoint filename（__data_loc 动态偏移，未解析相对路径），
 * 真实路径由消费线程读 /proc/<pid>/exe 解析；失败保留 memset 的空串。
 */
SEC("tracepoint/sched/sched_process_exec")
int tp_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct proc_event *e;
    __u32 off;

    e = reserve_proc_event();
    if (!e)
        return 0;

    fill_task_meta(e);
    e->kind = PROC_KIND_EXEC;

    /* __data_loc_filename 低 16 位为 filename 相对条目起始的偏移 */
    off = ctx->__data_loc_filename & 0xFFFF;
    if (off)
        bpf_probe_read_kernel_str(e->exe, sizeof(e->exe), (void *)ctx + off);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── exit：进程退出 ──────────────────────────────────────────────
 * ctx->pid 即当前进程 pid（线程组视角与 fill_task_meta 的 pid 一致）；
 * exe 留空（退出路径上 /proc/<pid>/exe 已不可读，消费线程无法补）。
 */
SEC("tracepoint/sched/sched_process_exit")
int tp_sched_process_exit(struct trace_event_raw_sched_process_exit *ctx)
{
    struct proc_event *e;

    e = reserve_proc_event();
    if (!e)
        return 0;

    fill_task_meta(e);
    e->kind = PROC_KIND_EXIT;
    e->pid  = (__u32)ctx->pid;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
