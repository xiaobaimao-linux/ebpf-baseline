/*
 * priv_watch.bpf.c — 权限类事件遥测：setuid/setgid 系 / capset / ptrace / 模块加载
 *
 * 挂点（全部 tracepoint）：
 *   - syscalls/sys_enter_setuid      kind=1，target_id=目标 uid（args[0]）
 *   - syscalls/sys_enter_setgid      kind=2，target_id=目标 gid（args[0]）
 *   - syscalls/sys_enter_setreuid    kind=1，target_id=新 effective uid（args[1]）
 *   - syscalls/sys_enter_setresuid   kind=1，target_id=新 effective uid（args[1]）
 *   - syscalls/sys_enter_capset      kind=3，尽力读 effective 掩码低 32 位，
 *                                      失败填 0xFFFFFFFF 表示未知
 *   - syscalls/sys_enter_ptrace      kind=4，request + 目标 pid 原样上报
 *   - module/module_load             kind=5，模块名从 tracepoint ctx 尽力读取
 *   - syscalls/sys_enter_mount       kind=6，source/target/fstype 用
 *                                      bpf_probe_read_user_str 尽力读取，
 *                                      失败填空串（事件仍上报）
 *   - syscalls/sys_enter_unshare     kind=7，flags 直取 args[0]
 *   - syscalls/sys_enter_setns       kind=8，fd/nstype 直取 args[0]/args[1]
 *
 * 事件经独立 ring buffer（priv_events）上报，丢包计数在 priv_drop_stats。
 *
 * 已知限制：
 *   - 仅采集 syscall 入口（sys_enter），不感知调用结果（成功/失败/被 LSM 拒绝）。
 *   - capset 只取 effective 低 32 位（data[0].effective）；高 32 位与 permitted/
 *     inheritable 不上报。
 *   - setreuid/setresuid 的 target_id 取新的 effective uid（args[1]），
 *     若用户传 -1 表示保持不变，此时 target_id 会是 0xFFFFFFFF。
 *   - mount 的字符串指针来自用户态，probe_read 失败只影响对应字段（空串）。
 */
#include "priv_event.h"
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* ── 权限事件 ring buffer（1<<22 = 4MB）────────────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} priv_events SEC(".maps");

/* ── per-CPU 丢包统计 ─────────────────────────────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} priv_drop_stats SEC(".maps");

static __always_inline void inc_priv_drop_count(void)
{
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&priv_drop_stats, &key);
    if (cnt)
        (*cnt)++;
}

static __always_inline struct priv_event *reserve_priv_event(void)
{
    struct priv_event *e = bpf_ringbuf_reserve(&priv_events, sizeof(*e), 0);
    if (!e) {
        inc_priv_drop_count();
        return NULL;
    }
    __builtin_memset(e, 0, sizeof(*e));
    return e;
}

static __always_inline void fill_task_meta(struct priv_event *e)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    unsigned long long uid_gid = bpf_get_current_uid_gid();

    e->ts_ns     = bpf_ktime_get_ns();
    e->pid       = bpf_get_current_pid_tgid() >> 32;
    e->ppid      = BPF_CORE_READ(task, real_parent, tgid);
    e->uid       = (__u32)(uid_gid & 0xffffffff);
    e->gid       = (__u32)(uid_gid >> 32);
    e->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(e->comm, sizeof(e->comm));
}

/* ── setuid/setgid 系公共入口 ──────────────────────────────────── */
static __always_inline int handle_setid(struct trace_event_raw_sys_enter *ctx,
                                        unsigned char kind, unsigned int target_id)
{
    struct priv_event *e = reserve_priv_event();
    if (!e)
        return 0;

    fill_task_meta(e);
    e->priv_kind  = kind;
    e->u.target_id = target_id;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int tp_sys_enter_setuid(struct trace_event_raw_sys_enter *ctx)
{
    return handle_setid(ctx, PRIV_KIND_SETUID, (__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int tp_sys_enter_setgid(struct trace_event_raw_sys_enter *ctx)
{
    return handle_setid(ctx, PRIV_KIND_SETGID, (__u32)ctx->args[0]);
}

/* setreuid(ruid, euid)：取新的 effective uid（args[1]）作为目标 */
SEC("tracepoint/syscalls/sys_enter_setreuid")
int tp_sys_enter_setreuid(struct trace_event_raw_sys_enter *ctx)
{
    return handle_setid(ctx, PRIV_KIND_SETUID, (__u32)ctx->args[1]);
}

/* setresuid(ruid, euid, suid)：取新的 effective uid（args[1]）作为目标 */
SEC("tracepoint/syscalls/sys_enter_setresuid")
int tp_sys_enter_setresuid(struct trace_event_raw_sys_enter *ctx)
{
    return handle_setid(ctx, PRIV_KIND_SETUID, (__u32)ctx->args[1]);
}

/* ── capset：尽力解析 effective 掩码低 32 位 ────────────────────
 * capset(hdrp, datap)：datap 为 cap_user_data 数组，
 * 元素布局 { effective, permitted, inheritable } 各 32 位。
 * 读 data[0].effective 即为掩码低 32 位；probe 失败填 0xFFFFFFFF 表示未知。
 */
SEC("tracepoint/syscalls/sys_enter_capset")
int tp_sys_enter_capset(struct trace_event_raw_sys_enter *ctx)
{
    struct priv_event *e;
    unsigned int effective_lo = 0xFFFFFFFF;

    if (bpf_probe_read_user(&effective_lo, sizeof(effective_lo),
                            (void *)ctx->args[1]) == 0) {
        /* 读取成功即得低 32 位；保持原值 */
    }

    e = reserve_priv_event();
    if (!e)
        return 0;

    fill_task_meta(e);
    e->priv_kind     = PRIV_KIND_CAPSET;
    e->u.effective_lo = effective_lo;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── ptrace：request + 目标 pid 原样上报 ──────────────────────── */
SEC("tracepoint/syscalls/sys_enter_ptrace")
int tp_sys_enter_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    struct priv_event *e = reserve_priv_event();
    if (!e)
        return 0;

    fill_task_meta(e);
    e->priv_kind         = PRIV_KIND_PTRACE;
    e->u.ptrace.request  = (unsigned long long)ctx->args[0];
    e->u.ptrace.target_pid = (__u32)ctx->args[1];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── 内核模块加载：module:module_load ───────────────────────────
 * 内核 6.x+ tracepoint 负载布局（ctx 含 trace_entry 公共头，同 sys_enter 系列）：
 *   ent(8) taints(4,8) name(__data_loc,12)
 * __data_loc 低 16 位为 name 相对条目起始的偏移、高 16 位为长度（变长字符串，
 * 非内联数组）。读取失败保留空串（事件仍上报）。
 * 注意：5.x 内核本挂点为 module_base/module_size + 内联 name，格式不同，
 * 本实现按 6.x+ 布局解析（运行环境内核 7.0）。
 */
struct tp_module_load_ctx {
    struct trace_entry ent;
    unsigned int taints;
    unsigned int name_loc;   /* __data_loc：低16位偏移，高16位长度 */
};

SEC("tracepoint/module/module_load")
int tp_module_load(struct tp_module_load_ctx *ctx)
{
    struct priv_event *e;
    unsigned int name_off;
    unsigned int name_len;

    e = reserve_priv_event();
    if (!e)
        return 0;

    fill_task_meta(e);
    e->priv_kind = PRIV_KIND_MODULE_LOAD;

    name_off = ctx->name_loc & 0xffff;
    name_len = (ctx->name_loc >> 16) & 0xffff;
    if (name_off == 0 || name_len == 0) {
        e->u.name[0] = '\0';
    } else {
        if (name_len > sizeof(e->u.name))
            name_len = sizeof(e->u.name);
        if (bpf_probe_read_kernel(e->u.name, name_len, (const char *)ctx + name_off) != 0)
            e->u.name[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── mount：source/target/fstype 尽力读取，失败填空串 ────────────
 * mount(source, target, filesystemtype, mountflags, data)：
 * args[0..2] 为用户态字符串指针，args[3] 为 flags。
 */
SEC("tracepoint/syscalls/sys_enter_mount")
int tp_sys_enter_mount(struct trace_event_raw_sys_enter *ctx)
{
    struct priv_event *e = reserve_priv_event();
    if (!e)
        return 0;

    fill_task_meta(e);
    e->priv_kind = PRIV_KIND_MOUNT;

    if (bpf_probe_read_user_str(e->u.mount.source, sizeof(e->u.mount.source),
                                (const char *)ctx->args[0]) < 0)
        e->u.mount.source[0] = '\0';
    if (bpf_probe_read_user_str(e->u.mount.target, sizeof(e->u.mount.target),
                                (const char *)ctx->args[1]) < 0)
        e->u.mount.target[0] = '\0';
    if (bpf_probe_read_user_str(e->u.mount.fstype, sizeof(e->u.mount.fstype),
                                (const char *)ctx->args[2]) < 0)
        e->u.mount.fstype[0] = '\0';
    e->u.mount.flags = (unsigned long long)ctx->args[3];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── unshare：flags 直取参数 ──────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_unshare")
int tp_sys_enter_unshare(struct trace_event_raw_sys_enter *ctx)
{
    struct priv_event *e = reserve_priv_event();
    if (!e)
        return 0;

    fill_task_meta(e);
    e->priv_kind       = PRIV_KIND_UNSHARE;
    e->u.unshare.flags = (unsigned long long)ctx->args[0];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── setns：fd/nstype 直取参数 ────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_setns")
int tp_sys_enter_setns(struct trace_event_raw_sys_enter *ctx)
{
    struct priv_event *e = reserve_priv_event();
    if (!e)
        return 0;

    fill_task_meta(e);
    e->priv_kind      = PRIV_KIND_SETNS;
    e->u.setns.fd     = (int)ctx->args[0];
    e->u.setns.nstype = (__u32)ctx->args[1];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
