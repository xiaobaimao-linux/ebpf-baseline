/*
 * net_watch.bpf.c — 网络连接遥测：connect / accept / bind
 *
 * 挂点：
 *   - kprobe/tcp_v4_connect      主动外连（本期仅 IPv4，不挂 tcp_v6_connect）
 *   - kretprobe/inet_csk_accept  服务端接受连接，返回值 struct sock* 读完整五元组
 *   - tracepoint/syscalls/sys_enter_bind  用户态 bind，bpf_probe_read_user 解析 sockaddr_in
 *
 * 事件经独立 ring buffer（net_events）上报，丢包计数在 net_drop_stats。
 *
 * 已知限制：connect 入口（kprobe）时源端口通常尚未分配，sk_rcv_saddr 也可能
 * 未绑定，因此 connect 事件的 saddr/sport 填 0，仅保证 daddr/dport 有效。
 */
#include "net_event.h"
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* ── 网络事件 ring buffer（独立于文件事件 rb，1<<22 = 4MB）────── */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} net_events SEC(".maps");

/* ── per-CPU 丢包统计 ─────────────────────────────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} net_drop_stats SEC(".maps");

static __always_inline void inc_net_drop_count(void)
{
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&net_drop_stats, &key);
    if (cnt)
        (*cnt)++;
}

static __always_inline struct net_event *reserve_net_event(void)
{
    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e) {
        inc_net_drop_count();
        return NULL;
    }
    __builtin_memset(e, 0, sizeof(*e));
    return e;
}

static __always_inline void fill_task_meta(struct net_event *e)
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

/* ── 主动外连：tcp_v4_connect 入口 ──────────────────────────────
 * 注意：入口时 sk 的 skc_daddr/skc_dport 尚未赋值（在函数体内才从
 * uaddr 拷贝），目的地址/端口必须从第二个参数 uaddr（内核缓冲区的
 * sockaddr_in，由 __sys_connect 的 move_addr_to_kernel 拷贝而来）读取。
 * 源地址/端口仅在 socket 已绑定时有效，未绑定则为 0。
 */
SEC("kprobe/tcp_v4_connect")
int kprobe_tcp_v4_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct sockaddr_in *uaddr = (struct sockaddr_in *)PT_REGS_PARM2(ctx);
    struct sockaddr_in usin;
    struct net_event *e;

    if (!sk || !uaddr)
        return 0;

    bpf_probe_read_kernel(&usin, sizeof(usin), uaddr);

    e = reserve_net_event();
    if (!e)
        return 0;

    fill_task_meta(e);
    e->event_kind = NET_EVENT_CONNECT;
    e->family     = NET_FAMILY_INET;
    e->protocol   = NET_PROTO_TCP;

    /* 目的地址/端口：sin_port 网络序转主机序；sin_addr 网络序原始拷贝 */
    e->dport = bpf_ntohs(usin.sin_port);
    __builtin_memcpy(e->daddr, &usin.sin_addr, sizeof(usin.sin_addr));

    /* 已知限制：未绑定 socket 的源地址/端口未分配，保持 0；已绑定时可读 */
    e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    __be32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __builtin_memcpy(e->saddr, &saddr, sizeof(saddr));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── 服务端接受：inet_csk_accept 返回已建立的 sock ────────────── */
SEC("kretprobe/inet_csk_accept")
int kretprobe_inet_csk_accept(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
    struct net_event *e;

    if (!sk)
        return 0;

    e = reserve_net_event();
    if (!e)
        return 0;

    fill_task_meta(e);
    e->event_kind = NET_EVENT_ACCEPT;
    e->family     = BPF_CORE_READ(sk, __sk_common.skc_family);
    e->protocol   = NET_PROTO_TCP;

    /* skc_num 是本地端口，主机序；skc_dport 是网络序 */
    e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    /* 本期仅 IPv4：非 AF_INET 连接端口照常上报，地址保持 0 */
    if (e->family == NET_FAMILY_INET) {
        __be32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __be32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(e->saddr, &saddr, sizeof(saddr));
        __builtin_memcpy(e->daddr, &daddr, sizeof(daddr));
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ── 用户态 bind：sys_enter_bind tracepoint ───────────────────── */
SEC("tracepoint/syscalls/sys_enter_bind")
int tp_sys_enter_bind(struct trace_event_raw_sys_enter *ctx)
{
    struct sockaddr *uaddr = (struct sockaddr *)ctx->args[1];
    struct sockaddr_in sin;
    sa_family_t family;
    struct net_event *e;

    if (!uaddr)
        return 0;

    bpf_probe_read_user(&family, sizeof(family), &uaddr->sa_family);
    if (family != NET_FAMILY_INET)
        return 0;

    e = reserve_net_event();
    if (!e)
        return 0;

    fill_task_meta(e);
    e->event_kind = NET_EVENT_BIND;
    e->family     = NET_FAMILY_INET;
    /* bind 无法从 sockaddr 推断协议，protocol 保持 0 */

    bpf_probe_read_user(&sin, sizeof(sin), uaddr);
    e->sport = bpf_ntohs(sin.sin_port);

    /* sin_addr 为网络序，原始拷贝前 4 字节 */
    __builtin_memcpy(e->saddr, &sin.sin_addr, sizeof(sin.sin_addr));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
