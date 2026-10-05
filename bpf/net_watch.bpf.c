/*
 * net_watch.bpf.c — 网络连接遥测：connect / accept / bind + DNS 查询
 *
 * 挂点：
 *   - kprobe/tcp_v4_connect      主动外连（本期仅 IPv4，不挂 tcp_v6_connect）
 *   - kretprobe/inet_csk_accept  服务端接受连接，返回值 struct sock* 读完整五元组
 *   - tracepoint/syscalls/sys_enter_bind  用户态 bind，bpf_probe_read_user 解析 sockaddr_in
 *   - tracepoint/syscalls/sys_enter_sendto   DNS 查询（UDP dport=53），解析 DNS 头取 QNAME/QTYPE
 *   - tracepoint/syscalls/sys_enter_sendmsg  DNS 查询（尽力支持：msg_name + 首个 iov）
 *   - tracepoint/syscalls/sys_enter_sendmmsg DNS 查询（尽力支持：msgvec[0] + 首个 iov；
 *                                            dig 实测走本挂点且 msg_name 为 NULL）
 *
 * 事件经独立 ring buffer（net_events）上报，丢包计数在 net_drop_stats。
 *
 * 已知限制：
 *   - connect 入口（kprobe）时源端口通常尚未分配，sk_rcv_saddr 也可能
 *     未绑定，因此 connect 事件的 saddr/sport 填 0，仅保证 daddr/dport 有效。
 *   - 仅采集 UDP 53 的明文 DNS 查询（dig 默认走 UDP）。TCP 53 仅用于大响应/
 *     域传送，本期不采集，后续再议。
 *   - 传 NULL 地址的 sendto/sendmsg/sendmmsg（已连接 UDP socket，如 dig
 *     connect 到 127.0.0.53 后用 sendmmsg）从 fd 回溯 socket 目的端口，
 *     仅认可 UDP 且 dport=53；回溯失败静默丢弃。write(2) 不经过本组挂点。
 *   - QNAME 遇压缩指针（0xC0）或保留位（0x40/0x80）直接放弃该事件；
 *     label 循环定长上界（最多 32 段、每段 1~63 字节），超出放弃。
 *   - kernel 只按 label 长度字节定位 QNAME 边界并整段拷贝线格式报文，
 *     线格式 → 点分文本的转换在用户态做（同 ptrace request 映射）。
 */
#include "net_event.h"
#include "stats_slots.h"
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* DNS 查询报文解析上界；线格式 QNAME（含根 0 字节）按 RFC 1035 不超过 255 */
#define DNS_PAYLOAD_MAX 512
#define DNS_HDR_LEN     12
#define DNS_MAX_LABELS  32
#define DNS_QNAME_MAX   255

/* ── 网络事件 ring buffer（独立于文件事件 rb，1<<22 = 4MB）────── */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} net_events SEC(".maps");

/* ── per-CPU 丢包统计 ─────────────────────────────────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, DROP_STATS_SLOTS);
    __type(key, __u32);
    __type(value, __u64);
} net_drop_stats SEC(".maps");

static __always_inline void inc_net_drop_slot(__u32 slot)
{
    __u64 *cnt = bpf_map_lookup_elem(&net_drop_stats, &slot);
    if (cnt)
        (*cnt)++;
}

static __always_inline void inc_net_drop_count(void)
{
    inc_net_drop_slot(DROP_SLOT_RESERVE_FAIL);
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

/* ── DNS 报文解析：跳过 12 字节头，定位 QNAME 边界并整段拷贝 ────
 * buff/len 为用户态 sendto/sendmsg/sendmmsg 缓冲区（len 已由调用方保证
 * >= 12）。返回 0 表示解析成功可上报；返回非 0 表示放弃该事件（压缩指针/
 * 越界/段数或长度异常），调用方应 discard。
 *
 * 只按 label 长度字节走查（每段一次 1 字节 probe，最多 32 次）确定 QNAME
 * 线格式总长，再一次性拷入事件 domain 字段；线格式 → 点分文本转换在用户态。
 * 不逐字节处理 QNAME：字节级循环（含 512 轮状态机、32×63 双层循环）会把
 * verifier 路径敏感探索指令数推过内核 100 万上限，而本写法仅 ~32 次小步进。
 * 每个用户态访问前都有冗余运行时上界判断，依赖路径敏感范围分析放行。
 */
static __always_inline int parse_dns_query(struct net_event *e, const void *buff, unsigned long long len)
{
    __u32 rdlen = len > DNS_PAYLOAD_MAX ? DNS_PAYLOAD_MAX : (__u32)len;
    __u32 pos = DNS_HDR_LEN;   /* 跳过 ID/flags/4 个计数器 */
    __u32 qname_len;
    int done = 0;
    int i;

    for (i = 0; i < DNS_MAX_LABELS; i++) {
        unsigned char c;

        if (done)
            break;
        if (pos >= rdlen)
            return -1;
        /* 尽力读长度字节：用户态缓冲区可能不可读，失败静默丢弃 */
        if (bpf_probe_read_user(&c, sizeof(c), buff + pos) != 0)
            return -1;
        if (c == 0) {
            pos++;
            done = 1;
        } else if (c & 0xC0) {
            /* 压缩指针（0xC0）/保留位（0x40/0x80）：QNAME 内不支持，放弃 */
            return -1;
        } else {
            if (pos + 1 + c > rdlen)
                return -1;
            pos += 1 + c;
            /* QNAME 线格式总长（含根 0 字节）按 RFC 1035 不超过 255 */
            if (pos - DNS_HDR_LEN >= DNS_QNAME_MAX)
                return -1;
        }
    }
    if (!done)
        return -1;   /* 超过 32 段仍未结束，视为异常放弃 */

    /* QTYPE：QNAME 结束后的 2 字节（大端转主机序）；QCLASS 2 字节不取 */
    if (pos + 2 > rdlen)
        return -1;
    {
        unsigned char qt[2];

        if (bpf_probe_read_user(qt, sizeof(qt), buff + pos) != 0)
            return -1;
        e->qtype = ((__u16)qt[0] << 8) | qt[1];
    }

    /* QNAME 线格式一次性拷入 domain。walk 已拒绝超长 QNAME（防御性收敛不会
     * 截断正常事件）；赋值式 clamp 让 verifier 可证明 probe 长度 <= domain
     * 缓冲（u32 比较+返回的写法经 clang 移位变换后无法回代范围，实测被拒） */
    qname_len = pos - DNS_HDR_LEN;
    if (qname_len > sizeof(e->domain) - 1)
        qname_len = sizeof(e->domain) - 1;
    if (bpf_probe_read_user(e->domain, qname_len, buff + DNS_HDR_LEN) != 0)
        return -1;
    return 0;
}

/* ── DNS 事件公共收尾：填充目的地址并提交/丢弃 ─────────────────── */
static __always_inline void submit_dns_event(struct net_event *e, struct sockaddr_in *sin,
                                             const void *buff, unsigned long long len)
{
    fill_task_meta(e);
    e->event_kind = NET_EVENT_DNS;
    e->family     = NET_FAMILY_INET;
    e->protocol   = NET_PROTO_UDP;
    e->dport      = NET_DNS_PORT;

    /* sin_addr 为网络序，原始拷贝前 4 字节；源地址/端口未知保持 0 */
    __builtin_memcpy(e->daddr, &sin->sin_addr, sizeof(sin->sin_addr));

    if (parse_dns_query(e, buff, len) == 0) {
        bpf_ringbuf_submit(e, 0);
        inc_net_drop_slot(DROP_SLOT_EMITTED);
    } else {
        bpf_ringbuf_discard(e, 0);
        inc_net_drop_slot(DROP_SLOT_DISCARDED);
    }
}

/* ── 已连接 socket 的目的地址回溯：fd → file → socket → sock ──────
 * sendto/sendmsg/sendmmsg 传 NULL 地址时（已连接 UDP socket；dig 实测
 * connect 到 127.0.0.53 后用 sendmmsg），从当前任务文件表解析目的
 * 地址，仅认可 UDP（SOCK_DGRAM）且 AF_INET、skc_dport==53。
 * 任一 probe 失败或类型不符返回非 0（调用方放弃该事件）。
 */
static __always_inline int resolve_dns_dst_from_fd(unsigned int fd, struct sockaddr_in *sin)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    struct files_struct *files;
    struct fdtable *fdt;
    struct file **fdarr;
    struct file *filp;
    struct socket *sock;
    struct sock *sk;
    unsigned short type;
    __be32 daddr;

    files = BPF_CORE_READ(task, files);
    if (!files)
        return -1;
    fdt = BPF_CORE_READ(files, fdt);
    if (!fdt)
        return -1;
    fdarr = BPF_CORE_READ(fdt, fd);
    if (!fdarr)
        return -1;
    if (bpf_probe_read_kernel(&filp, sizeof(filp), &fdarr[fd]) != 0 || !filp)
        return -1;
    sock = (struct socket *)BPF_CORE_READ(filp, private_data);
    if (!sock)
        return -1;
    type = ((unsigned short)BPF_CORE_READ(sock, type)) & 0xf;   /* SOCK_TYPE_MASK */
    if (type != 2)   /* SOCK_DGRAM */
        return -1;
    sk = BPF_CORE_READ(sock, sk);
    if (!sk)
        return -1;
    if (BPF_CORE_READ(sk, __sk_common.skc_family) != NET_FAMILY_INET)
        return -1;
    if (bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport)) != NET_DNS_PORT)
        return -1;

    __builtin_memset(sin, 0, sizeof(*sin));
    sin->sin_family = NET_FAMILY_INET;
    daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __builtin_memcpy(&sin->sin_addr, &daddr, sizeof(daddr));
    return 0;
}

/* ── DNS 查询：sys_enter_sendto tracepoint ─────────────────────
 * args: fd, buff, len, flags, addr, addr_len。
 * addr 非空时直接解析 sockaddr；addr 为 NULL（send()/已连接 socket）时
 * 从 fd 回溯目的地址。仅处理 AF_INET + dport=53。
 */
SEC("tracepoint/syscalls/sys_enter_sendto")
int tp_sys_enter_sendto(struct trace_event_raw_sys_enter *ctx)
{
    const void *buff = (const void *)ctx->args[1];
    unsigned long long len = (unsigned long long)ctx->args[2];
    struct sockaddr *addr = (struct sockaddr *)ctx->args[4];
    struct sockaddr_in sin;
    sa_family_t family;
    struct net_event *e;

    if (!buff || len < DNS_HDR_LEN)
        return 0;

    if (addr) {
        if (bpf_probe_read_user(&family, sizeof(family), &addr->sa_family) != 0)
            return 0;
        if (family != NET_FAMILY_INET)
            return 0;
        if (bpf_probe_read_user(&sin, sizeof(sin), addr) != 0)
            return 0;
        if (bpf_ntohs(sin.sin_port) != NET_DNS_PORT)
            return 0;
    } else {
        if (resolve_dns_dst_from_fd((__u32)ctx->args[0], &sin) != 0)
            return 0;
    }

    e = reserve_net_event();
    if (!e)
        return 0;

    submit_dns_event(e, &sin, buff, len);
    return 0;
}

/* ── DNS 查询（尽力）：sys_enter_sendmsg / sys_enter_sendmmsg ────
 * sendmsg args: fd, msg, flags；msg 为 user_msghdr（x86_64 布局 56 字节）：
 *   name(0,8) namelen(8,4) pad(12,4) iov(16,8) iovlen(24,8)
 *   control(32,8) controllen(40,8) flags(48,4) pad(52,4)
 * sendmmsg args: fd, msgvec, vlen, flags；msgvec[0] = { user_msghdr; msg_len }。
 * msg_name 非空时直接解析 sockaddr；为 NULL（已连接 socket）时从 fd 回溯。
 * 要求首个 iov 携带完整 DNS 头；任一 probe 失败静默丢弃。
 */
struct dns_msghdr {
    void *msg_name;
    unsigned int msg_namelen;
    unsigned int pad;
    void *msg_iov;
    unsigned long long msg_iovlen;
    void *msg_control;
    unsigned long long msg_controllen;
    unsigned int msg_flags;
    unsigned int pad1;
};

struct dns_mmsghdr {
    struct dns_msghdr msg_hdr;
    unsigned int msg_len;   /* 发送完成由内核回填，入口时未初始化，不使用 */
    unsigned int pad;
};

static __always_inline int handle_dns_msghdr(struct trace_event_raw_sys_enter *ctx,
                                             struct dns_msghdr *mh)
{
    struct iovec iov0;
    struct sockaddr_in sin;
    sa_family_t family;
    struct net_event *e;

    if (!mh->msg_iov)
        return 0;

    if (mh->msg_name) {
        if (bpf_probe_read_user(&family, sizeof(family), mh->msg_name) != 0)
            return 0;
        if (family != NET_FAMILY_INET)
            return 0;
        if (bpf_probe_read_user(&sin, sizeof(sin), mh->msg_name) != 0)
            return 0;
        if (bpf_ntohs(sin.sin_port) != NET_DNS_PORT)
            return 0;
    } else {
        if (resolve_dns_dst_from_fd((__u32)ctx->args[0], &sin) != 0)
            return 0;
    }

    if (bpf_probe_read_user(&iov0, sizeof(iov0), mh->msg_iov) != 0)
        return 0;
    if (!iov0.iov_base || iov0.iov_len < DNS_HDR_LEN)
        return 0;

    e = reserve_net_event();
    if (!e)
        return 0;

    submit_dns_event(e, &sin, iov0.iov_base, iov0.iov_len);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int tp_sys_enter_sendmsg(struct trace_event_raw_sys_enter *ctx)
{
    struct dns_msghdr mh;

    if (bpf_probe_read_user(&mh, sizeof(mh), (void *)ctx->args[1]) != 0)
        return 0;
    return handle_dns_msghdr(ctx, &mh);
}

SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int tp_sys_enter_sendmmsg(struct trace_event_raw_sys_enter *ctx)
{
    struct dns_mmsghdr mm;

    if (bpf_probe_read_user(&mm, sizeof(mm), (void *)ctx->args[1]) != 0)
        return 0;
    return handle_dns_msghdr(ctx, &mm.msg_hdr);
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
    inc_net_drop_slot(DROP_SLOT_EMITTED);
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
    inc_net_drop_slot(DROP_SLOT_EMITTED);
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
    inc_net_drop_slot(DROP_SLOT_EMITTED);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
