#include "monitor_network.hpp"

#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include "container.hpp"
#include "event_bus.hpp"
#include "event_record.hpp"
#include "net_event.h"
#include "stats_slots.h"

// 包含生成的skeleton头文件（经 -I. 从仓库根目录引用 bpf/）
#include "bpf/net_watch.skel.h"

using json = nlohmann::json;

// comm 不保证 NUL 结尾：拷到 17 字节本地数组再补 \0
static std::string comm_to_string(const char *comm)
{
    char buf[17];
    memcpy(buf, comm, 16);
    buf[16] = '\0';
    return std::string(buf);
}

// 事件内地址为网络序原始字节，IPv4 取前 4 字节
static std::string ipv4_to_string(const unsigned char *addr)
{
    char buf[16];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
    return std::string(buf);
}

// DNS QNAME 线格式（[len][bytes]...[0]）转点分文本。
// 以长度字段为界解析（数据不保证可读字符），任一段异常返回空串。
static std::string dns_qname_to_string(const unsigned char *qname, size_t max_len)
{
    std::string out;
    size_t i = 0;

    while (i < max_len) {
        unsigned int l = qname[i];
        if (l == 0)
            break;
        if (l > 63 || i + 1 + l > max_len) {
            out.clear();
            return out;
        }
        if (!out.empty())
            out += '.';
        out.append(reinterpret_cast<const char *>(qname + i + 1), l);
        i += 1 + l;
    }
    return out;
}

// /proc/<pid>/exe readlink；短寿进程 /proc 消失属正常场景，失败返回空串（省略字段）
static std::string exe_of(int pid)
{
    char path[64];
    char buf[4096];
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    ssize_t n = readlink(path, buf, sizeof(buf) - 1);
    if (n <= 0)
        return "";
    buf[n] = '\0';
    return std::string(buf);
}

// ── 消费线程渲染：net_event -> JSON（含 exe/container /proc IO）────────
// 本函数自原 rb 回调原样迁移（行为零变化），日志输出与迁移前逐字节一致；
// 同时回填 rec.exe / rec.container_id 供落库索引列使用。
void render_network_event(const struct net_event& evt, struct EventRecord& rec,
                          json& out)
{
    static const char *kind_names[] = {"", "network.connect", "network.accept", "network.bind", "network.dns"};
    const char *kind = (evt.event_kind >= NET_EVENT_CONNECT && evt.event_kind <= NET_EVENT_DNS)
                           ? kind_names[evt.event_kind]
                           : "network.unknown";

    json proc;
    proc["pid"]  = evt.pid;
    proc["ppid"] = evt.ppid;
    proc["uid"]  = evt.uid;
    proc["gid"]  = evt.gid;
    proc["comm"] = comm_to_string(evt.comm);

    std::string exe = exe_of(static_cast<int>(evt.pid));
    if (!exe.empty())
        proc["exe"] = exe;

    json j;
    j["event_type"] = kind;
    j["ts"]         = evt.ts_ns;
    j["process"]    = proc;

    if (evt.event_kind == NET_EVENT_DNS) {
        // domain 为 QNAME 线格式（[len][bytes]...[0]）：以长度字段为界转点分文本，
        // 转换结果经 nlohmann 自动转义后进 JSON
        json dns;
        dns["domain"] = dns_qname_to_string(evt.domain, sizeof(evt.domain));
        dns["qtype"]  = evt.qtype;
        j["dns"] = dns;
    } else {
        json net;
        net["family"]   = evt.family;
        net["protocol"] = evt.protocol;
        net["sip"]      = ipv4_to_string(evt.saddr);
        net["sport"]    = evt.sport;
        net["dip"]      = ipv4_to_string(evt.daddr);
        net["dport"]    = evt.dport;
        j["network"]    = net;
    }

    // 宿主机进程或解析失败时省略 container 字段
    std::string cid = container_id_of(static_cast<int>(evt.pid));
    if (!cid.empty()) {
        json c;
        c["container_id"] = cid;
        j["container"] = c;
    }

    // 回填 EventRecord 头部（落库 exe / container_id 列）
    record_set_str(rec.exe, sizeof(rec.exe), exe.c_str(), exe.size());
    record_set_str(rec.container_id, sizeof(rec.container_id), cid.c_str(), cid.size());

    out = j;
}

// ── rb 回调：net_event 归一化为 EventRecord 入事件总线 ────────────────
// 只做归一化 + try_push：禁 malloc / 阻塞 / /proc IO（/proc IO 已移至消费线程渲染）。
int handle_network_event(void *ctx, void *data, size_t data_sz)
{
    auto* bus = static_cast<EventBus*>(ctx);
    if (!bus || data_sz < sizeof(struct net_event))
        return 0;

    // ring buffer 回调内的内存是只读 mmap：先 memcpy 再处理
    struct net_event evt;
    memcpy(&evt, data, sizeof(evt));

    EventRecord rec{};   // 定长 POD，零初始化（payload/exe/container_id 一并清零）
    rec.ts_ns         = evt.ts_ns;
    rec.enqueue_ts_ns = now_monotonic_ns();
    rec.pid           = evt.pid;
    rec.ppid          = evt.ppid;
    rec.uid           = evt.uid;
    rec.gid           = evt.gid;
    memcpy(rec.comm, evt.comm, sizeof(rec.comm));
    rec.category = (evt.event_kind == NET_EVENT_DNS) ? CAT_DNS : CAT_NETWORK;
    rec.priority = (evt.event_kind == NET_EVENT_DNS) ? PRIO_DNS : PRIO_NETWORK;
    rec.action   = evt.event_kind;
    // 原始事件字节留给消费线程渲染（内部路由用；渲染 JSON 随 Append 直传，不写回槽位）
    static_assert(sizeof(evt) <= sizeof(rec.payload_raw), "net_event 超出 payload_raw 容量");
    memcpy(rec.payload_raw, &evt, sizeof(evt));

    bus->try_push(rec);
    return 0;
}

struct net_watch_bpf *network_monitor_start(struct ring_buffer **rb_out,
                                            bool enable_conn, bool enable_dns,
                                            EventBus *bus)
{
    struct net_watch_bpf *skel = nullptr;
    struct ring_buffer *rb = nullptr;
    int err;

    *rb_out = nullptr;

    skel = net_watch_bpf__open();
    if (!skel) {
        spdlog::error("[bpf_program_error] Failed to open net_watch skeleton");
        return nullptr;
    }

    // 按开关裁剪自动加载的程序：关闭的遥测不加载对应挂点
    if (!enable_conn) {
        bpf_program__set_autoload(skel->progs.kprobe_tcp_v4_connect, false);
        bpf_program__set_autoload(skel->progs.kretprobe_inet_csk_accept, false);
        bpf_program__set_autoload(skel->progs.tp_sys_enter_bind, false);
    }
    if (!enable_dns) {
        bpf_program__set_autoload(skel->progs.tp_sys_enter_sendto, false);
        bpf_program__set_autoload(skel->progs.tp_sys_enter_sendmsg, false);
        bpf_program__set_autoload(skel->progs.tp_sys_enter_sendmmsg, false);
    }

    err = net_watch_bpf__load(skel);
    if (err) {
        spdlog::error("[bpf_program_error] Failed to load net_watch skeleton: {}", err);
        net_watch_bpf__destroy(skel);
        return nullptr;
    }

    err = net_watch_bpf__attach(skel);
    if (err) {
        spdlog::error("[bpf_program_error] Failed to attach net_watch programs: {}", err);
        net_watch_bpf__destroy(skel);
        return nullptr;
    }
    spdlog::info("[bpf_program_loaded] net_watch attached (conn={} dns={})",
                 enable_conn ? "on" : "off", enable_dns ? "on(sendto/sendmsg/sendmmsg)" : "off");

    // pin 丢包计数 map 供 stats --drop 读取（先 unlink 清陈旧 pin）
    unlink(NET_DROP_STATS_PIN_PATH);
    if (int err = bpf_map__pin(skel->maps.net_drop_stats, NET_DROP_STATS_PIN_PATH))
        spdlog::warn("[bpf_map_pin] failed to pin net_drop_stats: {}", strerror(-err));

    rb = ring_buffer__new(bpf_map__fd(skel->maps.net_events), handle_network_event, bus, nullptr);
    if (!rb) {
        spdlog::error("[bpf_program_error] Failed to create net_events ring buffer");
        net_watch_bpf__destroy(skel);
        return nullptr;
    }

    *rb_out = rb;
    return skel;
}

void network_monitor_stop(struct net_watch_bpf *skel, struct ring_buffer *rb)
{
    if (!skel)
        return;

    // 汇总 per-CPU net_drop_stats 上报丢包数
    int fd = bpf_map__fd(skel->maps.net_drop_stats);
    int ncpu = libbpf_num_possible_cpus();
    if (fd >= 0 && ncpu > 0) {
        std::vector<__u64> values(ncpu);
        __u32 key = 0;
        if (bpf_map_lookup_elem(fd, &key, values.data()) == 0) {
            __u64 total = 0;
            for (int i = 0; i < ncpu; i++)
                total += values[i];
            if (total > 0)
                spdlog::warn("[net_watch] {} network events dropped (ring buffer reserve failed)", total);
        }
    }

    if (rb)
        ring_buffer__free(rb);
    bpf_map__unpin(skel->maps.net_drop_stats, NET_DROP_STATS_PIN_PATH);
    net_watch_bpf__destroy(skel);
    spdlog::info("[service_stop] net_watch stopped");
}
