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
#include "net_event.h"

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

int handle_network_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    if (data_sz < sizeof(struct net_event))
        return 0;

    // ring buffer 回调内的内存是只读 mmap：先 memcpy 再处理
    struct net_event evt;
    memcpy(&evt, data, sizeof(evt));

    static const char *kind_names[] = {"", "network.connect", "network.accept", "network.bind"};
    const char *kind = (evt.event_kind >= NET_EVENT_CONNECT && evt.event_kind <= NET_EVENT_BIND)
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

    json net;
    net["family"]   = evt.family;
    net["protocol"] = evt.protocol;
    net["sip"]      = ipv4_to_string(evt.saddr);
    net["sport"]    = evt.sport;
    net["dip"]      = ipv4_to_string(evt.daddr);
    net["dport"]    = evt.dport;

    json j;
    j["event_type"] = kind;
    j["ts"]         = evt.ts_ns;
    j["process"]    = proc;
    j["network"]    = net;

    // 宿主机进程或解析失败时省略 container 字段
    std::string cid = container_id_of(static_cast<int>(evt.pid));
    if (!cid.empty()) {
        json c;
        c["container_id"] = cid;
        j["container"] = c;
    }

    spdlog::info("{}", j.dump());
    return 0;
}

struct net_watch_bpf *network_monitor_start(struct ring_buffer **rb_out)
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
    spdlog::info("[bpf_program_loaded] net_watch attached (tcp_v4_connect / inet_csk_accept / sys_enter_bind)");

    rb = ring_buffer__new(bpf_map__fd(skel->maps.net_events), handle_network_event, nullptr, nullptr);
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
    net_watch_bpf__destroy(skel);
    spdlog::info("[service_stop] net_watch stopped");
}
