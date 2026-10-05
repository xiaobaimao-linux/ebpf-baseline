#include "monitor_privilege.hpp"

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
#include "priv_event.h"
#include "stats_slots.h"

// 包含生成的skeleton头文件（经 -I. 从仓库根目录引用 bpf/）
#include "bpf/priv_watch.skel.h"

using json = nlohmann::json;

// comm 不保证 NUL 结尾：拷到 17 字节本地数组再补 \0
static std::string comm_to_string(const char *comm)
{
    char buf[17];
    memcpy(buf, comm, 16);
    buf[16] = '\0';
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

// ptrace request 数值转字符串（用户态做，内核只透传数值）；未知值返回空串，
// 调用方回退为数值输出。数值取自 uapi/linux/ptrace.h。
static std::string ptrace_request_name(unsigned long long request)
{
    switch (request) {
    case 0:  return "PTRACE_TRACEME";
    case 1:  return "PTRACE_PEEKTEXT";
    case 2:  return "PTRACE_PEEKDATA";
    case 3:  return "PTRACE_PEEKUSR";
    case 4:  return "PTRACE_POKETEXT";
    case 5:  return "PTRACE_POKEDATA";
    case 6:  return "PTRACE_POKEUSR";
    case 7:  return "PTRACE_CONT";
    case 8:  return "PTRACE_KILL";
    case 9:  return "PTRACE_SINGLESTEP";
    case 12: return "PTRACE_GETREGS";
    case 13: return "PTRACE_SETREGS";
    case 14: return "PTRACE_GETFPREGS";
    case 15: return "PTRACE_SETFPREGS";
    case 16: return "PTRACE_ATTACH";
    case 17: return "PTRACE_DETACH";
    case 24: return "PTRACE_SYSCALL";
    case 0x4200: return "PTRACE_SEIZE";
    case 0x4201: return "PTRACE_INTERRUPT";
    case 0x4202: return "PTRACE_LISTEN";
    case 0x4203: return "PTRACE_PEEKSIGINFO";
    default: return "";
    }
}

// CLONE_NEW* 位→名字映射（数值取自 uapi/linux/sched.h，本机 /usr/include/linux/sched.h 核实）
static const struct {
    unsigned long long bit;
    const char *name;
} ns_flag_names[] = {
    {0x00000080ULL, "NEWTIME"},   // CLONE_NEWTIME
    {0x00020000ULL, "NEWNS"},     // CLONE_NEWNS
    {0x02000000ULL, "NEWCGROUP"}, // CLONE_NEWCGROUP
    {0x04000000ULL, "NEWUTS"},    // CLONE_NEWUTS
    {0x08000000ULL, "NEWIPC"},    // CLONE_NEWIPC
    {0x10000000ULL, "NEWUSER"},   // CLONE_NEWUSER
    {0x20000000ULL, "NEWPID"},    // CLONE_NEWPID
    {0x40000000ULL, "NEWNET"},    // CLONE_NEWNET
};

// unshare flags 解码成名字数组；已知位给名字，未知位保留数值原样入数组
static void decode_ns_flags(unsigned long long flags, json *names)
{
    unsigned long long known = 0;
    for (const auto &f : ns_flag_names) {
        if (flags & f.bit) {
            names->push_back(f.name);
            known |= f.bit;
        }
    }
    unsigned long long unknown = flags & ~known;
    for (unsigned int i = 0; unknown; i++, unknown >>= 1) {
        if (unknown & 1)
            names->push_back(1ULL << i);
    }
}

// setns nstype 单值解码；0（任意）与未知值返回空串，调用方省略字段
static std::string ns_type_name(unsigned int nstype)
{
    for (const auto &f : ns_flag_names) {
        if (nstype == f.bit)
            return f.name;
    }
    return "";
}

// /proc/<pid>/fd/<fd> readlink 尽力补 target_ns；短寿进程 /proc 已回收、
// fd 已关闭等失败场景静默返回空串，由调用方省略字段
static std::string ns_fd_target(int pid, int fd)
{
    char path[64];
    char buf[256];
    snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, fd);
    ssize_t n = readlink(path, buf, sizeof(buf) - 1);
    if (n <= 0)
        return "";
    buf[n] = '\0';
    return std::string(buf);
}

// ── 消费线程渲染：priv_event -> JSON（含 exe/container /proc IO）──────
// 本函数自原 rb 回调原样迁移（行为零变化），日志输出与迁移前逐字节一致；
// 同时回填 rec.exe / rec.container_id 供落库索引列使用。
void render_privilege_event(const struct priv_event& evt, struct EventRecord& rec,
                            json& out)
{
    static const char *kind_names[] = {"", "priv.setuid", "priv.setgid",
                                       "priv.capset", "priv.ptrace", "priv.module_load",
                                       "ns.mount", "ns.unshare", "ns.setns"};
    const char *kind = (evt.priv_kind >= PRIV_KIND_SETUID && evt.priv_kind <= PRIV_KIND_SETNS)
                           ? kind_names[evt.priv_kind]
                           : "priv.unknown";

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

    if (evt.priv_kind >= PRIV_KIND_MOUNT) {
        // 命名空间事件：负载放 ns 对象
        json ns;
        switch (evt.priv_kind) {
        case PRIV_KIND_MOUNT:
            // 字符串不保证 NUL 结尾：以长度字段为界拷本地补 \0
            ns["source"] = std::string(evt.u.mount.source, strnlen(evt.u.mount.source, sizeof(evt.u.mount.source)));
            ns["target"] = std::string(evt.u.mount.target, strnlen(evt.u.mount.target, sizeof(evt.u.mount.target)));
            ns["fstype"] = std::string(evt.u.mount.fstype, strnlen(evt.u.mount.fstype, sizeof(evt.u.mount.fstype)));
            ns["flags"]  = evt.u.mount.flags;
            break;
        case PRIV_KIND_UNSHARE: {
            ns["flags"] = evt.u.unshare.flags;
            json names  = json::array();
            decode_ns_flags(evt.u.unshare.flags, &names);
            ns["names"] = names;
            break;
        }
        case PRIV_KIND_SETNS: {
            ns["fd"]     = evt.u.setns.fd;
            ns["nstype"] = evt.u.setns.nstype;
            std::string tn = ns_type_name(evt.u.setns.nstype);
            if (!tn.empty())
                ns["nstype_name"] = tn;
            // 尽力补 target_ns：读 /proc/<pid>/fd/<fd> 软链，失败省略不报错
            std::string tgt = ns_fd_target(static_cast<int>(evt.pid), evt.u.setns.fd);
            if (!tgt.empty())
                ns["target_ns"] = tgt;
            break;
        }
        default:
            break;
        }
        j["ns"] = ns;
    } else {
        json priv;
        switch (evt.priv_kind) {
        case PRIV_KIND_SETUID:
        case PRIV_KIND_SETGID:
            priv["target_id"] = evt.u.target_id;
            break;
        case PRIV_KIND_CAPSET:
            priv["effective_lo"] = evt.u.effective_lo;
            break;
        case PRIV_KIND_PTRACE: {
            priv["target_pid"] = evt.u.ptrace.target_pid;
            std::string req = ptrace_request_name(evt.u.ptrace.request);
            if (!req.empty()) {
                priv["request"] = req;
            } else {
                // 未知 request 数值：以数值回退输出，同时给字符串占位
                priv["request"] = "PTRACE_UNKNOWN";
            }
            priv["request_value"] = evt.u.ptrace.request;
            break;
        }
        case PRIV_KIND_MODULE_LOAD:
            // name 不保证 NUL 结尾：以长度字段为界拷本地补 \0
            priv["name"] = std::string(evt.u.name, strnlen(evt.u.name, sizeof(evt.u.name)));
            break;
        default:
            break;
        }
        j["priv"] = priv;
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

// ── rb 回调：priv_event 归一化为 EventRecord 入事件总线 ───────────────
// 只做归一化 + try_push：禁 malloc / 阻塞 / /proc IO（/proc IO 已移至消费线程渲染）。
int handle_privilege_event(void *ctx, void *data, size_t data_sz)
{
    auto* bus = static_cast<EventBus*>(ctx);
    if (!bus || data_sz < sizeof(struct priv_event))
        return 0;

    // ring buffer 回调内的内存是只读 mmap：先 memcpy 再处理
    struct priv_event evt;
    memcpy(&evt, data, sizeof(evt));

    EventRecord rec{};   // 定长 POD，零初始化
    rec.ts_ns         = evt.ts_ns;
    rec.enqueue_ts_ns = now_monotonic_ns();
    rec.pid           = evt.pid;
    rec.ppid          = evt.ppid;
    rec.uid           = evt.uid;
    rec.gid           = evt.gid;
    memcpy(rec.comm, evt.comm, sizeof(rec.comm));
    // setuid/setgid/capset/ptrace/module_load -> priv；mount/unshare/setns -> ns
    rec.category = (evt.priv_kind >= PRIV_KIND_MOUNT) ? CAT_NS : CAT_PRIV;
    rec.priority = PRIO_CTRL;
    rec.action   = evt.priv_kind;
    // 原始事件字节留给消费线程渲染
    memcpy(rec.payload_json, &evt, sizeof(evt));

    bus->try_push(rec);
    return 0;
}

struct priv_watch_bpf *privilege_monitor_start(struct ring_buffer **rb_out, EventBus *bus)
{
    struct priv_watch_bpf *skel = nullptr;
    struct ring_buffer *rb = nullptr;
    int err;

    *rb_out = nullptr;

    skel = priv_watch_bpf__open();
    if (!skel) {
        spdlog::error("[bpf_program_error] Failed to open priv_watch skeleton");
        return nullptr;
    }

    err = priv_watch_bpf__load(skel);
    if (err) {
        spdlog::error("[bpf_program_error] Failed to load priv_watch skeleton: {}", err);
        priv_watch_bpf__destroy(skel);
        return nullptr;
    }

    err = priv_watch_bpf__attach(skel);
    if (err) {
        spdlog::error("[bpf_program_error] Failed to attach priv_watch programs: {}", err);
        priv_watch_bpf__destroy(skel);
        return nullptr;
    }
    spdlog::info("[bpf_program_loaded] priv_watch attached (setuid/setgid/capset/ptrace/module_load/mount/unshare/setns)");

    // pin 丢包计数 map 供 stats --drop 读取（先 unlink 清陈旧 pin）
    unlink(PRIV_DROP_STATS_PIN_PATH);
    if (int err = bpf_map__pin(skel->maps.priv_drop_stats, PRIV_DROP_STATS_PIN_PATH))
        spdlog::warn("[bpf_map_pin] failed to pin priv_drop_stats: {}", strerror(-err));

    rb = ring_buffer__new(bpf_map__fd(skel->maps.priv_events), handle_privilege_event, bus, nullptr);
    if (!rb) {
        spdlog::error("[bpf_program_error] Failed to create priv_events ring buffer");
        priv_watch_bpf__destroy(skel);
        return nullptr;
    }

    *rb_out = rb;
    return skel;
}

void privilege_monitor_stop(struct priv_watch_bpf *skel, struct ring_buffer *rb)
{
    if (!skel)
        return;

    // 汇总 per-CPU priv_drop_stats 上报丢包数
    int fd = bpf_map__fd(skel->maps.priv_drop_stats);
    int ncpu = libbpf_num_possible_cpus();
    if (fd >= 0 && ncpu > 0) {
        std::vector<__u64> values(ncpu);
        __u32 key = 0;
        if (bpf_map_lookup_elem(fd, &key, values.data()) == 0) {
            __u64 total = 0;
            for (int i = 0; i < ncpu; i++)
                total += values[i];
            if (total > 0)
                spdlog::warn("[priv_watch] {} privilege events dropped (ring buffer reserve failed)", total);
        }
    }

    if (rb)
        ring_buffer__free(rb);
    bpf_map__unpin(skel->maps.priv_drop_stats, PRIV_DROP_STATS_PIN_PATH);
    priv_watch_bpf__destroy(skel);
    spdlog::info("[service_stop] priv_watch stopped");
}
