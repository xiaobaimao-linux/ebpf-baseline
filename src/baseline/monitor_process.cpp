#include "monitor_process.hpp"

#include <unistd.h>

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
#include "proc_event.h"
#include "stats_slots.h"

// 包含生成的skeleton头文件（经 -I. 从仓库根目录引用 bpf/）
#include "bpf/proc_watch.skel.h"

using json = nlohmann::json;

// comm 不保证 NUL 结尾：拷到 17 字节本地数组再补 \0
static std::string comm_to_string(const char *comm)
{
    char buf[17];
    memcpy(buf, comm, 16);
    buf[16] = '\0';
    return std::string(buf);
}

// ── 消费线程渲染：proc_event(exec) -> 落库 JSON 负载 ─────────────────
// exe 优先用 /proc 解析的真实路径（tracepoint filename 可能是相对路径），
// 解析失败回退事件自带的 filename。祖先链由 Enricher 后续追加。
void render_process_exec_event(const struct proc_event& evt, struct EventRecord& rec,
                               json& out)
{
    std::string exe = exe_path_of(static_cast<int>(evt.pid));
    if (exe.empty())
        exe.assign(evt.exe, strnlen(evt.exe, sizeof(evt.exe)));

    json proc;
    proc["pid"]  = evt.pid;
    proc["ppid"] = evt.ppid;
    proc["uid"]  = evt.uid;
    proc["gid"]  = evt.gid;
    proc["comm"] = comm_to_string(evt.comm);
    if (!exe.empty())
        proc["exe"] = exe;

    json j;
    j["event_type"] = "process.exec";
    j["ts"]         = evt.ts_ns;
    j["process"]    = proc;

    record_set_str(rec.exe, sizeof(rec.exe), exe.c_str(), exe.size());
    out = j;
}

// ── rb 回调：proc_event 归一化为 EventRecord 入事件总线 hi 队列 ───────
// 只做归一化 + try_push：禁 malloc / 阻塞 / /proc IO。
int handle_process_event(void *ctx, void *data, size_t data_sz)
{
    auto* bus = static_cast<EventBus*>(ctx);
    if (!bus || data_sz < sizeof(struct proc_event))
        return 0;

    struct proc_event evt;
    memcpy(&evt, data, sizeof(evt));

    EventRecord rec{};   // 定长 POD，零初始化
    rec.ts_ns         = evt.ts_ns;
    rec.enqueue_ts_ns = now_monotonic_ns();
    rec.pid           = evt.pid;
    rec.ppid          = evt.ppid;
    rec.uid           = evt.uid;
    rec.gid           = evt.gid;
    memcpy(rec.comm, evt.comm, sizeof(rec.comm));
    rec.category = CAT_PROCESS;
    rec.priority = PRIO_CTRL;   // hi 队列
    rec.action   = evt.kind;
    static_assert(sizeof(evt) <= sizeof(rec.payload_raw), "proc_event 超出 payload_raw 容量");
    memcpy(rec.payload_raw, &evt, sizeof(evt));  // 原始事件字节，供消费线程建树/渲染

    bus->try_push(rec);
    return 0;
}

struct proc_watch_bpf *process_monitor_start(struct ring_buffer **rb_out, EventBus *bus)
{
    struct proc_watch_bpf *skel = nullptr;
    struct ring_buffer *rb = nullptr;
    int err;

    *rb_out = nullptr;

    skel = proc_watch_bpf__open();
    if (!skel) {
        spdlog::error("[bpf_program_error] Failed to open proc_watch skeleton");
        return nullptr;
    }

    err = proc_watch_bpf__load(skel);
    if (err) {
        spdlog::error("[bpf_program_error] Failed to load proc_watch skeleton: {}", err);
        proc_watch_bpf__destroy(skel);
        return nullptr;
    }

    err = proc_watch_bpf__attach(skel);
    if (err) {
        spdlog::error("[bpf_program_error] Failed to attach proc_watch programs: {}", err);
        proc_watch_bpf__destroy(skel);
        return nullptr;
    }
    spdlog::info("[bpf_program_loaded] proc_watch attached (fork/exec/exit)");

    // pin 丢包计数 map 供 stats --drop 读取（先 unlink 清陈旧 pin）
    unlink(PROC_DROP_STATS_PIN_PATH);
    if (int err = bpf_map__pin(skel->maps.proc_drop_stats, PROC_DROP_STATS_PIN_PATH))
        spdlog::warn("[bpf_map_pin] failed to pin proc_drop_stats: {}", strerror(-err));

    rb = ring_buffer__new(bpf_map__fd(skel->maps.proc_events), handle_process_event, bus, nullptr);
    if (!rb) {
        spdlog::error("[bpf_program_error] Failed to create proc_events ring buffer");
        proc_watch_bpf__destroy(skel);
        return nullptr;
    }

    *rb_out = rb;
    return skel;
}

void process_monitor_stop(struct proc_watch_bpf *skel, struct ring_buffer *rb)
{
    if (!skel)
        return;

    // 汇总 per-CPU proc_drop_stats 上报丢包数
    int fd = bpf_map__fd(skel->maps.proc_drop_stats);
    int ncpu = libbpf_num_possible_cpus();
    if (fd >= 0 && ncpu > 0) {
        std::vector<__u64> values(ncpu);
        __u32 key = 0;
        if (bpf_map_lookup_elem(fd, &key, values.data()) == 0) {
            __u64 total = 0;
            for (int i = 0; i < ncpu; i++)
                total += values[i];
            if (total > 0)
                spdlog::warn("[proc_watch] {} process events dropped (ring buffer reserve failed)", total);
        }
    }

    if (rb)
        ring_buffer__free(rb);
    bpf_map__unpin(skel->maps.proc_drop_stats, PROC_DROP_STATS_PIN_PATH);
    proc_watch_bpf__destroy(skel);
    spdlog::info("[service_stop] proc_watch stopped");
}
