#include "monitor.hpp"
#include "../bpf/event.h"
#include "monitor_baseline.hpp"
#include "watermark_backpressure.hpp"
#include "utils.hpp"
#include "config.hpp"
#include "commonfun.hpp"
#include "baseline_db.hpp"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <csignal>
#include <cstring>
#include <fstream>
#include <iostream>
#include <linux/types.h>
#include <pwd.h>
#include <spdlog/spdlog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unordered_map>
#include <vector>
#include <sstream>

// 包含生成的skeleton头文件
#include "../bpf/lsm_file.skel.h"        // 5.8+ ring buffer
#include "../bpf/lsm_file_perf.skel.h"   // 5.7 perf buffer
#include "../bpf/lsm_kprobe.skel.h"      // 5.4 kprobe

static volatile bool running = true;

// ── 内核版本检测 ────────────────────────────────────────────────
struct KernelVersion { unsigned int major, minor; };

static KernelVersion get_kernel_version() {
    struct utsname uts;
    KernelVersion kv = {0, 0};
    if (uname(&uts) == 0) {
        sscanf(uts.release, "%u.%u", &kv.major, &kv.minor);
    }
    return kv;
}

static bool kernel_at_least(unsigned int major, unsigned int minor) {
    auto kv = get_kernel_version();
    return kv.major > major || (kv.major == major && kv.minor >= minor);
}

void signal_handler(int sig) {
    running = false;
    if (sig == SIGTERM) {
        spdlog::info("[service_stop] received SIGTERM, shutting down gracefully");
    }
}

static std::string ResolveUserInfoByPid(int pid, std::string& uid) {
    uid.clear();
    std::string user_name;

    if (pid <= 0) {
        return user_name;
    }

    const std::string proc_status = "/proc/" + std::to_string(pid) + "/status";
    std::ifstream in(proc_status);
    if (!in.is_open()) {
        return user_name;
    }

    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind("Uid:", 0) == 0) {
            std::istringstream iss(line);
            std::string key;
            iss >> key;
            int raw_uid = 0;
            iss >> raw_uid;
            if (raw_uid > 0) {
                uid = std::to_string(raw_uid);
                struct passwd* pw = getpwuid(static_cast<uid_t>(raw_uid));
                if (pw != nullptr) {
                    user_name = pw->pw_name;
                }
            }
            break;
        }
    }

    return user_name;
}

// 全局映射（或封装到类）
std::unordered_map<unsigned long, Rule> g_inode_to_rule;
std::unordered_map<unsigned long, std::string> g_inode_to_path;
std::unordered_map<unsigned long, std::string> g_inode_to_hash;

// 基线实时监控映射：inode -> CheckEntry（仅当 --db 模式下非空）
std::unordered_map<unsigned long, CheckEntry> g_inode_to_baseline;

// 初始化映射
void init_inode_maps(const Config &config) {
    g_inode_to_rule.clear();
    g_inode_to_path.clear();
    g_inode_to_hash.clear();

    for (const auto &rule : config.rules) {
        if (!rule.has_monitor)
            continue;
        if (rule.monitor_path.empty())
            continue;
        if (rule.ino == 0)
            continue;
        g_inode_to_rule[rule.ino] = rule;
        g_inode_to_path[rule.ino] = rule.monitor_path;
        if (!rule.check_hash.empty()) {
            g_inode_to_hash[rule.ino] = rule.check_hash;
        }
    }
}


void on_violation_detected(const Rule& rule, 
                           const std::string& file_path,
                           const std::string& actual_mode,
                           const std::string& proc_name,
                           int pid,
                           AlertManager& alert_mgr)
{
    std::string uid;
    const std::string user_name = ResolveUserInfoByPid(pid, uid);

    // 1. 写日志
    spdlog::warn("VIOLATION: {} mode {} -> {} by {}/{} user={} uid={}",
                 file_path, mode_to_string(rule.check_expected), actual_mode, proc_name, pid,
                 user_name.empty() ? "unknown" : user_name,
                 uid.empty() ? "-" : uid);

    // 2. 发钉钉 + 自动落库（AlertManager 内部统一处理，被节流也入库）
    AlertEvent evt;
    evt.rule_id      = rule.id;
    evt.rule_name    = rule.name;
    evt.severity     = severityToString(rule.severity);
    evt.file_path    = file_path;
    evt.expected     = mode_to_string(rule.check_expected);
    evt.actual       = actual_mode;
    evt.process_name = proc_name;
    evt.pid          = pid;
    evt.user_name    = user_name;
    evt.uid          = uid;
    evt.timestamp    = NowString();
    evt.event_type   = actual_mode;  // read / write
    evt.action_taken = actionToString(rule.monitor_action);

    alert_mgr.SendDingTalk(evt);
}

void on_check_mismatch_detected(const Rule& rule,
                                const std::string& file_path,
                                const std::string& proc_name,
                                int pid,
                                AlertManager& alert_mgr)
{
    if (!rule.has_check || rule.check_path.empty() || rule.check_path != file_path) {
        return;
    }

    struct stat st;
    if (stat(file_path.c_str(), &st) != 0) {
        return;
    }

    const mode_t actual_mode = st.st_mode & 0777;
    const bool expected_hash = !rule.check_hash.empty();
    const bool expected_perm = rule.check_expected != 0;

    const std::string actual_hash = compute_sha256(const_cast<std::string&>(file_path));

    bool permission_match = true;
    bool hash_match = true;

    if (expected_perm) {
        permission_match = (actual_mode == rule.check_expected);
    }
    if (expected_hash) {
        hash_match = (actual_hash == rule.check_hash);
    }

    if (permission_match && hash_match) {
        return;
    }

    std::string uid;
    const std::string user_name = ResolveUserInfoByPid(pid, uid);

    std::ostringstream msg;
    msg << "check mismatch detected by monitor";
    if (!permission_match) {
        msg << " permission=" << mode_to_string(actual_mode) << " expected=" << mode_to_string(rule.check_expected);
    }
    if (!hash_match) {
        msg << " hash=" << actual_hash << " expected=" << rule.check_hash;
    }

    spdlog::warn("[monitor_check_mismatch] {} process={} pid={} user={} uid={} file={}",
                 msg.str(), proc_name, pid,
                 user_name.empty() ? "unknown" : user_name,
                 uid.empty() ? "-" : uid,
                 file_path);

    AlertEvent evt;
    evt.rule_id      = rule.id;
    evt.rule_name    = rule.name;
    evt.severity     = severityToString(rule.severity);
    evt.file_path    = file_path;
    evt.expected     = (expected_perm ? mode_to_string(rule.check_expected) : "-");
    evt.actual       = (expected_perm ? mode_to_string(actual_mode) : "-");
    evt.process_name = proc_name;
    evt.pid          = pid;
    evt.user_name    = user_name;
    evt.uid          = uid;
    evt.timestamp    = NowString();
    evt.event_type   = "check_mismatch";
    evt.action_taken = actionToString(rule.monitor_action);

    if (!rule.check_hash.empty()) {
        evt.expected += "|hash=" + rule.check_hash;
        evt.actual += "|hash=" + actual_hash;
    }

    alert_mgr.SendDingTalk(evt);
}

// ── chmod/chown 事件处理（--db 模式下）──────────────────────────────
// eBPF 拦截到 chmod/chown 后，直接用事件中的新值与基线比对
// 无需 stat 磁盘文件（LSM hook 在操作前触发，磁盘上仍是旧值）
static void handle_chmod_chown_event(const struct event *e,
                                      AlertManager& alert_mgr) {
    auto it_bl = g_inode_to_baseline.find(e->ino);
    if (it_bl == g_inode_to_baseline.end())
        return;

    const CheckEntry& baseline = it_bl->second;
    const std::string& file_path = baseline.file_path;
    std::string proc_name(reinterpret_cast<const char*>(e->comm), 16);
    // 去除尾部 \0
    auto null_pos = proc_name.find('\0');
    if (null_pos != std::string::npos) proc_name.resize(null_pos);

    if (e->event_type == EVENT_CHMOD) {
        std::string actual_perm = mode_to_string(e->new_mode & 0777);
        if (actual_perm != baseline.permission) {
            BaselineDeviation dev;
            dev.event_type = "perm_changed";
            dev.severity   = "medium";
            dev.expected   = "mode=" + baseline.permission;
            dev.actual     = "mode=" + actual_perm;
            HandleBaselineDeviation(dev, file_path, proc_name, e->pid, alert_mgr);
        }
    } else if (e->event_type == EVENT_CHOWN) {
        bool uid_diff = (static_cast<int64_t>(e->new_uid) != baseline.uid);
        bool gid_diff = (static_cast<int64_t>(e->new_gid) != baseline.gid);
        if (uid_diff || gid_diff) {
            BaselineDeviation dev;
            dev.event_type = "own_changed";
            dev.severity   = "medium";
            std::string exp_parts, act_parts;
            if (uid_diff) {
                exp_parts += "uid=" + std::to_string(baseline.uid);
                act_parts += "uid=" + std::to_string(e->new_uid);
            }
            if (gid_diff) {
                if (!exp_parts.empty()) exp_parts += ", ";
                exp_parts += "gid=" + std::to_string(baseline.gid);
                if (!act_parts.empty()) act_parts += ", ";
                act_parts += "gid=" + std::to_string(e->new_gid);
            }
            dev.expected = exp_parts;
            dev.actual   = act_parts;
            HandleBaselineDeviation(dev, file_path, proc_name, e->pid, alert_mgr);
        }
    }
}

// ── 监控上下文：聚合 AlertManager + 水位背压控制器 + 事件批量缓冲 ──
static constexpr size_t kMaxBatchSize = 1024;

struct MonitorContext {
    AlertManager*            alert_mgr    = nullptr;
    WatermarkBackpressure*   backpressure = nullptr;
    std::vector<struct event> event_batch;
    size_t                   dropped_count = 0;
};

// ── 核心事件处理逻辑（前向声明）─────────────────────────────────────
static void process_event_core(struct event* e, MonitorContext* mctx);

// ── 事件回调：将事件拷贝到批量缓冲区，由 FlushEventBatch 统一处理 ──
// ring buffer 回调签名
static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)data_sz;

    auto* mctx = static_cast<MonitorContext*>(ctx);
    auto* e    = static_cast<struct event *>(data);

    if (mctx->event_batch.size() < kMaxBatchSize) {
        mctx->event_batch.push_back(*e);
    } else {
        mctx->dropped_count++;
    }

    return 0;
}

// perf event buffer 回调签名（5.7 / 5.4 路径复用）
static void perf_event_cb(void *ctx, int cpu, void *data, __u32 size) {
    (void)cpu;
    auto* mctx = static_cast<MonitorContext*>(ctx);
    auto* e    = static_cast<struct event *>(data);

    if (size < sizeof(struct event))
        return;

    if (mctx->event_batch.size() < kMaxBatchSize) {
        mctx->event_batch.push_back(*e);
    } else {
        mctx->dropped_count++;
    }
}

// ── 核心事件处理逻辑 ────────────────────────────────────────────────
static void process_event_core(struct event* e, MonitorContext* mctx) {
    AlertManager* alert_mgr = mctx->alert_mgr;

    // ── chmod/chown/unlink 实时检测（--db 模式下，eBPF 直接拦截）────────
    if (!g_inode_to_baseline.empty() && alert_mgr != nullptr) {
        if (e->event_type == EVENT_CHMOD || e->event_type == EVENT_CHOWN) {
            handle_chmod_chown_event(e, *alert_mgr);
            return;
        }
        if (e->event_type == EVENT_UNLINK) {
            auto it_bl = g_inode_to_baseline.find(e->ino);
            if (it_bl != g_inode_to_baseline.end()) {
                const std::string& file_path = it_bl->second.file_path;
                std::string proc_name(reinterpret_cast<const char*>(e->comm), 16);
                auto null_pos = proc_name.find('\0');
                if (null_pos != std::string::npos) proc_name.resize(null_pos);
                BaselineDeviation dev;
                dev.event_type = "missing";
                dev.severity   = "high";
                dev.expected   = "file exists";
                dev.actual     = "file deleted (unlink detected by eBPF)";
                HandleBaselineDeviation(dev, file_path, proc_name, e->pid, *alert_mgr);
            }
            return;
        }
    }

    // ── 原有 YAML 规则匹配逻辑（不变）──────────────────────────────
    auto it_rule = g_inode_to_rule.find(e->ino);
    if (it_rule != g_inode_to_rule.end()) {
        const Rule &rule = it_rule->second;

        auto it_path = g_inode_to_path.find(e->ino);
        if (it_path != g_inode_to_path.end()) {
            const std::string &path = it_path->second;

            const std::string actual_event = ((e->mask & EVENT_READ) != 0) ? "read" : "write";
            if (alert_mgr != nullptr) {
                on_violation_detected(rule, path, actual_event, e->comm, e->pid, *alert_mgr);
            }

            if (alert_mgr != nullptr && (e->mask & EVENT_WRITE) != 0) {
                on_check_mismatch_detected(rule, path, e->comm, e->pid, *alert_mgr);
            }
        }

        auto it_hash = g_inode_to_hash.find(e->ino);
        if (it_hash != g_inode_to_hash.end()) {
            const std::string &expected_hash = it_hash->second;
            std::string current_hash = compute_sha256(it_path->second);

            if (current_hash != expected_hash) {
                std::ostringstream oss;
                oss << "[" << actionToString(static_cast<Action>(e->action)) << "] File modified! hash mismatch\n"
                    << "  path: " << it_path->second << "\n"
                    << "  pid: " << e->pid << "\n"
                    << "  comm: " << e->comm << "\n"
                    << "  expected_hash: " << expected_hash << "\n"
                    << "  current_hash:  " << current_hash << std::endl;
                spdlog::warn(oss.str());
            }
        } else {
            std::ostringstream oss;
            oss << "[" << actionToString(static_cast<Action>(e->action)) << "] File access detected (no hash baseline)\n"
                << "  path: " << (it_path != g_inode_to_path.end() ? it_path->second : "unknown") << "\n"
                << "  pid: " << e->pid << "\n"
                << "  comm: " << e->comm << std::endl;
            spdlog::warn(oss.str());
            spdlog::default_logger()->flush();
        }
    }

    // ── 基线实时比对（--db 模式下）────────────────────────────────
    if (!g_inode_to_baseline.empty() && alert_mgr != nullptr) {
        auto it_bl = g_inode_to_baseline.find(e->ino);
        if (it_bl != g_inode_to_baseline.end()) {
            const CheckEntry& baseline = it_bl->second;
            // 使用基线中存储的完整路径（不跟随 symlink）
            const std::string& full_path = baseline.file_path;

            std::vector<BaselineDeviation> devs = CompareWithBaseline(baseline, full_path);
            for (const auto& dev : devs) {
                HandleBaselineDeviation(dev, full_path, e->comm, e->pid, *alert_mgr);
            }
        }
    }
}

// ── 批量处理：遍历缓冲区中的所有事件，逐条调用核心处理逻辑 ────────
static void FlushEventBatch(MonitorContext* mctx) {
    for (auto& e : mctx->event_batch) {
        process_event_core(&e, mctx);
    }
    mctx->event_batch.clear();
}

// ── 公共初始化：写入规则到 eBPF map + 基线加载 ─────────────────
static int common_monitor_init(int fd_actions,
                               const Config& config,
                               const std::string& baseline_db_path,
                               bool skip_boot_check,
                               AlertManager& alert_mgr,
                               BaselineDB*& baseline_db_out) {
    // 写入 monitor_actions：同时传递动作、事件掩码和严重等级
    for (const auto &rule : config.rules) {
        if (!rule.has_monitor)
            continue;
        if (rule.monitor_path.empty() || rule.ino == 0)
            continue;

        unsigned long key = rule.ino;
        struct monitor_rule value{};
        value.action = (rule.monitor_action == Action::BLOCK) ? ACTION_BLOCK : ACTION_ALERT;
        value.events_mask = 0;
        if (rule.monitor_read)
            value.events_mask |= EVENT_READ;
        if (rule.monitor_write)
            value.events_mask |= EVENT_WRITE;
        if (rule.monitor_delete)
            value.events_mask |= EVENT_MASK_BIT(EVENT_UNLINK);
        value.severity = rule.severity;

        bpf_map_update_elem(fd_actions, &key, &value, BPF_ANY);
    }

    init_inode_maps(config);

    // ── 基线实时监控初始化（仅当 --db 模式下）────────────────
    baseline_db_out = nullptr;
    if (!baseline_db_path.empty()) {
        try {
            baseline_db_out = new BaselineDB(baseline_db_path);

            g_inode_to_baseline.clear();
            auto entries = baseline_db_out->GetAllBaselineEntries();
            for (auto& e : entries) {
                struct stat st;
                if (lstat(e.file_path.c_str(), &st) == 0 && st.st_ino != 0) {
                    g_inode_to_baseline[st.st_ino] = e;
                }
            }
            spdlog::info("[baseline_monitor] loaded {} baseline entries from {}",
                         g_inode_to_baseline.size(), baseline_db_path);

            int baseline_registered = 0;
            for (const auto& [ino, entry] : g_inode_to_baseline) {
                if (g_inode_to_rule.find(ino) == g_inode_to_rule.end()) {
                    struct monitor_rule value{};
                    value.action = ACTION_ALERT;
                    value.events_mask = EVENT_READ | EVENT_WRITE;
                    value.severity = SEVERITY_HIGH;
                    if (bpf_map_update_elem(fd_actions, &ino, &value, BPF_NOEXIST) == 0) {
                        ++baseline_registered;
                    }
                }
            }
            spdlog::info("[baseline_monitor] registered {} baseline inodes to eBPF map",
                         baseline_registered);

            if (!skip_boot_check) {
                int boot_devs = 0;
                for (const auto& [ino, entry] : g_inode_to_baseline) {
                    std::vector<BaselineDeviation> devs = CompareWithBaseline(entry, entry.file_path);
                    for (const auto& dev : devs) {
                        HandleBaselineDeviation(dev, entry.file_path, "-", 0, alert_mgr);
                        ++boot_devs;
                    }
                }
                spdlog::info("[baseline_boot_check] completed, {} deviations found", boot_devs);
            } else {
                spdlog::info("[baseline_boot_check] skipped (--skip-boot-baseline-check)");
            }
        } catch (const std::exception& ex) {
            spdlog::error("[baseline_monitor] failed to open baseline DB: {}", ex.what());
            delete baseline_db_out;
            baseline_db_out = nullptr;
            g_inode_to_baseline.clear();
        }
    }
    return 0;
}

// ── 公共监控循环（perf buffer 路径，5.7 和 5.4 共用）──────────
static int run_perf_buffer_loop(struct perf_buffer *pb,
                                MonitorContext& mctx,
                                AlertManager& alert_mgr) {
    int count = 0;
    const int RETENTION_INTERVAL = 36000;

    while (running) {
        count++;
        int err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            spdlog::error("[bpf_program_error] Error polling perf buffer: {}", err);
            break;
        }

        FlushEventBatch(&mctx);

        if (count % RETENTION_INTERVAL == 0) {
            int deleted = alert_mgr.RunRetention();
            (void)deleted;
        }
    }

    FlushEventBatch(&mctx);

    if (mctx.dropped_count > 0) {
        spdlog::warn("[batch] {} events dropped (batch overflow, max_batch_size={})",
                     mctx.dropped_count, kMaxBatchSize);
    }
    return 0;
}

// ══════════════════════════════════════════════════════════════════
// 路径 A：内核 5.8+ — BPF LSM + ring buffer
// ══════════════════════════════════════════════════════════════════
static int do_monitor_ringbuf(const Config& config, AlertManager &alert_mgr,
                              const std::string& baseline_db_path, bool skip_boot_check) {
    struct lsm_file_bpf *skel;
    int err;

    skel = lsm_file_bpf__open();
    if (!skel) {
        spdlog::error("[bpf_program_error] Failed to open BPF skeleton");
        return 1;
    }

    // 兼容内核 5.8：mmap_file LSM hook 在 5.9 才引入
    if (skel->progs.file_mmap_hook && !kernel_at_least(5, 9)) {
        bpf_program__set_autoload(skel->progs.file_mmap_hook, false);
        auto kv = get_kernel_version();
        spdlog::info("[bpf_compat] mmap_file hook disabled (kernel {}.{}, requires 5.9+)",
                     kv.major, kv.minor);
    }

    err = lsm_file_bpf__load(skel);
    if (err) {
        spdlog::error("[bpf_program_error] Failed to load BPF skeleton: {}", err);
        lsm_file_bpf__destroy(skel);
        return 1;
    }

    err = lsm_file_bpf__attach(skel);
    if (err) {
        spdlog::error("[bpf_program_error] Failed to attach BPF program: {}", err);
        lsm_file_bpf__destroy(skel);
        return 1;
    }
    spdlog::info("[bpf_program_loaded] BPF LSM (ring buffer) attached, kernel 5.8+, {} rules",
                 config.rules.size());

    // Pin maps
    (void)mkdir("/sys/fs/bpf/baseline-guard", 0755);
    bpf_map__pin(skel->maps.drop_stats, "/sys/fs/bpf/baseline-guard/drop_stats");
    bpf_map__pin(skel->maps.watermark_level, "/sys/fs/bpf/baseline-guard/watermark_level");

    int fd_actions   = bpf_map__fd(skel->maps.monitor_actions);
    int fd_watermark = bpf_map__fd(skel->maps.watermark_level);

    BaselineDB* baseline_db = nullptr;
    common_monitor_init(fd_actions, config, baseline_db_path, skip_boot_check, alert_mgr, baseline_db);

    // 水位背压控制器
    WatermarkBackpressure backpressure;
    MonitorContext mctx;
    mctx.alert_mgr    = &alert_mgr;
    mctx.backpressure = &backpressure;

    spdlog::info("Monitoring started (ring buffer mode). Press Ctrl+C to stop.");

    struct ring_buffer *rb =
        ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, &mctx, nullptr);
    if (!rb) {
        spdlog::error("[bpf_program_error] Failed to create ring buffer");
        if (baseline_db) delete baseline_db;
        lsm_file_bpf__destroy(skel);
        return 1;
    }

    backpressure.SetRingBuffer(rb);
    backpressure.SetNumCPUs(libbpf_num_possible_cpus());

    int count = 0;
    const int RETENTION_INTERVAL = 36000;
    const int WATERMARK_INTERVAL = 100;
    while (running) {
        count++;
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            spdlog::error("[bpf_program_error] Error polling ring buffer: {}", err);
            break;
        }
        FlushEventBatch(&mctx);

        if (count % WATERMARK_INTERVAL == 0) {
            backpressure.UpdateUtilization();
            __u32 wm_key   = 0;
            __u32 wm_value = static_cast<__u32>(backpressure.GetWatermarkLevel());
            bpf_map_update_elem(fd_watermark, &wm_key, &wm_value, BPF_ANY);
        }
        if (count % RETENTION_INTERVAL == 0) {
            int deleted = alert_mgr.RunRetention();
            (void)deleted;
        }
    }

    FlushEventBatch(&mctx);
    spdlog::info("[watermark] final utilization={:.1f}% level={}",
                 backpressure.GetUtilization(),
                 WatermarkBackpressure::LevelToString(backpressure.GetWatermarkLevel()));

    if (mctx.dropped_count > 0) {
        spdlog::warn("[batch] {} events dropped (batch overflow, max_batch_size={})",
                     mctx.dropped_count, kMaxBatchSize);
    }

    spdlog::info("[service_stop] monitoring loop exited");
    spdlog::info("Monitoring stopped.");
    ring_buffer__free(rb);

    bpf_map__unpin(skel->maps.drop_stats, "/sys/fs/bpf/baseline-guard/drop_stats");
    bpf_map__unpin(skel->maps.watermark_level, "/sys/fs/bpf/baseline-guard/watermark_level");
    lsm_file_bpf__destroy(skel);

    if (baseline_db) {
        delete baseline_db;
        g_inode_to_baseline.clear();
    }
    return 0;
}

// ══════════════════════════════════════════════════════════════════
// 路径 B：内核 5.7 — BPF LSM + perf event buffer
// ══════════════════════════════════════════════════════════════════
static int do_monitor_perf(const Config& config, AlertManager &alert_mgr,
                           const std::string& baseline_db_path, bool skip_boot_check) {
    struct lsm_file_perf_bpf *skel;
    int err;

    skel = lsm_file_perf_bpf__open();
    if (!skel) {
        spdlog::error("[bpf_program_error] Failed to open perf BPF skeleton");
        return 1;
    }

    // mmap_file hook 在 5.9 才引入
    if (skel->progs.file_mmap_hook && !kernel_at_least(5, 9)) {
        bpf_program__set_autoload(skel->progs.file_mmap_hook, false);
        spdlog::info("[bpf_compat] mmap_file hook disabled (kernel requires 5.9+)");
    }

    err = lsm_file_perf_bpf__load(skel);
    if (err) {
        spdlog::error("[bpf_program_error] Failed to load perf BPF skeleton: {}", err);
        lsm_file_perf_bpf__destroy(skel);
        return 1;
    }

    err = lsm_file_perf_bpf__attach(skel);
    if (err) {
        spdlog::error("[bpf_program_error] Failed to attach perf BPF program: {}", err);
        lsm_file_perf_bpf__destroy(skel);
        return 1;
    }
    spdlog::info("[bpf_program_loaded] BPF LSM (perf buffer) attached, kernel 5.7, {} rules",
                 config.rules.size());

    // Pin drop_stats
    (void)mkdir("/sys/fs/bpf/baseline-guard", 0755);
    bpf_map__pin(skel->maps.drop_stats, "/sys/fs/bpf/baseline-guard/drop_stats");

    int fd_actions = bpf_map__fd(skel->maps.monitor_actions);

    BaselineDB* baseline_db = nullptr;
    common_monitor_init(fd_actions, config, baseline_db_path, skip_boot_check, alert_mgr, baseline_db);

    // 无水位背压（perf buffer 无利用率查询）
    MonitorContext mctx;
    mctx.alert_mgr = &alert_mgr;

    spdlog::info("Monitoring started (perf buffer mode). Press Ctrl+C to stop.");

    struct perf_buffer *pb =
        perf_buffer__new(bpf_map__fd(skel->maps.events), 64,
                         perf_event_cb, nullptr, &mctx, nullptr);
    if (!pb) {
        spdlog::error("[bpf_program_error] Failed to create perf buffer");
        if (baseline_db) delete baseline_db;
        lsm_file_perf_bpf__destroy(skel);
        return 1;
    }

    run_perf_buffer_loop(pb, mctx, alert_mgr);

    spdlog::info("[service_stop] monitoring loop exited");
    spdlog::info("Monitoring stopped.");
    perf_buffer__free(pb);

    bpf_map__unpin(skel->maps.drop_stats, "/sys/fs/bpf/baseline-guard/drop_stats");
    lsm_file_perf_bpf__destroy(skel);

    if (baseline_db) {
        delete baseline_db;
        g_inode_to_baseline.clear();
    }
    return 0;
}

// ══════════════════════════════════════════════════════════════════
// 路径 C：内核 5.4 — kprobe + perf event buffer（仅告警，无法阻止）
// ══════════════════════════════════════════════════════════════════
static int do_monitor_kprobe(const Config& config, AlertManager &alert_mgr,
                             const std::string& baseline_db_path, bool skip_boot_check) {
    struct lsm_kprobe_bpf *skel;
    int err;

    spdlog::warn("[bpf_compat] kernel < 5.7, using kprobe mode — BLOCK actions degraded to ALERT only");

    skel = lsm_kprobe_bpf__open();
    if (!skel) {
        spdlog::error("[bpf_program_error] Failed to open kprobe BPF skeleton");
        return 1;
    }

    err = lsm_kprobe_bpf__load(skel);
    if (err) {
        spdlog::error("[bpf_program_error] Failed to load kprobe BPF skeleton: {}", err);
        lsm_kprobe_bpf__destroy(skel);
        return 1;
    }

    // 手动 attach kprobe 程序到内核函数
    struct bpf_link *link_perm   = bpf_program__attach_kprobe(skel->progs.kprobe_file_permission, false, "security_file_permission");
    struct bpf_link *link_chmod  = bpf_program__attach_kprobe(skel->progs.kprobe_path_chmod,     false, "security_path_chmod");
    struct bpf_link *link_chown  = bpf_program__attach_kprobe(skel->progs.kprobe_path_chown,     false, "security_path_chown");
    struct bpf_link *link_unlink = bpf_program__attach_kprobe(skel->progs.kprobe_inode_unlink,   false, "security_inode_unlink");
    struct bpf_link *link_rename = bpf_program__attach_kprobe(skel->progs.kprobe_inode_rename,   false, "security_inode_rename");

    if (!link_perm || !link_chmod || !link_chown || !link_unlink || !link_rename) {
        spdlog::error("[bpf_program_error] Failed to attach one or more kprobes");
        if (link_perm)   bpf_link__destroy(link_perm);
        if (link_chmod)  bpf_link__destroy(link_chmod);
        if (link_chown)  bpf_link__destroy(link_chown);
        if (link_unlink) bpf_link__destroy(link_unlink);
        if (link_rename) bpf_link__destroy(link_rename);
        lsm_kprobe_bpf__destroy(skel);
        return 1;
    }
    spdlog::info("[bpf_program_loaded] kprobe programs attached (5 kprobes), {} rules",
                 config.rules.size());

    // Pin drop_stats
    (void)mkdir("/sys/fs/bpf/baseline-guard", 0755);
    bpf_map__pin(skel->maps.drop_stats, "/sys/fs/bpf/baseline-guard/drop_stats");

    int fd_actions = bpf_map__fd(skel->maps.monitor_actions);

    BaselineDB* baseline_db = nullptr;
    common_monitor_init(fd_actions, config, baseline_db_path, skip_boot_check, alert_mgr, baseline_db);

    MonitorContext mctx;
    mctx.alert_mgr = &alert_mgr;

    spdlog::info("Monitoring started (kprobe mode, alert-only). Press Ctrl+C to stop.");

    struct perf_buffer *pb =
        perf_buffer__new(bpf_map__fd(skel->maps.events), 64,
                         perf_event_cb, nullptr, &mctx, nullptr);
    if (!pb) {
        spdlog::error("[bpf_program_error] Failed to create perf buffer for kprobe");
        if (baseline_db) delete baseline_db;
        bpf_link__destroy(link_perm);
        bpf_link__destroy(link_chmod);
        bpf_link__destroy(link_chown);
        bpf_link__destroy(link_unlink);
        bpf_link__destroy(link_rename);
        lsm_kprobe_bpf__destroy(skel);
        return 1;
    }

    run_perf_buffer_loop(pb, mctx, alert_mgr);

    spdlog::info("[service_stop] monitoring loop exited");
    spdlog::info("Monitoring stopped.");
    perf_buffer__free(pb);

    bpf_map__unpin(skel->maps.drop_stats, "/sys/fs/bpf/baseline-guard/drop_stats");
    bpf_link__destroy(link_perm);
    bpf_link__destroy(link_chmod);
    bpf_link__destroy(link_chown);
    bpf_link__destroy(link_unlink);
    bpf_link__destroy(link_rename);
    lsm_kprobe_bpf__destroy(skel);

    if (baseline_db) {
        delete baseline_db;
        g_inode_to_baseline.clear();
    }
    return 0;
}

// ── 入口函数：根据内核版本分派到不同路径 ────────────────────────
int do_monitor(const Config& config, AlertManager &alert_mgr,
               const std::string& baseline_db_path, bool skip_boot_check) {

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    auto kv = get_kernel_version();
    spdlog::info("[kernel_detect] detected kernel {}.{}", kv.major, kv.minor);

    if (kv.major > 5 || (kv.major == 5 && kv.minor >= 8)) {
        // 5.8+: BPF LSM + ring buffer（完整功能）
        return do_monitor_ringbuf(config, alert_mgr, baseline_db_path, skip_boot_check);
    } else if (kv.major == 5 && kv.minor >= 7) {
        // 5.7: BPF LSM + perf event buffer（支持 block）
        return do_monitor_perf(config, alert_mgr, baseline_db_path, skip_boot_check);
    } else if (kv.major == 5 && kv.minor >= 4) {
        // 5.4~5.6: kprobe + perf event buffer（仅告警）
        return do_monitor_kprobe(config, alert_mgr, baseline_db_path, skip_boot_check);
    } else {
        spdlog::error("[kernel_unsupported] kernel {}.{} not supported, minimum is 5.4",
                     kv.major, kv.minor);
        return 1;
    }
}
