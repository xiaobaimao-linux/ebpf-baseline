#include "monitor.hpp"
#include "../bpf/event.h"
#include "utils.hpp"
#include "config.hpp"
#include "commonfun.hpp"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <csignal>
#include <cstring>
#include <iostream>
#include <linux/types.h>
#include <spdlog/spdlog.h>
#include <unordered_map>
#include <sstream>

// 包含生成的skeleton头文件
#include "../bpf/lsm_file.skel.h"

static volatile bool running = true;

void signal_handler(int sig) {
    running = false;
    if (sig == SIGTERM) {
        spdlog::info("[service_stop] received SIGTERM, shutting down gracefully");
    }
}

// 全局映射（或封装到类）
std::unordered_map<unsigned long, Rule> g_inode_to_rule;
std::unordered_map<unsigned long, std::string> g_inode_to_path;
std::unordered_map<unsigned long, std::string> g_inode_to_hash;

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
                           AlertManager& alert_mgr,
                           BaselineDB& db)
{
    // 1. 写日志
    spdlog::warn("VIOLATION: {} mode {} -> {} by {}/{}",
                 file_path, mode_to_string(rule.check_expected), actual_mode, proc_name, pid);

    // 2. 发钉钉（可能因节流被跳过）
    bool dingtalk_sent = false;
    if (alert_mgr.IsEnabled()) {
        AlertEvent evt;
        evt.rule_id = rule.id;
        evt.rule_name = rule.name;
        evt.severity = rule.severity;
        evt.file_path = file_path;
        evt.expected = mode_to_string(rule.check_expected);
        evt.actual = actual_mode;
        evt.process_name = proc_name;
        evt.pid = pid;
        evt.timestamp = NowString();

        dingtalk_sent = alert_mgr.SendDingTalk(evt);
    }

    // 3. 落库到 SQLite（无论是否发钉钉都记录，便于后期复查）
    AlertRecord record;
    record.rule_id      = rule.id;
    record.rule_name    = rule.name;
    record.severity     = rule.severity;
    record.file_path    = file_path;
    record.event_type   = actual_mode;   // monitor 场景里 actual_mode 是 "read" 或 "write"
    record.process_name = proc_name;
    record.pid          = pid;
    record.expected     = mode_to_string(rule.check_expected);
    record.actual       = actual_mode;
    record.action_taken = actionToString(rule.monitor_action);
    record.dingtalk_sent = dingtalk_sent;
    record.recorded_at  = NowString();

    db.SaveAlert(record);
}


static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)data_sz;

    // ctx 现在包含 alert_mgr 和 db 的指针
    struct MonitorCtx {
        AlertManager* alert_mgr;
        BaselineDB* db;
    };

    auto* ctx_wrapper = static_cast<MonitorCtx*>(ctx);
    auto* e = static_cast<struct event *>(data);

    auto it_rule = g_inode_to_rule.find(e->ino);
    if (it_rule == g_inode_to_rule.end()) {
        return 0;
    }
    const Rule &rule = it_rule->second;

    auto it_path = g_inode_to_path.find(e->ino);
    if (it_path == g_inode_to_path.end()) {
        return 0;
    }
    const std::string &path = it_path->second;

    const std::string actual_event = ((e->mask & EVENT_READ) != 0) ? "read" : "write";
    if (ctx_wrapper != nullptr && ctx_wrapper->alert_mgr != nullptr && ctx_wrapper->db != nullptr) {
        on_violation_detected(rule, path, actual_event, e->comm, e->pid,
                              *ctx_wrapper->alert_mgr, *ctx_wrapper->db);
    }

    auto it_hash = g_inode_to_hash.find(e->ino);
    if (it_hash == g_inode_to_hash.end()) {
        std::ostringstream oss;
        oss << "[" << actionToString(static_cast<Action>(e->action)) << "] File access detected (no hash baseline)\n"
            << "  path: " << path << "\n"
            << "  pid: " << e->pid << "\n"
            << "  comm: " << e->comm << std::endl;
        spdlog::warn(oss.str());
        spdlog::default_logger()->flush();
        return 0;
    }

    const std::string &expected_hash = it_hash->second;
    std::string current_hash = compute_sha256(path);

    if (current_hash != expected_hash) {
        std::ostringstream oss;
        oss << "[" << actionToString(static_cast<Action>(e->action)) << "] File modified! hash mismatch\n"
            << "  path: " << path << "\n"
            << "  pid: " << e->pid << "\n"
            << "  comm: " << e->comm << "\n"
            << "  expected_hash: " << expected_hash << "\n"
            << "  current_hash:  " << current_hash << std::endl;
        spdlog::warn(oss.str());
    }

    return 0;
}

int do_monitor(const Config& config, AlertManager &alert_mgr, BaselineDB& db) {
    struct lsm_file_bpf *skel;
    int err;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    skel = lsm_file_bpf__open_and_load();
    if (!skel) {
        spdlog::error("[bpf_program_error] Failed to open and load BPF skeleton");
        return 1;
    }
    spdlog::info("[bpf_program_loaded] BPF skeleton opened and loaded successfully");

    err = lsm_file_bpf__attach(skel);
    if (err) {
        spdlog::error("[bpf_program_error] Failed to attach BPF program: {}", err);
        lsm_file_bpf__destroy(skel);
        return 1;
    }
    spdlog::info("[bpf_program_loaded] BPF LSM program attached successfully, monitoring {} rules", config.rules.size());

    int fd_actions = bpf_map__fd(skel->maps.monitor_actions);

    // 只写入 monitor_actions：同时传递动作和事件掩码
    for (const auto &rule : config.rules) {
        if (!rule.has_monitor)
            continue;
        if (rule.monitor_path.empty() || rule.ino == 0)
            continue;

        unsigned long key = rule.ino;
        struct monitor_rule value{};
        value.action = (rule.monitor_action == Action::BLOCK) ? ACTION_BLOCK : ACTION_ALERT;
        value.events_mask = 0;
        if (rule.monitor_read) {
            value.events_mask |= EVENT_READ;
        }
        if (rule.monitor_write) {
            value.events_mask |= EVENT_WRITE;
        }

        bpf_map_update_elem(fd_actions, &key, &value, BPF_ANY);
    }

    // 初始化 inode 映射
    init_inode_maps(config);

    spdlog::info("Monitoring started. Press Ctrl+C to stop.");

    // 包装上下文，同时传递 alert_mgr 和 db
    struct MonitorCtx {
        AlertManager* alert_mgr;
        BaselineDB* db;
    } ctx_wrapper = { &alert_mgr, &db };

    struct ring_buffer *rb =
        ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, &ctx_wrapper, nullptr);

    if (!rb) {
        spdlog::error("[bpf_program_error] Failed to create ring buffer");
        lsm_file_bpf__destroy(skel);
        return 1;
    }

    int count = 0;
    while (running) {
        count++;
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            spdlog::error("[bpf_program_error] Error polling ring buffer: {}", err);
            break;
        }
    }

    spdlog::info("[service_stop] monitoring loop exited");
    spdlog::info("Monitoring stopped.");
    ring_buffer__free(rb);
    lsm_file_bpf__destroy(skel);
    return 0;
}