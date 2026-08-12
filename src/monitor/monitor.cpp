#include "monitor.hpp"
#include "../bpf/event.h"
#include "utils.hpp"
#include "config.hpp"
#include "commonfun.hpp"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <csignal>
#include <cstring>
#include <fstream>
#include <iostream>
#include <linux/types.h>
#include <pwd.h>
#include <spdlog/spdlog.h>
#include <sys/types.h>
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
    evt.severity     = rule.severity;
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
    evt.severity     = rule.severity;
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

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)data_sz;

    auto* alert_mgr = static_cast<AlertManager*>(ctx);
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
    if (alert_mgr != nullptr) {
        on_violation_detected(rule, path, actual_event, e->comm, e->pid, *alert_mgr);
    }

    if (alert_mgr != nullptr && (e->mask & EVENT_WRITE) != 0) {
        on_check_mismatch_detected(rule, path, e->comm, e->pid, *alert_mgr);
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

int do_monitor(const Config& config, AlertManager &alert_mgr) {
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

    struct ring_buffer *rb =
        ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, &alert_mgr, nullptr);

    if (!rb) {
        spdlog::error("[bpf_program_error] Failed to create ring buffer");
        lsm_file_bpf__destroy(skel);
        return 1;
    }

    int count = 0;
    // 每1小时(约36000次poll)触发一次保留策略清理
    const int RETENTION_INTERVAL = 36000;  // 100ms * 36000 = 3600s = 1h
    while (running) {
        count++;
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            spdlog::error("[bpf_program_error] Error polling ring buffer: {}", err);
            break;
        }

        // 定期执行保留策略清理
        if (count % RETENTION_INTERVAL == 0) {
            int deleted = alert_mgr.RunRetention();
            (void)deleted;  // 避免unused警告
        }
    }

    spdlog::info("[service_stop] monitoring loop exited");
    spdlog::info("Monitoring stopped.");
    ring_buffer__free(rb);
    lsm_file_bpf__destroy(skel);
    return 0;
}