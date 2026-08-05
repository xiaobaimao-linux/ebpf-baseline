#include "monitor.hpp"
#include "../bpf/event.h"
#include "utils.hpp"
#include "config.hpp"


#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <csignal>
#include <cstring>
#include <iostream>
#include <linux/types.h>
#include <spdlog/spdlog.h>
#include <unordered_map>

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
std::unordered_map<unsigned long, std::string> g_inode_to_path;
std::unordered_map<unsigned long, std::string> g_inode_to_hash;

// 初始化映射
void init_inode_maps(const Config &config) {
    for (const auto &rule : config.rules) {
        if (!rule.has_monitor)
            continue;
        if (rule.monitor_path.empty())
            continue;
        if (rule.ino == 0)
            continue;
        g_inode_to_path[rule.ino] = rule.monitor_path;
        if (!rule.check_hash.empty()) {
            g_inode_to_hash[rule.ino] = rule.check_hash;
        }
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    std::cout <<"-------------------------------------------"<<endl;
    auto *e = static_cast<struct event *>(data);

    auto it_path = g_inode_to_path.find(e->ino);
    if (it_path == g_inode_to_path.end()) {
        return 0;
    }
    const std::string &path = it_path->second;

    auto it_hash = g_inode_to_hash.find(e->ino);
    if (it_hash == g_inode_to_hash.end()) {
        std::cout << "["<< actionToString(static_cast<Action>(e->action)) <<"] File access detected (no hash baseline)\n"
                  << "  path: " << path << "\n"
                  << "  pid: " << e->pid << "\n"
                  << "  comm: " << e->comm << std::endl;
        return 0;
    }
    const std::string &expected_hash = it_hash->second;
    std::string current_hash = compute_sha256(path);

    if (current_hash != expected_hash) {
        std::cout << "["<< e->action <<"] File modified! hash mismatch\n"
                  << "  path: " << path << "\n"
                  << "  pid: " << e->pid << "\n"
                  << "  comm: " << e->comm << "\n"
                  << "  expected_hash: " << expected_hash << "\n"
                  << "  current_hash:  " << current_hash << std::endl;
    }

    return 0;
}

int do_monitor(const Config &config) {
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

    std::cout << "Monitoring started. Press Ctrl+C to stop." << std::endl;

    struct ring_buffer *rb =
        ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, nullptr, nullptr);

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
    std::cout << "Monitoring stopped." << std::endl;
    ring_buffer__free(rb);
    lsm_file_bpf__destroy(skel);
    return 0;
}