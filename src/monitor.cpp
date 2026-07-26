#include "monitor.hpp"
#include "../bpf/event.h"
#include "utils.hpp"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <csignal>
#include <cstring>
#include <iostream>
#include <linux/types.h>
#include <unordered_map>

// 包含生成的skeleton头文件
#include "../bpf/lsm_file.skel.h"

static volatile bool running = true;

void signal_handler(int) {
    running = false;
}

// 全局映射（或封装到类）
std::unordered_map<unsigned long, std::string> g_inode_to_path;
std::unordered_map<unsigned long, std::string> g_inode_to_hash;

// 初始化映射
void init_inode_maps(const Config &config) {
    for (const auto &rule : config.rules) {
        if (rule.ino == 0)
            continue;
        g_inode_to_path[rule.ino] = rule.path;
        if (!rule.hash.empty()) {
            g_inode_to_hash[rule.ino] = rule.hash;
        }
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    auto *e = static_cast<struct event *>(data);

    // 只处理写入事件（MAY_WRITE = 2）
    if (!(e->mask & 2)) {
        return 0;
    }

    // 查找路径
    auto it_path = g_inode_to_path.find(e->ino);
    if (it_path == g_inode_to_path.end()) {
        return 0;
    }
    const std::string &path = it_path->second;

    // 查找期望 hash
    auto it_hash = g_inode_to_hash.find(e->ino);
    if (it_hash == g_inode_to_hash.end()) {
        // 无 hash 配置，只告警写入
        std::cout << "[ALERT] File write detected (no hash baseline)\n"
                  << "  path: " << path << "\n"
                  << "  pid: " << e->pid << "\n"
                  << "  comm: " << e->comm << std::endl;
        return 0;
    }
    const std::string &expected_hash = it_hash->second;

    // 计算当前 hash
    std::string current_hash = compute_sha256(path);

    // 比对
    if (current_hash != expected_hash) {
        std::cout << "[ALERT] File modified! hash mismatch\n"
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
        std::cerr << "Failed to open and load BPF skeleton" << std::endl;
        return 1;
    }

    err = lsm_file_bpf__attach(skel);
    if (err) {
        std::cerr << "Failed to attach BPF program: " << err << std::endl;
        lsm_file_bpf__destroy(skel);
        return 1;
    }
    int fd_actions = bpf_map__fd(skel->maps.monitor_actions);

    // 只写入 monitor_actions
    for (const auto &rule : config.rules) {
        if (rule.ino == 0)
            continue;

        unsigned long key = rule.ino;
        unsigned char action = (rule.action == Action::BLOCK) ? ACTION_BLOCK : ACTION_ALERT;

        bpf_map_update_elem(fd_actions, &key, &action, BPF_ANY);
    }

    // 初始化 inode 映射
    init_inode_maps(config);

    std::cout << "Monitoring started. Press Ctrl+C to stop." << std::endl;

    struct ring_buffer *rb =
        ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, nullptr, nullptr);

    if (!rb) {
        std::cerr << "Failed to create ring buffer " << std::endl;
        lsm_file_bpf__destroy(skel);
        return 1;
    }

    int count = 0;
    while (running) {
        count++;
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            std::cerr << "Error polling ring buffer: " << err << std::endl;
            break;
        }
    }

    std::cout << "Monitoring stopped." << std::endl;
    ring_buffer__free(rb);
    lsm_file_bpf__destroy(skel);
    return 0;
}