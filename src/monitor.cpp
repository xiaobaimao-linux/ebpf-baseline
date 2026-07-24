#include "monitor.hpp"
#include "../bpf/event.h"
#include "utils.hpp"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <csignal>
#include <cstring>
#include <iostream>
#include <linux/types.h>

// 包含生成的skeleton头文件
#include "../bpf/lsm_file.skel.h"

static volatile bool running = true;

void signal_handler(int) {
    running = false;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    auto *e = static_cast<struct event *>(data);
    std::cout << "[ALERT] pid=" << e->pid << " comm=" << e->comm << " path=" << e->path
              << " mask=" << e->mask << std::endl;
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

    // 将配置文件中的路径写入 BPF map
    for (const auto &rule : config.rules) {
        uint8_t val = 1;
        bpf_map__update_elem(skel->maps.monitor_inodes, &rule.ino, sizeof(rule.ino), &val,
                             sizeof(val), BPF_ANY);
    }

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