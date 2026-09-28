#include "stats.hpp"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <set>
#include <string>
#include <unistd.h>
#include <vector>

// drop_stats map 的 pinned 路径（与 monitor.cpp 保持一致）
static const char* kDropStatsPinPath = "/sys/fs/bpf/baseline-guard/drop_stats";

static int GetNumPossibleCPUs() {
    // 优先从 sysfs 读取准确值
    std::ifstream f("/sys/devices/system/cpu/possible");
    if (f.is_open()) {
        std::string line;
        std::getline(f, line);
        // 格式: "0-N" 表示 N+1 个 CPU
        auto dash = line.find('-');
        if (dash != std::string::npos) {
            int max_cpu = std::stoi(line.substr(dash + 1));
            return max_cpu + 1;
        }
    }
    // 回退: 使用 libbpf 辅助函数
    return libbpf_num_possible_cpus();
}

// 解析 CPU 列表字符串（如 "0-3,5,7"）为 CPU ID 集合
static std::set<int> ParseCPUList(const std::string& s) {
    std::set<int> cpus;
    size_t pos = 0;
    while (pos < s.size()) {
        size_t comma = s.find(',', pos);
        std::string token = s.substr(pos, comma - pos);
        auto dash = token.find('-');
        if (dash != std::string::npos) {
            int start = std::stoi(token.substr(0, dash));
            int end = std::stoi(token.substr(dash + 1));
            for (int i = start; i <= end; ++i) {
                cpus.insert(i);
            }
        } else if (!token.empty()) {
            cpus.insert(std::stoi(token));
        }
        if (comma == std::string::npos) break;
        pos = comma + 1;
    }
    return cpus;
}

// 获取当前在线 CPU ID 集合
static std::set<int> GetOnlineCPUs() {
    std::ifstream f("/sys/devices/system/cpu/online");
    if (f.is_open()) {
        std::string line;
        std::getline(f, line);
        return ParseCPUList(line);
    }
    // 回退: 假设所有 CPU 都在线
    std::set<int> all;
    int ncpus = GetNumPossibleCPUs();
    for (int i = 0; i < ncpus; ++i) all.insert(i);
    return all;
}

static void PrintUsage() {
    printf("Usage: baseline-guard stats [options]\n");
    printf("Options:\n");
    printf("  --drop        show ring buffer drop statistics from eBPF map\n");
    printf("  -h, --help    display this message\n");
}

int RunStats(int argc, char* argv[]) {
    if (argc == 0) {
        PrintUsage();
        return 1;
    }

    bool show_drop = false;

    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--drop") {
            show_drop = true;
        } else if (arg == "-h" || arg == "--help") {
            PrintUsage();
            return 0;
        } else {
            fprintf(stderr, "Error: unknown stats option: %s\n", argv[i]);
            PrintUsage();
            return 1;
        }
    }

    if (!show_drop) {
        fprintf(stderr, "Error: no stats type specified. Use --drop.\n");
        PrintUsage();
        return 1;
    }

    // 打开 pinned map
    int map_fd = bpf_obj_get(kDropStatsPinPath);
    if (map_fd < 0) {
        fprintf(stderr, "Error: failed to open drop_stats map at %s\n", kDropStatsPinPath);
        fprintf(stderr, "Is the monitor process running? (sudo ./baseline-guard monitor --db ...)\n");
        return 1;
    }

    // 读取 PERCPU_ARRAY: key=0, value 为每个 CPU 的 __u64 计数器
    int ncpus = GetNumPossibleCPUs();
    std::vector<unsigned long long> values(ncpus, 0);

    unsigned int key = 0;
    int err = bpf_map_lookup_elem(map_fd, &key, values.data());
    if (err != 0) {
        fprintf(stderr, "Error: failed to read drop_stats map: %s\n", strerror(-err));
        close(map_fd);
        return 1;
    }

    // 只汇总在线 CPU
    std::set<int> online = GetOnlineCPUs();
    unsigned long long total = 0;
    printf("Ring buffer drop statistics (online CPUs only):\n");
    printf("  %-6s  %-12s\n", "CPU", "DROPPED");
    for (int cpu : online) {
        if (cpu < ncpus) {
            printf("  %-6d  %-12llu\n", cpu, values[cpu]);
            total += values[cpu];
        }
    }
    printf("  %-6s  %-12s\n", "------", "------------");
    printf("  %-6s  %-12llu\n", "TOTAL", total);

    close(map_fd);
    return 0;
}
