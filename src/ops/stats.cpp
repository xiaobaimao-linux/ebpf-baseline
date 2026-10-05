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

#include "stats_slots.h"

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
    printf("  --drop        show drop/accounting counters from pinned eBPF maps\n");
    printf("  -h, --help    display this message\n");
}

// 读 PERCPU_ARRAY 计数 map，按槽位汇总在线 CPU；map 不存在返回 false
static bool ReadPercpuDropStats(const char* pin_path, unsigned long long sums[DROP_STATS_SLOTS]) {
    int map_fd = bpf_obj_get(pin_path);
    if (map_fd < 0)
        return false;

    int ncpus = GetNumPossibleCPUs();
    std::vector<unsigned long long> values(static_cast<size_t>(ncpus) * DROP_STATS_SLOTS, 0);

    bool ok = true;
    std::set<int> online = GetOnlineCPUs();
    for (unsigned int slot = 0; slot < DROP_STATS_SLOTS; ++slot) {
        // percpu map：每个 key（槽位）一次读出 ncpus 个 __u64，buffer 按槽位分段
        unsigned long long* base = values.data() + static_cast<size_t>(ncpus) * slot;
        if (bpf_map_lookup_elem(map_fd, &slot, base) != 0) {
            ok = false;
            break;
        }
        unsigned long long total = 0;
        for (int cpu : online) {
            if (cpu < ncpus)
                total += base[cpu];
        }
        sums[slot] = total;
    }

    close(map_fd);
    return ok;
}

// 读用户态 ARRAY 计数 map；map 不存在返回 false
static bool ReadUserStats(const char* pin_path, unsigned long long vals[USER_STATS_SLOTS]) {
    int map_fd = bpf_obj_get(pin_path);
    if (map_fd < 0)
        return false;
    bool ok = true;
    for (unsigned int slot = 0; slot < USER_STATS_SLOTS; ++slot) {
        if (bpf_map_lookup_elem(map_fd, &slot, &vals[slot]) != 0) {
            ok = false;
            break;
        }
    }
    close(map_fd);
    return ok;
}

// 按探针打印内核侧计数（emitted / reserve_failed / backpressure_drop / discarded）
static void PrintKernelProbe(const char* probe, const unsigned long long sums[DROP_STATS_SLOTS],
                             bool has_backpressure) {
    printf("[%s]\n", probe);
    printf("kernel.%s.emitted           = %llu\n", probe, sums[DROP_SLOT_EMITTED]);
    printf("kernel.%s.reserve_failed    = %llu\n", probe, sums[DROP_SLOT_RESERVE_FAIL]);
    if (has_backpressure)
        printf("kernel.%s.backpressure_drop = %llu\n", probe, sums[DROP_SLOT_BACKPRESSURE]);
    if (sums[DROP_SLOT_DISCARDED] > 0)
        printf("kernel.%s.discarded         = %llu\n", probe, sums[DROP_SLOT_DISCARDED]);
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

    bool any = false;
    printf("Drop/accounting counters (pinned eBPF maps, monitor must be running):\n");

    // ── 内核侧：按探针分组（map 未 pin 即该探针未运行，跳过）──────
    struct ProbeEntry { const char* name; const char* pin; bool has_bp; };
    const ProbeEntry probes[] = {
        {"file", DROP_STATS_PIN_PATH, true},
        {"proc", PROC_DROP_STATS_PIN_PATH, false},
        {"net",  NET_DROP_STATS_PIN_PATH, false},
        {"priv", PRIV_DROP_STATS_PIN_PATH, false},
    };
    for (const auto& p : probes) {
        unsigned long long sums[DROP_STATS_SLOTS] = {0};
        if (ReadPercpuDropStats(p.pin, sums)) {
            any = true;
            PrintKernelProbe(p.name, sums, p.has_bp);
        }
    }

    // ── 用户态：事件总线 / 批缓冲 / 落库 ─────────────────────────
    unsigned long long uvals[USER_STATS_SLOTS] = {0};
    if (ReadUserStats(USER_STATS_PIN_PATH, uvals)) {
        any = true;
        static const char* hi_names[4] = {"file", "ctrl", "p2", "p3"};
        static const char* lo_names[4] = {"p0", "p1", "net", "dns"};
        printf("[userspace]\n");
        for (int p = 0; p < 4; p++)
            printf("bus.queue_full.hi.p%d_%s = %llu\n", p, hi_names[p],
                   uvals[USTAT_BUS_DROP_HI_P0 + p]);
        for (int p = 0; p < 4; p++)
            printf("bus.queue_full.lo.p%d_%s = %llu\n", p, lo_names[p],
                   uvals[USTAT_BUS_DROP_LO_P0 + p]);
        printf("batch_overflow = %llu\n", uvals[USTAT_BATCH_OVERFLOW]);
        printf("store_failed   = %llu\n", uvals[USTAT_STORE_FAILED]);
        printf("bus.pushed     = %llu\n", uvals[USTAT_BUS_PUSHED]);
        printf("store.stored   = %llu\n", uvals[USTAT_STORE_STORED]);
        printf("bus.depth.hi   = %llu\n", uvals[USTAT_BUS_HI_DEPTH]);
        printf("bus.depth.lo   = %llu\n", uvals[USTAT_BUS_LO_DEPTH]);
    }

    if (!any) {
        fprintf(stderr, "Error: no pinned stats maps found under %s\n", BG_PIN_DIR);
        fprintf(stderr, "Is the monitor process running? (sudo ./baseline-guard monitor --db ...)\n");
        return 1;
    }
    return 0;
}
