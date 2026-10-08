#include "gpu_collector.hpp"

#include <nlohmann/json.hpp>

#include <spdlog/spdlog.h>

#include <cctype>
#include <cstdio>
#include <sstream>
#include <string>
#include <vector>

namespace {

using json = nlohmann::json;

const char* kNvidiaSmiQuery =
    "nvidia-smi --query-gpu=name,driver_version,memory.total,memory.used,"
    "utilization.gpu --format=csv,noheader 2>/dev/null";

std::string Trim(const std::string& value) {
    size_t begin = 0;
    while (begin < value.size() &&
           std::isspace(static_cast<unsigned char>(value[begin]))) {
        ++begin;
    }
    size_t end = value.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
        --end;
    }
    return value.substr(begin, end - begin);
}

// 去掉 "24576 MiB" / "12 %" 之类的单位后缀；"[N/A]" 等不可解析值返回 -1
int64_t ParseNumber(const std::string& raw) {
    const std::string token = Trim(raw);
    if (token.empty() || token.front() == '[') {  // [N/A] / [Not Supported]
        return -1;
    }
    try {
        return std::stoll(token);
    } catch (...) {
        return -1;
    }
}

} // namespace

std::vector<GpuInfo> ParseNvidiaSmiCsv(const std::string& csv) {
    std::vector<GpuInfo> gpus;
    std::istringstream lines(csv);
    std::string line;
    while (std::getline(lines, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (Trim(line).empty()) {
            continue;
        }
        // 型号本身可能含逗号（如 "A100-PCIE-40GB, MIG 1g.5gb"），
        // 从右侧按固定 4 个尾字段切分，剩余部分整体作为型号
        std::vector<std::string> fields;
        std::stringstream ss(line);
        std::string field;
        while (std::getline(ss, field, ',')) {
            fields.push_back(Trim(field));
        }
        if (fields.size() < 5) {
            spdlog::warn("[asset] nvidia-smi csv line has {} fields, skipped: {}",
                         fields.size(), line);
            continue;
        }
        GpuInfo info;
        info.vendor = "nvidia";
        const size_t n = fields.size();
        for (size_t i = 0; i < n - 4; ++i) {
            if (!info.model.empty()) {
                info.model += ", ";
            }
            info.model += fields[i];
        }
        info.driver = fields[n - 4];
        info.mem_total_mb = ParseNumber(fields[n - 3]);
        info.mem_used_mb = ParseNumber(fields[n - 2]);
        info.util_pct = static_cast<int>(ParseNumber(fields[n - 1]));
        gpus.push_back(info);
    }
    return gpus;
}

std::vector<GpuInfo> NvidiaCollector::collect() {
    FILE* pipe = popen(kNvidiaSmiQuery, "r");
    if (pipe == nullptr) {
        spdlog::debug("[asset] failed to run nvidia-smi");
        return {};
    }
    char buffer[4096];
    std::string output;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    const int rc = pclose(pipe);
    if (rc != 0) {  // 命令不存在（127）或无卡（非 0）均属正常缺失
        spdlog::debug("[asset] nvidia-smi unavailable (rc={}), skip nvidia gpus", rc);
        return {};
    }
    return ParseNvidiaSmiCsv(output);
}

std::vector<AssetItem> CollectGpus() {
    std::vector<AssetItem> items;
    NvidiaCollector nvidia;
    const std::vector<GpuInfo> gpus = nvidia.collect();
    int index = 0;
    for (const auto& gpu : gpus) {
        json detail;
        detail["vendor"] = gpu.vendor;
        detail["model"] = gpu.model;
        detail["driver"] = gpu.driver;
        detail["mem_total_mb"] = gpu.mem_total_mb;
        detail["mem_used_mb"] = gpu.mem_used_mb;
        detail["util_pct"] = gpu.util_pct;
        // 稳定键：gpu<序号>（与 nvidia-smi 枚举序一致）
        items.push_back({"gpu", "gpu" + std::to_string(index++), detail.dump()});
    }
    if (items.empty()) {
        spdlog::debug("[asset] no GPU detected (nvidia-smi missing or no card)");
    }
    return items;
}
