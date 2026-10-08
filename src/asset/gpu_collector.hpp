// W5 AI 资产：GPU 统一采集接口（IGpuCollector）与各厂商实现。
//
// NVIDIA 已实现（解析 nvidia-smi csv 输出，不链 NVML 库）；
// 昇腾（Ascend）/海光（DCU）为 stub，collect() 返回空并记 debug，
// 字段映射对照见 docs/gpu-collector-mapping.md。
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "asset_collector.hpp"

struct GpuInfo {
    std::string vendor;        // nvidia / ascend / dcu
    std::string model;         // 芯片型号
    std::string driver;        // 驱动版本
    int64_t mem_total_mb = -1; // 显存总量（MB），未知为 -1
    int64_t mem_used_mb = -1;  // 显存已用（MB），未知为 -1
    int util_pct = -1;         // 计算核心利用率（%），未知为 -1
};

// 统一 GPU 采集接口：vendor() 返回厂商标识，collect() 返回本机该厂商全部卡信息。
// 无任何卡或工具缺失时 collect() 返回空数组，不抛异常。
class IGpuCollector {
public:
    virtual ~IGpuCollector() = default;
    virtual std::string vendor() const = 0;
    // 是否已适配（stub 返回 false，供调用方区分"无卡"与"未支持该平台"）
    virtual bool adapted() const { return true; }
    virtual std::vector<GpuInfo> collect() = 0;
};

// 解析 `nvidia-smi --query-gpu=name,driver_version,memory.total,memory.used,
// utilization.gpu --format=csv,noheader` 的输出；单独暴露供 fixture 单测使用。
std::vector<GpuInfo> ParseNvidiaSmiCsv(const std::string& csv);

// NVIDIA：popen 调 nvidia-smi，无该命令或无卡时返回空
class NvidiaCollector : public IGpuCollector {
public:
    std::string vendor() const override { return "nvidia"; }
    std::vector<GpuInfo> collect() override;
};

// 昇腾 NPU（npu-smi info）：未适配 stub
class AscendCollector : public IGpuCollector {
public:
    std::string vendor() const override { return "ascend"; }
    bool adapted() const override { return false; }
    std::vector<GpuInfo> collect() override { return {}; }  // 未适配
};

// 海光 DCU（hy-smi）：未适配 stub
class DcuCollector : public IGpuCollector {
public:
    std::string vendor() const override { return "dcu"; }
    bool adapted() const override { return false; }
    std::vector<GpuInfo> collect() override { return {}; }  // 未适配
};

// 汇总入口：逐厂商采集（当前仅 NVIDIA 实现），失败/缺失记 debug 降级为空数组
std::vector<AssetItem> CollectGpus();
