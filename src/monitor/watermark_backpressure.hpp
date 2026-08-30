#pragma once

#include <cstddef>
#include <cstdint>

#include "event.h"

struct ring_buffer;

// 水位等级复用 event.h 中的 WATERMARK_NORMAL / WATERMARK_WARNING / WATERMARK_HIGH / WATERMARK_OVERLOAD

// 严重等级复用 event.h 中的 SEVERITY_LOW / SEVERITY_MEDIUM / SEVERITY_HIGH / SEVERITY_CRITICAL / SEVERITY_UNKNOWN

// ── Ring Buffer 四级水位控制器 ──────────────────────────────────────
//
// 职责：计算 Ring Buffer 利用率，确定水位等级
// 背压决策（丢弃/批量/实时）由内核态 eBPF 根据 watermark_level map 执行
//
class WatermarkBackpressure {
public:
    // 默认水位阈值
    static constexpr double kWarningThreshold  = 70.0;
    static constexpr double kHighThreshold     = 85.0;
    static constexpr double kOverloadThreshold = 95.0;

    WatermarkBackpressure() = default;

    // ── 配置 ──────────────────────────────────────────────────────
    void SetRingBuffer(struct ring_buffer* rb);
    void SetNumCPUs(int num_cpus);

    // ── 水位查询 ──────────────────────────────────────────────────
    // 遍历所有 per-CPU ring 实例，计算总利用率并更新水位
    void UpdateUtilization();

    // 直接设置利用率（用于测试或外部驱动）
    void SetUtilization(double percent);

    double           GetUtilization()    const { return utilization_; }
    unsigned char  GetWatermarkLevel() const { return level_; }

    // ── 辅助 ──────────────────────────────────────────────────────
    static const char* LevelToString(unsigned char level);

private:
    struct ring_buffer* rb_       = nullptr;
    int                 num_cpus_ = 0;

    double         utilization_ = 0.0;
    unsigned char  level_       = WATERMARK_NORMAL;
};
