#include "watermark_backpressure.hpp"

#include <algorithm>
#include <bpf/libbpf.h>
#include <spdlog/spdlog.h>

// ── 配置 ────────────────────────────────────────────────────────────

void WatermarkBackpressure::SetRingBuffer(struct ring_buffer* rb) {
    rb_ = rb;
}

void WatermarkBackpressure::SetNumCPUs(int num_cpus) {
    num_cpus_ = num_cpus;
}

// ── 水位计算 ────────────────────────────────────────────────────────

void WatermarkBackpressure::UpdateUtilization() {
    if (!rb_ || num_cpus_ <= 0) {
        utilization_ = 0.0;
        level_ = WATERMARK_NORMAL;
        return;
    }

    size_t total_avail = 0;
    size_t total_size  = 0;

    for (int i = 0; i < num_cpus_; ++i) {
        struct ring* r = ring_buffer__ring(rb_, static_cast<unsigned int>(i));
        if (!r) continue;

        total_avail += ring__avail_data_size(r);
        total_size  += ring__size(r);
    }

    if (total_size > 0) {
        utilization_ = static_cast<double>(total_avail) / static_cast<double>(total_size) * 100.0;
    } else {
        utilization_ = 0.0;
    }

    // 限制在 [0, 100] 范围
    utilization_ = std::clamp(utilization_, 0.0, 100.0);

    // 根据利用率确定水位等级
    unsigned char new_level;
    if (utilization_ < kWarningThreshold) {
        new_level = WATERMARK_NORMAL;
    } else if (utilization_ < kHighThreshold) {
        new_level = WATERMARK_WARNING;
    } else if (utilization_ < kOverloadThreshold) {
        new_level = WATERMARK_HIGH;
    } else {
        new_level = WATERMARK_OVERLOAD;
    }

    if (new_level != level_) {
        spdlog::info("[watermark] level changed: {} -> {} (utilization={:.1f}%)",
                     LevelToString(level_), LevelToString(new_level), utilization_);
        level_ = new_level;
    }
}

void WatermarkBackpressure::SetUtilization(double percent) {
    utilization_ = std::clamp(percent, 0.0, 100.0);

    if (utilization_ < kWarningThreshold) {
        level_ = WATERMARK_NORMAL;
    } else if (utilization_ < kHighThreshold) {
        level_ = WATERMARK_WARNING;
    } else if (utilization_ < kOverloadThreshold) {
        level_ = WATERMARK_HIGH;
    } else {
        level_ = WATERMARK_OVERLOAD;
    }
}

// ── 辅助函数 ────────────────────────────────────────────────────────

const char* WatermarkBackpressure::LevelToString(unsigned char level) {
    switch (level) {
    case WATERMARK_NORMAL:   return "normal";
    case WATERMARK_WARNING:  return "warning";
    case WATERMARK_HIGH:     return "high";
    case WATERMARK_OVERLOAD: return "overload";
    default:                 return "unknown";
    }
}
