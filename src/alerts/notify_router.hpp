#pragma once
#include <chrono>
#include <string>
#include "alert_event.hpp"
#include "severity.hpp"

// 外发路由与静默判定的纯函数（W5 D4）：无 IO、无全局状态，供单测直接覆盖。
namespace notify {

// severity 等级数值（critical=3 ... low=0）；未知值按 medium（DSL priority 缺省口径）
inline int SeverityRank(const std::string& s) {
    alert::Severity sev;
    if (alert::SeverityFromString(s, sev)) {
        switch (sev) {
        case alert::Severity::Critical: return 3;
        case alert::Severity::High:     return 2;
        case alert::Severity::Medium:   return 1;
        case alert::Severity::Low:      return 0;
        }
    }
    return 1;  // medium
}

// 级别路由：告警级别 >= min_level 才外发（min_level 空/非法按默认 high）
inline bool ShouldRouteByLevel(const std::string& severity, const std::string& min_level) {
    const std::string min = alert::SeverityIsValid(min_level) ? min_level : "high";
    return SeverityRank(severity) >= SeverityRank(min);
}

// 静默对象 key：进程类告警（process.* 事件，如 DSL process.exec）用 exe+pid
// 命名空间；文件类用路径（与现有冷却按 rule_id 键控的 map 窗口同款结构，
// 此处扩展为 rule_id + 对象 key 两级）。均无则退 "-"，仅剩 rule_id 维度。
inline std::string SilenceObjectKey(const AlertEvent& e) {
    if (e.event_type.rfind("process.", 0) == 0) {
        return "proc:" + e.exe + ":" + std::to_string(e.pid);
    }
    if (!e.file_path.empty()) {
        return "file:" + e.file_path;
    }
    if (!e.exe.empty()) {
        return "proc:" + e.exe + ":" + std::to_string(e.pid);
    }
    return "-";
}

// 静默窗口判定：window_seconds <= 0 视为静默关闭（不抑制）
inline bool SilenceWindowActive(std::chrono::steady_clock::time_point last_sent,
                                std::chrono::steady_clock::time_point now,
                                int window_seconds) {
    if (window_seconds <= 0) {
        return false;
    }
    return now - last_sent < std::chrono::seconds(window_seconds);
}

// 聚合窗口动作（W5 D5 聚合降噪）：同 key（rule_id + SilenceObjectKey，与静默同 key）
// 窗口内重复告警合并为窗末一条 occurrences=N 摘要。窗口活跃判定复用静默窗口语义。
enum class AggAction {
    kOpenAndSend,    // 无窗口：本条开新窗并立即外发（首条不延迟）
    kMerge,          // 窗口活跃：并入窗口，不外发（计 merged），窗末摘要统一补发
    kFlushAndSend,   // 窗口到期：先补发旧窗摘要（若有合并），本条开新窗并立即外发
};

inline AggAction AggregationAction(bool window_exists,
                                   std::chrono::steady_clock::time_point win_start,
                                   std::chrono::steady_clock::time_point now,
                                   int window_seconds) {
    if (!window_exists) {
        return AggAction::kOpenAndSend;
    }
    if (SilenceWindowActive(win_start, now, window_seconds)) {
        return AggAction::kMerge;
    }
    return AggAction::kFlushAndSend;
}

}  // namespace notify
