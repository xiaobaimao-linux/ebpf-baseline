#pragma once

#include <string>

// 告警四级分级模型（W5 D3）：critical / high / medium / low。
// DSL priority 字段、AlertEvent.severity、alerts 表 severity 列与 CLI 查询
// 共用此取值集；DSL 缺省值为 medium（解析器不报错）。
namespace alert {

enum class Severity { Critical, High, Medium, Low };

// DSL priority 缺省值
inline const char *SeverityDefault() {
    return "medium";
}

inline const char *SeverityToString(Severity s) {
    switch (s) {
    case Severity::Critical:
        return "critical";
    case Severity::High:
        return "high";
    case Severity::Medium:
        return "medium";
    case Severity::Low:
        return "low";
    }
    return "medium";
}

// 字符串 → 枚举；非法值返回 false（out 不变）
inline bool SeverityFromString(const std::string &s, Severity &out) {
    if (s == "critical") {
        out = Severity::Critical;
        return true;
    }
    if (s == "high") {
        out = Severity::High;
        return true;
    }
    if (s == "medium") {
        out = Severity::Medium;
        return true;
    }
    if (s == "low") {
        out = Severity::Low;
        return true;
    }
    return false;
}

inline bool SeverityIsValid(const std::string &s) {
    Severity tmp;
    return SeverityFromString(s, tmp);
}

} // namespace alert
