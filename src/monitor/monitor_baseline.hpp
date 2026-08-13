#pragma once

#include "alert_manager.hpp"
#include "baseline_db.hpp"

#include <string>

// 基线实时监控告警标识（与 yaml-rule / baseline-check 区分）
constexpr const char* kBaselineRuleId   = "baseline";
constexpr const char* kBaselineRuleName = "基线监控";

// 基线比对偏差结果
// event_type 为空表示一致；否则为以下之一：
//   hash_changed (high) / perm_changed (medium) / missing (high) / access_failed
struct BaselineDeviation {
    std::string event_type;   // hash_changed / perm_changed / missing / access_failed
    std::string severity;     // high / medium
    std::string expected;
    std::string actual;
};

// 比对单个文件的当前磁盘状态与基线条目
// 逻辑与 baseline_check.cpp::CheckOneEntry 严格一致：
//   lstat -> missing / compute_sha256 -> hash_changed / 比对 mode+uid+gid -> perm_changed
BaselineDeviation CompareWithBaseline(const CheckEntry& baseline,
                                       const std::string& file_path);

// 处理一次基线偏差：打印日志 + 通过 AlertManager 落库 + 钉钉推送
void HandleBaselineDeviation(const BaselineDeviation& dev,
                              const std::string& file_path,
                              const std::string& proc_name,
                              int pid,
                              AlertManager& alert_mgr);
