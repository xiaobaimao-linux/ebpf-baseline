// include/baseline.hpp
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "event.h"

enum class Action {
    LOG = ACTION_LOG,
    ALERT = ACTION_ALERT,
    THROTTLE = ACTION_THROTTLE,
    BLOCK = ACTION_BLOCK,
    KILL = ACTION_KILL,
    UNKNOWN = -1
};

struct Rule {
    std::string id;
    std::string severity;
    std::string name;

    unsigned long ino = 0;

    bool has_check = false;
    std::vector<std::string> check_types;
    std::string check_path;
    uint32_t check_expected = 0;
    std::string check_hash;
    std::string check_on_failure = "report_only";
    bool has_check_hash = false;

    // kernel_param 检查字段
    std::string check_param;            // 如 "kernel.randomize_va_space"
    std::string check_operator;         // 如 "=", ">=", "<=", "!="
    long long check_expected_value = 0; // 期望值

    bool has_monitor = false;
    std::string monitor_path;
    std::vector<std::string> monitor_events;
    Action monitor_action = Action::UNKNOWN;
    bool monitor_read = false;
    bool monitor_write = false;
};

