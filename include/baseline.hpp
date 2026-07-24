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
    std::string name;
    std::string path;
    unsigned long ino;
    uint32_t mode;    // expected mode
    std::string hash; // expected sha256, empty if not set
    Action action;
    bool has_hash = false;

    // 添加一个辅助方法
    void set_hash(const std::string &h) {
        hash = h;
        has_hash = !h.empty(); // 自动设置
    }
};

struct Config {
    std::vector<Rule> rules;
};