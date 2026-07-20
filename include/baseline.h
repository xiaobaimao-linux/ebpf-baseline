// include/baseline.hpp
#pragma once
#include <string>
#include <vector>

enum class Action {
    LOG,
    ALERT,
    THROTTLE,
    BLOCK,
    KILL
};

struct Rule {
    std::string name;
    std::string path;
    uint32_t mode;      // expected mode
    std::string hash;   // expected sha256, empty if not set
    Action action;
    bool has_hash = false;
};

struct Config {
    std::vector<Rule> rules;
};