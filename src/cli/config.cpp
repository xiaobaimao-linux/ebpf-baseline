#include <cstdint>
#include <iostream>
#include <spdlog/spdlog.h>
#include <string>
#include <vector>
#include <yaml-cpp/yaml.h>

#include "config.hpp"

using namespace std;

static vector<string> parseYamlTypes(const YAML::Node &node) {
    vector<string> out;
    if (!node) {
        return out;
    }
    if (node.IsSequence()) {
        for (const auto &item : node) {
            if (item && item.IsScalar()) {
                out.push_back(item.as<string>());
            }
        }
    } else if (node.IsScalar()) {
        out.push_back(node.as<string>());
    }
    return out;
}

// 将字符串转为 Action 枚举
Action stringToAction(const string &str) {
    if (str == "allow")
        return Action::LOG;
    if (str == "block")
        return Action::BLOCK;
    if (str == "alert")
        return Action::ALERT;
    if (str == "kill")
        return Action::KILL;
    if (str == "throttle")
        return Action::THROTTLE;
    return Action::UNKNOWN;
}

// 将 Action 枚举转为字符串（用于打印）
string actionToString(Action action) {
    switch (action) {
    case Action::LOG:
        return "allow";
    case Action::BLOCK:
        return "block";
    case Action::ALERT:
        return "alert";
    case Action::KILL:
        return "kill";
    case Action::THROTTLE:
        return "throttle";
    default:
        return "unknown";
    }
}

// 将 severity 字符串转为数值
unsigned char stringToSeverity(const string& s) {
    if (s == "low")      return SEVERITY_LOW;
    if (s == "medium")   return SEVERITY_MEDIUM;
    if (s == "high")     return SEVERITY_HIGH;
    if (s == "critical") return SEVERITY_CRITICAL;
    return SEVERITY_UNKNOWN;  // 未知等级
}

// 将 severity 数值转为字符串
string severityToString(unsigned char sev) {
    switch (sev) {
    case SEVERITY_LOW:      return "low";
    case SEVERITY_MEDIUM:   return "medium";
    case SEVERITY_HIGH:     return "high";
    case SEVERITY_CRITICAL: return "critical";
    default:                return "unknown";
    }
}

void compute_inodes(Config &config) {
    for (auto &rule : config.rules) {
        struct stat st;
        string target_path = rule.check_path;
        if (target_path.empty()) {
            target_path = rule.monitor_path;
        }
        if (target_path.empty()) {
            rule.ino = 0;
            continue;
        }
        if (stat(target_path.c_str(), &st) == 0) {
            rule.ino = st.st_ino;
        } else {
            rule.ino = 0; // 文件不存在
        }
    }
}

// 解析 YAML 文件，返回完整配置对象
Config parseYamlFile(const string &filename) {
    Config config;
    vector<Rule> rules;

    try {
        YAML::Node root = YAML::LoadFile(filename);

        if (root["alert"]) {
            const YAML::Node &alertNode = root["alert"];
            if (alertNode["dingtalk"]) {
                const YAML::Node &dingtalkNode = alertNode["dingtalk"];
                if (dingtalkNode["webhook"]) {
                    config.alert.dingtalk_webhook = dingtalkNode["webhook"].as<string>();
                }
                if (dingtalkNode["secret"]) {
                    config.alert.dingtalk_secret = dingtalkNode["secret"].as<string>();
                }
            }
            if (alertNode["throttle"]) {
                try {
                    config.alert.throttle_seconds = alertNode["throttle"].as<int>();
                    spdlog::info("告警节流配置: {} 秒", config.alert.throttle_seconds);
                } catch (const YAML::Exception &e) {
                    spdlog::warn("无法解析 alert.throttle 值: {}", e.what());
                }
            }
        }

        // 解析 db: 节点（数据库保留策略）
        if (root["db"]) {
            const YAML::Node &dbNode = root["db"];
            if (dbNode["retention_days"]) {
                try {
                    config.db.retention_days = dbNode["retention_days"].as<int>();
                    if (config.db.retention_days > 0) {
                        spdlog::info("告警保留天数: {} 天", config.db.retention_days);
                    } else {
                        spdlog::info("告警保留: 永久");
                    }
                } catch (const YAML::Exception &e) {
                    spdlog::warn("无法解析 db.retention_days 值: {}", e.what());
                }
            }
            if (dbNode["retention_max_records"]) {
                try {
                    config.db.retention_max_records = dbNode["retention_max_records"].as<int>();
                    if (config.db.retention_max_records > 0) {
                        spdlog::info("告警最大记录数: {} 条", config.db.retention_max_records);
                    } else {
                        spdlog::info("告警记录数: 无限制");
                    }
                } catch (const YAML::Exception &e) {
                    spdlog::warn("无法解析 db.retention_max_records 值: {}", e.what());
                }
            }
        }

        if (!root["rules"]) {
            spdlog::error("YAML 文件缺少 'rules' 根节点: {}", filename);
            return config;
        }

        const YAML::Node &rulesNode = root["rules"];
        for (const auto &item : rulesNode) {
            try {
            Rule rule;

            rule.id = item["id"] ? item["id"].as<string>() : "";
            if (item["severity"]) {
                rule.severity = stringToSeverity(item["severity"].as<string>());
                // 未知字符串回退到 MEDIUM
                if (rule.severity == SEVERITY_UNKNOWN) {
                    rule.severity = SEVERITY_MEDIUM;
                }
            }
            // 否则保持默认值 SEVERITY_MEDIUM
            string name = item["name"] ? item["name"].as<string>() : "";
            if (!rule.id.empty() && !name.empty()) {
                rule.name = rule.id + ": " + name;
            } else if (!name.empty()) {
                rule.name = name;
            } else if (!rule.id.empty()) {
                rule.name = rule.id;
            } else {
                rule.name = "(unnamed)";
            }

            if (item["check"]) {
                rule.has_check = true;
                const YAML::Node &check = item["check"];
                rule.check_types = parseYamlTypes(check["type"]);
                if (check["path"]) {
                    rule.check_path = check["path"].as<string>();
                }
                if (check["expected"]) {
                    // 根据检查类型解析 expected：文件权限为八进制字符串，内核参数为数值
                    const YAML::Node& expectedNode = check["expected"];
                    bool is_kernel = false;
                    for (const auto& t : rule.check_types) {
                        if (t == "kernel_param") {
                            is_kernel = true;
                            break;
                        }
                    }
                    if (is_kernel) {
                        try {
                            rule.check_expected_value = expectedNode.as<long long>();
                        } catch (...) {
                            spdlog::warn("无法解析 expected 值 (rule: {})", rule.name);
                            rule.check_expected_value = 0;
                        }
                    } else {
                        string expected = expectedNode.as<string>();
                        try {
                            rule.check_expected = stoul(expected, nullptr, 8);
                        } catch (...) {
                            spdlog::warn("无法解析 expected 值: {} (rule: {})", expected, rule.name);
                            rule.check_expected = 0;
                        }
                    }
                }
                if (check["hash"]) {
                    rule.check_hash = check["hash"].as<string>();
                    rule.has_check_hash = true;
                }
                if (check["param"]) {
                    rule.check_param = check["param"].as<string>();
                }
                if (check["operator"]) {
                    rule.check_operator = check["operator"].as<string>();
                }
                if (check["on_failure"]) {
                    rule.check_on_failure = check["on_failure"].as<string>();
                }
            }

            if (item["monitor"]) {
                rule.has_monitor = true;
                const YAML::Node &monitor = item["monitor"];
                if (monitor["path"]) {
                    rule.monitor_path = monitor["path"].as<string>();
                }
                if (monitor["action"]) {
                    rule.monitor_action = stringToAction(monitor["action"].as<string>());
                }
                if (monitor["events"]) {
                    const auto &eventsNode = monitor["events"];
                    if (eventsNode.IsSequence()) {
                        for (const auto &ev : eventsNode) {
                            string evt = ev.as<string>();
                            rule.monitor_events.push_back(evt);
                            if (evt == "read") {
                                rule.monitor_read = true;
                            }
                            if (evt == "write") {
                                rule.monitor_write = true;
                            }
                            if (evt == "delete") {
                                rule.monitor_delete = true;
                            }
                        }
                    }
                }
            }

            if (!rule.has_check && !rule.has_monitor) {
                spdlog::warn("规则 {} 缺少 'check' 或 'monitor' 节点，已跳过", rule.name);
                continue;
            }

            rules.push_back(rule);
            spdlog::debug("解析 YAML 规则: name={}, check_path={}, check_expected={:o}, check_hash={}, check_on_failure={}, monitor_path={}, monitor_events={}",
                          rule.name,
                          rule.check_path.empty() ? "(无)" : rule.check_path,
                          rule.check_expected,
                          rule.has_check_hash ? rule.check_hash : "(无)",
                          rule.check_on_failure.empty() ? "(无)" : rule.check_on_failure,
                          rule.monitor_path.empty() ? "(无)" : rule.monitor_path,
                          rule.monitor_events.empty() ? "(无)" : "set");
            } catch (const YAML::Exception &e) {
                string rule_id = item["id"] ? item["id"].as<string>() : "(unknown)";
                spdlog::warn("规则 {} 解析失败，已跳过: {}", rule_id, e.what());
            }
        }

        config.rules = rules;
    } catch (const YAML::Exception &e) {
        spdlog::error("YAML 解析错误: {}", e.what());
    }

    return config;
}

// 打印规则列表
void printRules(const vector<Rule> &rules) {
    spdlog::info("共解析 {} 条规则:", rules.size());
    for (const auto &rule : rules) {
        spdlog::info("  [{}]", rule.name);
        if (rule.has_check) {
            spdlog::info("    check_types:  {}", fmt::format("{}", fmt::join(rule.check_types, ", ")));
            if (!rule.check_path.empty()) {
                spdlog::info("    check_path:   {}", rule.check_path);
            }
            if (rule.check_expected != 0) {
                spdlog::info("    check_expected: {:o}", rule.check_expected);
            }
            if (rule.has_check_hash) {
                spdlog::info("    check_hash:   {}", rule.check_hash);
            } else {
                spdlog::info("    check_hash:   (未设置)");
            }
            if (!rule.check_param.empty()) {
                spdlog::info("    check_param:  {}", rule.check_param);
                spdlog::info("    check_op:     {}", rule.check_operator);
                spdlog::info("    check_expect: {}", rule.check_expected_value);
            }
            spdlog::info("    check_on_failure: {}", rule.check_on_failure.empty() ? "report_only" : rule.check_on_failure);
        }
        if (rule.has_monitor) {
            spdlog::info("    monitor_path:   {}", rule.monitor_path);
            spdlog::info("    monitor_events: {}", rule.monitor_events.empty() ? "(无)" : "set");
            spdlog::info("    monitor_action: {}", actionToString(rule.monitor_action));
        }
    }
}