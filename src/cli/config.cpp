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

// alert/db/telemetry 节点解析（lenient：字段类型错告警并取默认值），
// parseYamlFile 与 tryParseYamlFile 共用。
static void parseAlertNode(const YAML::Node &alertNode, AlertConfig &alert) {
    if (alertNode["dingtalk"]) {
        const YAML::Node &dingtalkNode = alertNode["dingtalk"];
        if (dingtalkNode["webhook"]) {
            alert.dingtalk_webhook = dingtalkNode["webhook"].as<string>();
        }
        if (dingtalkNode["secret"]) {
            alert.dingtalk_secret = dingtalkNode["secret"].as<string>();
        }
    }
    if (alertNode["throttle"]) {
        try {
            alert.throttle_seconds = alertNode["throttle"].as<int>();
            spdlog::info("告警节流配置: {} 秒", alert.throttle_seconds);
        } catch (const YAML::Exception &e) {
            spdlog::warn("无法解析 alert.throttle 值: {}", e.what());
        }
    }
}

static void parseDbNode(const YAML::Node &dbNode, DbConfig &db) {
    if (dbNode["retention_days"]) {
        try {
            db.retention_days = dbNode["retention_days"].as<int>();
            if (db.retention_days > 0) {
                spdlog::info("告警保留天数: {} 天", db.retention_days);
            } else {
                spdlog::info("告警保留: 永久");
            }
        } catch (const YAML::Exception &e) {
            spdlog::warn("无法解析 db.retention_days 值: {}", e.what());
        }
    }
    if (dbNode["retention_max_records"]) {
        try {
            db.retention_max_records = dbNode["retention_max_records"].as<int>();
            if (db.retention_max_records > 0) {
                spdlog::info("告警最大记录数: {} 条", db.retention_max_records);
            } else {
                spdlog::info("告警记录数: 无限制");
            }
        } catch (const YAML::Exception &e) {
            spdlog::warn("无法解析 db.retention_max_records 值: {}", e.what());
        }
    }
}

static void parseTelemetryNode(const YAML::Node &telemetryNode, TelemetryConfig &telemetry) {
    if (telemetryNode["network"]) {
        try {
            telemetry.network = telemetryNode["network"].as<bool>();
            spdlog::info("网络遥测: {}", telemetry.network ? "开启" : "关闭");
        } catch (const YAML::Exception &e) {
            spdlog::warn("无法解析 telemetry.network 值: {}", e.what());
        }
    }
    if (telemetryNode["dns"]) {
        try {
            telemetry.dns = telemetryNode["dns"].as<bool>();
            spdlog::info("DNS 查询遥测: {}", telemetry.dns ? "开启" : "关闭");
        } catch (const YAML::Exception &e) {
            spdlog::warn("无法解析 telemetry.dns 值: {}", e.what());
        }
    }
    if (telemetryNode["privilege"]) {
        try {
            telemetry.privilege = telemetryNode["privilege"].as<bool>();
            spdlog::info("权限事件遥测: {}", telemetry.privilege ? "开启" : "关闭");
        } catch (const YAML::Exception &e) {
            spdlog::warn("无法解析 telemetry.privilege 值: {}", e.what());
        }
    }
    if (telemetryNode["store"]) {
        try {
            telemetry.store = telemetryNode["store"].as<bool>();
            spdlog::info("遥测落库: {}", telemetry.store ? "开启" : "关闭");
        } catch (const YAML::Exception &e) {
            spdlog::warn("无法解析 telemetry.store 值: {}", e.what());
        }
    }
    if (telemetryNode["events_db"]) {
        telemetry.events_db = telemetryNode["events_db"].as<string>();
    }
    if (telemetryNode["queue_hi"]) {
        try {
            telemetry.queue_hi = telemetryNode["queue_hi"].as<int>();
        } catch (const YAML::Exception &e) {
            spdlog::warn("无法解析 telemetry.queue_hi 值: {}", e.what());
        }
    }
    if (telemetryNode["queue_lo"]) {
        try {
            telemetry.queue_lo = telemetryNode["queue_lo"].as<int>();
        } catch (const YAML::Exception &e) {
            spdlog::warn("无法解析 telemetry.queue_lo 值: {}", e.what());
        }
    }
    if (telemetryNode["batch_size"]) {
        try {
            telemetry.batch_size = telemetryNode["batch_size"].as<int>();
        } catch (const YAML::Exception &e) {
            spdlog::warn("无法解析 telemetry.batch_size 值: {}", e.what());
        }
    }
    if (telemetryNode["batch_ms"]) {
        try {
            telemetry.batch_ms = telemetryNode["batch_ms"].as<int>();
        } catch (const YAML::Exception &e) {
            spdlog::warn("无法解析 telemetry.batch_ms 值: {}", e.what());
        }
    }
}

static void parseRuleEngineNode(const YAML::Node &node, RuleEngineConfig &rule_engine) {
    if (node["enabled"]) {
        try {
            rule_engine.enabled = node["enabled"].as<bool>();
            spdlog::info("规则引擎: {}", rule_engine.enabled ? "开启" : "关闭");
        } catch (const YAML::Exception &e) {
            spdlog::warn("无法解析 rule_engine.enabled 值: {}", e.what());
        }
    }
    if (node["rules_dir"]) {
        try {
            rule_engine.rules_dir = node["rules_dir"].as<string>();
        } catch (const YAML::Exception &e) {
            spdlog::warn("无法解析 rule_engine.rules_dir 值: {}", e.what());
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
            parseAlertNode(root["alert"], config.alert);
        }

        // 解析 db: 节点（数据库保留策略）
        if (root["db"]) {
            parseDbNode(root["db"], config.db);
        }

        // 解析 telemetry: 节点（遥测开关）
        if (root["telemetry"]) {
            parseTelemetryNode(root["telemetry"], config.telemetry);
        }

        // 解析 rule_engine: 节点（DSL 规则引擎）
        if (root["rule_engine"]) {
            parseRuleEngineNode(root["rule_engine"], config.rule_engine);
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
                            if (evt == "chmod") {
                                rule.monitor_chmod = true;
                            }
                            if (evt == "chown") {
                                rule.monitor_chown = true;
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
        if (!rule.whitelist.empty()) {
            spdlog::info("    whitelist:      {} 条进程白名单", rule.whitelist.size());
        }
    }
}

// ── 严格规则解析（M0-2）：任何字段类型/结构错误抛出 YAML::Exception（mark 带行号）──
static Rule parseOneRuleStrict(const YAML::Node &item) {
    Rule rule;

    rule.id = item["id"] ? item["id"].as<string>() : "";
    if (item["severity"]) {
        rule.severity = stringToSeverity(item["severity"].as<string>());
        // 未知字符串回退到 MEDIUM
        if (rule.severity == SEVERITY_UNKNOWN) {
            rule.severity = SEVERITY_MEDIUM;
        }
    }
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
                rule.check_expected_value = expectedNode.as<long long>();
            } else {
                string expected = expectedNode.as<string>();
                try {
                    rule.check_expected = stoul(expected, nullptr, 8);
                } catch (...) {
                    throw YAML::Exception(expectedNode.Mark(),
                                          "无法解析 expected 八进制值: " + expected);
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
                    if (evt == "chmod") {
                        rule.monitor_chmod = true;
                    }
                    if (evt == "chown") {
                        rule.monitor_chown = true;
                    }
                }
            }
        }
    }

    // whitelist: 可选进程白名单列表，条目 {exe: 全路径, parent_chain: [祖先 exe...]}
    if (item["whitelist"]) {
        const YAML::Node &wl = item["whitelist"];
        if (!wl.IsSequence()) {
            throw YAML::Exception(wl.Mark(), "whitelist 必须是条目列表");
        }
        for (const auto &ent : wl) {
            if (!ent.IsMap()) {
                throw YAML::Exception(ent.Mark(), "whitelist 条目必须是 map（含 exe 字段）");
            }
            WhitelistEntry we;
            if (!ent["exe"]) {
                throw YAML::Exception(ent.Mark(), "whitelist 条目缺少 exe 字段");
            }
            we.exe = ent["exe"].as<string>();
            if (ent["parent_chain"]) {
                const YAML::Node &pc = ent["parent_chain"];
                if (!pc.IsSequence()) {
                    throw YAML::Exception(pc.Mark(), "parent_chain 必须是字符串列表");
                }
                for (const auto &p : pc) {
                    we.parent_chain.push_back(p.as<string>());
                }
            }
            rule.whitelist.push_back(we);
        }
    }

    return rule;
}

bool tryParseYamlFile(const string &filename, Config &out, string &err) {
    YAML::Node root;
    try {
        root = YAML::LoadFile(filename);
    } catch (const YAML::Exception &e) {
        err = filename + ":" + to_string(e.mark.line + 1) + ": " + e.what();
        return false;
    }

    if (root["alert"]) {
        parseAlertNode(root["alert"], out.alert);
    }
    if (root["db"]) {
        parseDbNode(root["db"], out.db);
    }
    if (root["telemetry"]) {
        parseTelemetryNode(root["telemetry"], out.telemetry);
    }
    if (root["rule_engine"]) {
        parseRuleEngineNode(root["rule_engine"], out.rule_engine);
    }

    if (!root["rules"]) {
        err = filename + ": 缺少 'rules' 根节点";
        return false;
    }
    if (!root["rules"].IsSequence()) {
        err = filename + ":" + to_string(root["rules"].Mark().line + 1) +
              ": rules 必须是规则列表";
        return false;
    }

    vector<Rule> rules;
    try {
        for (const auto &item : root["rules"]) {
            Rule rule = parseOneRuleStrict(item);
            if (!rule.has_check && !rule.has_monitor) {
                spdlog::warn("规则 {} 缺少 'check' 或 'monitor' 节点，已跳过", rule.name);
                continue;
            }
            rules.push_back(rule);
        }
    } catch (const YAML::Exception &e) {
        err = filename + ":" + to_string(e.mark.line + 1) + ": " + e.what();
        return false;
    }

    out.rules = rules;
    return true;
}