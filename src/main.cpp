#include "baseline.hpp"
#include "check.hpp"
#include "config.hpp"
#include "monitor.hpp"
#include "utils.hpp"
#include "commonfun.hpp"
#include "logger.h"
#include "baseline_db.hpp"
#include "alert_manager.hpp"

#include "spdlog/spdlog.h"
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <string>

static volatile bool g_reload = false;

void sighup_handler(int) {
    g_reload = true;
}

namespace {

std::string ToUpper(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });
    return value;
}

void PrintAlertsUsage() {
    printf("Usage: %s alerts [options]\n", "baseline-guard");
    printf("Options:\n");
    printf("  -n, --limit <num>     display the latest N alerts (default: 20)\n");
    printf("  --today               only show alerts from today\n");
    printf("  --rule=<name>         filter by rule_id/rule_name\n");
    printf("  --rule <name>         same as above\n");
}

std::string NormalizeTimestamp(const std::string& timestamp) {
    if (timestamp.size() >= 19 && timestamp[4] == '-' && timestamp[7] == '-') {
        return timestamp;
    }

    if (timestamp.size() >= 17 && timestamp[8] == '-') {
        return timestamp.substr(0, 4) + "-" + timestamp.substr(4, 2) + "-" + timestamp.substr(6, 2)
               + " " + timestamp.substr(9, 2) + ":" + timestamp.substr(12, 2) + ":" + timestamp.substr(15, 2);
    }

    return timestamp;
}

void PrintAlerts(const std::vector<AlertRecord>& records) {
    if (records.empty()) {
        std::cout << "No alert records found." << std::endl;
        return;
    }

    for (const auto& record : records) {
        const std::string timestamp = NormalizeTimestamp(record.recorded_at);
        const std::string severity = ToUpper(record.severity);
        const std::string rule_name = record.rule_name.empty() ? record.rule_id : record.rule_name;
        const std::string event_desc = record.dingtalk_sent ? "" : "(节流跳过)";

        const std::string process_text = record.process_name.empty()
            ? "-"
            : record.process_name;
        const std::string pid_text = record.pid > 0
            ? ("pid=" + std::to_string(record.pid))
            : "pid=-";
        const std::string user_text = record.user_name.empty()
            ? (record.uid.empty() ? "-" : record.uid)
            : record.user_name;
        const std::string user_uid_text = record.uid.empty()
            ? "-"
            : record.uid;

        const std::string actual_text = record.actual.empty() ? "-" : record.actual;
        const std::string expected_text = record.expected.empty() ? "-" : record.expected;
        const std::string details = expected_text == "-" || actual_text == "-"
            ? "-"
            : (expected_text + "→" + actual_text);

        const std::string push_text = record.dingtalk_sent
            ? "✓已推送钉钉"
            : "✗未推送";

        std::cout << std::left
                  << std::setw(19) << timestamp
                  << "  [" << std::setw(5) << severity << "]"
                  << "   " << std::setw(12) << rule_name
                  << "   " << std::setw(16) << record.file_path
                  << "   " << std::setw(14) << (record.event_type.empty() ? event_desc : record.event_type)
                  << "   " << std::setw(16) << (process_text + "(" + pid_text + ")")
                  << "   " << std::setw(14) << (user_text + "(" + user_uid_text + ")")
                  << "   " << std::setw(14) << details
                  << "   " << push_text
                  << std::endl;
    }
}

} // namespace

int main(int argc, char* argv[]) {
    // 设置全局日志级别（默认是 info，低于它的 debug/trace 不会输出）
    spdlog::set_level(spdlog::level::debug);

    // 2. 初始化数据库
    BaselineDB db;

    std::string config_path;
    std::string cmd;

    int i = 1;
    while (i < argc) {
        std::string arg = argv[i];

        if (arg == "-c" || arg == "--config") {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: missing config path after %s\n", arg.c_str());
                return 1;
            }
            config_path = argv[++i];
        } else if (arg.rfind("--config=", 0) == 0) {
            config_path = arg.substr(std::string("--config=").size());
        } else if (arg == "-h" || arg == "--help") {
            printf("Usage: %s [options] [command]\n", argv[0]);
            printf("Options:\n");
            printf("  -c, --config <path>   config file path\n");
            printf("  -h, --help            display this message\n");
            printf("Commands:\n");
            printf("  --check               check baseline\n");
            printf("  --monitor             monitor baseline\n");
            printf("  alerts                show alert history from SQLite\n");
            return 0;
        } else if (arg == "-C" || arg == "--check") {
            cmd = "check";
            spdlog::debug("command is : check");
        } else if (arg == "-m" || arg == "--monitor") {
            cmd = "monitor";
            spdlog::debug("command is : monitor");
        } else if (arg == "alerts") {
            cmd = arg;
            int j = i + 1;
            bool today = false;
            int limit = 20;
            std::string rule;
            while (j < argc) {
                std::string subarg = argv[j];
                if (subarg == "-n" || subarg == "--limit") {
                    if (j + 1 >= argc) {
                        fprintf(stderr, "Error: missing value for %s\n", subarg.c_str());
                        return 1;
                    }
                    try {
                        limit = std::stoi(argv[++j]);
                        if (limit < 1) {
                            limit = 20;
                        }
                    } catch (...) {
                        fprintf(stderr, "Error: invalid numeric value for %s\n", argv[j]);
                        return 1;
                    }
                } else if (subarg == "--today") {
                    today = true;
                } else if (subarg.rfind("--rule=", 0) == 0) {
                    rule = subarg.substr(std::string("--rule=").size());
                } else if (subarg == "--rule") {
                    if (j + 1 >= argc) {
                        fprintf(stderr, "Error: missing value for --rule\n");
                        return 1;
                    }
                    rule = argv[++j];
                } else if (subarg == "-h" || subarg == "--help") {
                    PrintAlertsUsage();
                    return 0;
                } else if (subarg.size() > 0 && std::all_of(subarg.begin(), subarg.end(), [](unsigned char c) {
                    return std::isdigit(c);
                })) {
                    try {
                        const int parsed_limit = std::stoi(subarg);
                        if (parsed_limit > 0) {
                            limit = parsed_limit;
                        }
                    } catch (...) {
                        fprintf(stderr, "Error: invalid numeric value for %s\n", subarg.c_str());
                        return 1;
                    }
                } else {
                    break;
                }
                ++j;
            }

            auto alerts = db.GetAlerts(rule, limit, today);
            PrintAlerts(alerts);
            return 0;
        } else if (cmd.empty()) {
            cmd = arg;
        } else {
            // 当已有命令时，剩余参数忽略处理，避免影响旧格式
            break;
        }
        ++i;
    }

    // 验证
    if (cmd == "alerts") {
        // alerts 已经在扫描过程中直接处理完毕
        return 0;
    }

    if (config_path.empty()) {
        fprintf(stderr, "Error: config file required (-c <path>)\n");
        return 1;
    }

    if (cmd.empty()) {
        fprintf(stderr, "Error: command required (check or monitor)\n");
        return 1;
    }

    // 1. 初始化日志（仅服务型命令才需要）
    Logger::init("/var/log/baseline-guard");

    spdlog::info("[service_start] baseline-guard starting, pid={}", getpid());

    Config config;
    if (!ends_with(config_path, ".yaml") && !ends_with(config_path, ".yml")) {
        spdlog::error("[config_error] only yaml/yml config is supported now: {}", config_path);
        return 1;
    }

    config = parseYamlFile(config_path);

    spdlog::info("[rules_loaded] config={}, format=yaml, rules={}",
                 config_path,
                 config.rules.size());

    // 打印结果
    printRules(config.rules);

    AlertManager alert_mgr;
    alert_mgr.LoadConfig(config.alert, config.db);  // alert + db 分开配置
    alert_mgr.SetDB(&db);  // 绑定数据库，所有告警统一落库

    if (alert_mgr.IsEnabled()) {
        spdlog::info("DingTalk alert enabled, throttle={}s", config.alert.throttle_seconds);
    } else {
        spdlog::warn("DingTalk alert NOT configured (alerts will still be persisted to DB)");
    }
    spdlog::info("Alert retention: {} days, max {} records",
                 config.db.retention_days, config.db.retention_max_records);

    compute_inodes(config);

    if (cmd == "check") {
        spdlog::info("[service_start] check mode started");
        int ret = do_check(config, db);
        spdlog::info("[service_stop] check mode finished, exit_code={}", ret);
        return ret;
    } else if (cmd == "monitor") {
        // 注册 SIGHUP 用于配置重载
        signal(SIGHUP, sighup_handler);
        spdlog::info("[service_start] monitor mode started");

        int ret = 0;
        while (true) {
            ret = do_monitor(config, alert_mgr);
            if (!g_reload) {
                break;
            }
            g_reload = false;
            spdlog::info("[rules_reload] SIGHUP received, reloading config from {}", config_path);

            config = parseYamlFile(config_path);
            compute_inodes(config);

            spdlog::info("[rules_reload] config reloaded, rules={}", config.rules.size());
        }

        spdlog::info("[service_stop] monitor mode stopped, exit_code={}", ret);
        return ret;
    } else {
        spdlog::error("未知命令: {}", cmd);
        return 1;
    }
}