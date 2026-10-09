#include "alert_manager.hpp"
#include "asset_collect.hpp"
#include "asset_list.hpp"
#include "baseline.hpp"
#include "baseline_check.hpp"
#include "baseline_clean.hpp"
#include "baseline_delete.hpp"
#include "baseline_list.hpp"
#include "baseline_snapshot.hpp"
#include "baseline_db.hpp"
#include "check.hpp"
#include "commonfun.hpp"
#include "config.hpp"
#include "logger.h"
#include "monitor.hpp"
#include "utils.hpp"
#include "report_generator.hpp"
#include "severity.hpp"
#include "stats.hpp"


#include "spdlog/spdlog.h"
#include <algorithm>
#include <cctype>
#include <ctime>
#include <fstream>
#include <getopt.h>
#include <iomanip>
#include <signal.h>
#include <sstream>
#include <stdio.h>
#include <string>
#include <unistd.h>

static volatile bool g_reload = false;

void sighup_handler(int) {
    g_reload = true;
}

namespace {

std::string ToUpper(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::toupper(ch)); });
    return value;
}

void PrintAlertsUsage() {
    printf("Usage: %s alerts [options]\n", "baseline-guard");
    printf("Options:\n");
    printf("  -n, --limit <num>     display the latest N alerts (default: 20)\n");
    printf("  --today               only show alerts from today\n");
    printf("  --rule=<name>         filter by rule_id/rule_name\n");
    printf("  --rule <name>         same as above\n");
    printf("  --severity <level>    filter by severity: critical/high/medium/low\n");
    printf("  --stats               aggregate alert counts by severity x rule_id\n");
    printf("  --since <window>      stats time window, e.g. 1h / 24h / 30m / 7d (only with --stats)\n");
}

void PrintReportUsage() {
    printf("Usage: %s report [--start <time>] [--end <time>] -o <file>\n", "baseline-guard");
    printf("Options:\n");
    printf("  --start <time>        inclusive start time\n");
    printf("  --end <time>          inclusive end time\n");
    printf("  -o, --output <file>   output HTML file (required)\n");
    printf("Time formats:\n");
    printf("  YYYY-MM-DD or YYYY-MM-DD HH:MM:SS (T may replace the space)\n");
    printf("Example:\n");
    printf("  baseline-guard report --start 2026-08-01 --end 2026-08-10 -o events.html\n");
}



std::string EscapeHtml(const std::string &raw) {
    std::string out;
    for (char c : raw) {
        switch (c) {
        case '&':
            out += "&amp;";
            break;
        case '<':
            out += "&lt;";
            break;
        case '>':
            out += "&gt;";
            break;
        case '"':
            out += "&quot;";
            break;
        default:
            out += c;
        }
    }
    return out;
}



bool NormalizeReportTime(const std::string &value, bool end_of_day, std::string &normalized) {
    std::string input = value;
    if (input.size() == 10) {
        input += end_of_day ? " 23:59:59" : " 00:00:00";
    } else if (input.size() == 19 && input[10] == 'T') {
        input[10] = ' ';
    }

    if (input.size() != 19 || input[4] != '-' || input[7] != '-' || input[10] != ' ' ||
        input[13] != ':' || input[16] != ':') {
        return false;
    }

    std::tm tm = {};
    std::istringstream ss(input);
    ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
    if (ss.fail()) {
        return false;
    }

    const int year = tm.tm_year;
    const int month = tm.tm_mon;
    const int day = tm.tm_mday;
    const int hour = tm.tm_hour;
    const int minute = tm.tm_min;
    const int second = tm.tm_sec;
    tm.tm_isdst = -1;
    const std::time_t timestamp = std::mktime(&tm);
    if (timestamp == static_cast<std::time_t>(-1)) {
        return false;
    }
    const std::tm verified = *std::localtime(&timestamp);
    if (verified.tm_year != year || verified.tm_mon != month || verified.tm_mday != day ||
        verified.tm_hour != hour || verified.tm_min != minute || verified.tm_sec != second) {
        return false;
    }

    normalized = input;
    return true;
}


void PrintAlerts(const std::vector<AlertRecord> &records) {
    if (records.empty()) {
        std::cout << "No alert records found." << std::endl;
        return;
    }

    for (const auto &record : records) {
        const std::string timestamp = NormalizeTimestamp(record.recorded_at);
        const std::string severity = ToUpper(record.severity);
        const std::string rule_name = record.rule_name.empty() ? record.rule_id : record.rule_name;
        const std::string event_desc = record.dingtalk_sent ? "" : "(节流跳过)";

        const std::string process_text = record.process_name.empty() ? "-" : record.process_name;
        const std::string pid_text =
            record.pid > 0 ? ("pid=" + std::to_string(record.pid)) : "pid=-";
        const std::string user_text =
            record.user_name.empty() ? (record.uid.empty() ? "-" : record.uid) : record.user_name;
        const std::string user_uid_text = record.uid.empty() ? "-" : record.uid;

        const std::string actual_text = record.actual.empty() ? "-" : record.actual;
        const std::string expected_text = record.expected.empty() ? "-" : record.expected;
        const std::string details =
            expected_text == "-" || actual_text == "-" ? "-" : (expected_text + "→" + actual_text);

        const std::string push_text = record.dingtalk_sent ? "✓已推送钉钉" : "✗未推送";

        std::cout << std::left << std::setw(19) << timestamp << "  [" << std::setw(8) << severity
                  << "]"
                  << "   " << std::setw(12) << rule_name << "   " << std::setw(16)
                  << record.file_path << "   " << std::setw(14)
                  << (record.event_type.empty() ? event_desc : record.event_type) << "   "
                  << std::setw(16) << (process_text + "(" + pid_text + ")") << "   "
                  << std::setw(14) << (user_text + "(" + user_uid_text + ")") << "   "
                  << std::setw(14) << details << "   " << push_text << std::endl;
    }
}

// --since 秒数 → 归一化时间下限（本地时间，与 DB 侧 recorded_at 归一化口径一致）
std::string CutoffTimeString(long long seconds_ago) {
    const std::time_t t = std::time(nullptr) - static_cast<std::time_t>(seconds_ago);
    char buf[32] = {};
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
    return buf;
}

// alerts --stats 输出：severity × rule_id 聚合计数表 + 合计行（供与表行数对账）
void PrintAlertStats(const std::vector<AlertStatRow> &rows, const std::string &since_spec) {
    if (since_spec.empty()) {
        std::cout << "Alert stats (all time)" << std::endl;
    } else {
        std::cout << "Alert stats (since " << since_spec << ")" << std::endl;
    }
    std::cout << std::left << std::setw(10) << "SEVERITY" << std::setw(44) << "RULE_ID"
              << "COUNT" << std::endl;
    long long total = 0;
    for (const auto &row : rows) {
        std::cout << std::left << std::setw(10) << row.severity << std::setw(44) << row.rule_id
                  << row.count << std::endl;
        total += row.count;
    }
    std::cout << std::left << std::setw(10) << "TOTAL" << std::setw(44) << "-" << total
              << std::endl;
}

} // namespace

int main(int argc, char *argv[]) {
    // baseline snapshot / delete / list / check / clean 使用独立参数解析，并在解析 --db 后再初始化数据库。
    if (argc >= 2 && std::string(argv[1]) == "baseline") {
        if (argc < 3) {
            fprintf(stderr, "Error: baseline subcommand required (snapshot, delete, list, check, clean)\n");
            return 2;
        }
        std::string subcmd = argv[2];
        if (subcmd == "snapshot") {
            return RunBaselineSnapshot(argc - 3, argv + 3);
        } else if (subcmd == "delete") {
            return RunBaselineDelete(argc - 3, argv + 3);
        } else if (subcmd == "list") {
            return RunBaselineList(argc - 3, argv + 3);
        } else if (subcmd == "check") {
            return RunBaselineCheck(argc - 3, argv + 3);
        } else if (subcmd == "clean") {
            return RunBaselineClean(argc - 3, argv + 3);
        } else {
            fprintf(stderr, "Error: unknown baseline subcommand: %s\n", subcmd.c_str());
            return 2;
        }
    }

    // stats 子命令：读取 eBPF map 统计信息（独立于 config/DB）
    if (argc >= 2 && std::string(argv[1]) == "stats") {
        return RunStats(argc - 2, argv + 2);
    }

    // asset collect / list 子命令（M1-2）：独立于 config，使用独立参数解析
    if (argc >= 2 && std::string(argv[1]) == "asset") {
        if (argc < 3) {
            fprintf(stderr, "Error: asset subcommand required (collect, list)\n");
            return 2;
        }
        const std::string subcmd = argv[2];
        if (subcmd == "collect") {
            return RunAssetCollect(argc - 3, argv + 3);
        } else if (subcmd == "list") {
            return RunAssetList(argc - 3, argv + 3);
        } else {
            fprintf(stderr, "Error: unknown asset subcommand: %s\n", subcmd.c_str());
            return 2;
        }
    }

    // 设置全局日志级别（默认是 info，低于它的 debug/trace 不会输出）
    spdlog::set_level(spdlog::level::debug);

    // 2. 延迟初始化数据库（仅在需要时创建）
    BaselineDB* db_ptr = nullptr;
    auto get_db = [&db_ptr]() -> BaselineDB& {
        if (!db_ptr) {
            db_ptr = new BaselineDB();
        }
        return *db_ptr;
    };

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
            printf("  baseline snapshot     create or update file baselines\n");
            printf("  baseline delete       delete file baseline entries\n");
            printf("  baseline list         list file baseline entries\n");
            printf("  baseline check        check baseline integrity against disk\n");
            printf("  baseline clean        clean orphan baseline entries\n");
            printf("  alerts                show alert history from SQLite\n");
            printf("  report                export monitor events to HTML\n");
            printf("  asset collect         collect host assets into SQLite\n");
            printf("  asset list            list host assets (--type/--json)\n");
            printf("  stats --drop          show eBPF ring buffer drop statistics\n");
            return 0;
        } else if (arg == "-C" || arg == "--check") {
            cmd = "check";
            spdlog::debug("command is : check");
        } else if (arg == "-m" || arg == "--monitor") {
            cmd = "monitor";
            spdlog::debug("command is : monitor");
        } else if (arg == "report") {
            std::string start;
            std::string end;
            std::string output_path;
            int j = i + 1;
            while (j < argc) {
                const std::string subarg = argv[j];
                if (subarg == "-h" || subarg == "--help") {
                    PrintReportUsage();
                    return 0;
                } else if (subarg == "-o" || subarg == "--output") {
                    if (j + 1 >= argc) {
                        fprintf(stderr, "Error: missing value for %s\n", subarg.c_str());
                        return 1;
                    }
                    output_path = argv[++j];
                } else if (subarg.rfind("--output=", 0) == 0) {
                    output_path = subarg.substr(std::string("--output=").size());
                } else if (subarg == "--start" || subarg == "--end") {
                    if (j + 1 >= argc) {
                        fprintf(stderr, "Error: missing value for %s\n", subarg.c_str());
                        return 1;
                    }
                    const std::string value = argv[++j];
                    std::string normalized;
                    if (!NormalizeReportTime(value, subarg == "--end", normalized)) {
                        fprintf(stderr, "Error: invalid time for %s: %s\n", subarg.c_str(),
                                value.c_str());
                        return 1;
                    }
                    (subarg == "--start" ? start : end) = normalized;
                } else if (subarg.rfind("--start=", 0) == 0 || subarg.rfind("--end=", 0) == 0) {
                    const bool is_end = subarg.rfind("--end=", 0) == 0;
                    const std::string value = subarg.substr(is_end ? 6 : 8);
                    std::string normalized;
                    if (!NormalizeReportTime(value, is_end, normalized)) {
                        fprintf(stderr, "Error: invalid time: %s\n", value.c_str());
                        return 1;
                    }
                    (is_end ? end : start) = normalized;
                } else {
                    fprintf(stderr, "Error: unknown report option: %s\n", subarg.c_str());
                    return 1;
                }
                ++j;
            }

            if (output_path.empty()) {
                fprintf(stderr, "Error: output file required (-o <file>)\n");
                return 1;
            }
            if (!start.empty() && !end.empty() && start > end) {
                fprintf(stderr, "Error: --start must not be later than --end\n");
                return 1;
            }

            const auto events = get_db().GetMonitorEvents(start, end);
            ReportGenerator rg;
            if (!rg.GenerateMonitorEventsHtml(events, output_path, start, end)) {
                fprintf(stderr, "Error: failed to generate HTML report: %s\n", output_path.c_str());
                return 1;
            }
            std::cout << "Monitor event report generated: " << output_path << std::endl;
            std::cout << "Total events: " << events.size() << std::endl;
            return 0;
        } else if (arg == "alerts") {
            cmd = arg;
            int j = i + 1;
            bool today = false;
            int limit = 20;
            std::string rule;
            std::string severity;
            bool stats = false;
            std::string since_spec;
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
                } else if (subarg == "--stats") {
                    stats = true;
                } else if (subarg.rfind("--since=", 0) == 0) {
                    since_spec = subarg.substr(std::string("--since=").size());
                } else if (subarg == "--since") {
                    if (j + 1 >= argc) {
                        fprintf(stderr, "Error: missing value for --since\n");
                        return 1;
                    }
                    since_spec = argv[++j];
                } else if (subarg.rfind("--severity=", 0) == 0) {
                    severity = subarg.substr(std::string("--severity=").size());
                } else if (subarg == "--severity") {
                    if (j + 1 >= argc) {
                        fprintf(stderr, "Error: missing value for --severity\n");
                        return 1;
                    }
                    severity = argv[++j];
                } else if (subarg == "--report_html") {
                    fprintf(
                        stderr,
                        "Error: --report_html has moved; use baseline-guard report -o <file>\n");
                    return 1;
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
                } else if (subarg.size() > 0 &&
                           std::all_of(subarg.begin(), subarg.end(),
                                       [](unsigned char c) { return std::isdigit(c); })) {
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
                    fprintf(stderr, "Error: unknown alerts option: %s\n", subarg.c_str());
                    return 1;
                }
                ++j;
            }

            if (!severity.empty() && !alert::SeverityIsValid(severity)) {
                fprintf(stderr, "Error: invalid severity: %s (critical/high/medium/low)\n",
                        severity.c_str());
                return 1;
            }
            if (!since_spec.empty() && !stats) {
                fprintf(stderr, "Error: --since is only valid with --stats\n");
                return 1;
            }
            if (stats) {
                std::string cutoff;
                if (!since_spec.empty()) {
                    long long seconds = 0;
                    if (!ParseSinceSpec(since_spec, seconds)) {
                        fprintf(stderr,
                                "Error: invalid --since window: %s (e.g. 1h / 24h / 30m / 7d)\n",
                                since_spec.c_str());
                        return 1;
                    }
                    cutoff = CutoffTimeString(seconds);
                }
                PrintAlertStats(get_db().GetAlertStats(cutoff, severity), since_spec);
                return 0;
            }

            const auto alerts = get_db().GetAlerts(rule, severity, limit, today);
            PrintAlerts(alerts);
            return 0;
        } else if (arg == "monitor") {
            // 解析 monitor 子命令的参数
            std::string monitor_db_path;
            bool skip_boot_check = false;
            int j = i + 1;
            while (j < argc) {
                std::string subarg = argv[j];
                if (subarg == "--db") {
                    if (j + 1 >= argc) {
                        fprintf(stderr, "Error: missing value for --db\n");
                        return 1;
                    }
                    monitor_db_path = argv[++j];
                } else if (subarg.rfind("--db=", 0) == 0) {
                    monitor_db_path = subarg.substr(5);
                } else if (subarg == "-c" || subarg == "--config") {
                    if (j + 1 >= argc) {
                        fprintf(stderr, "Error: missing value for -c\n");
                        return 1;
                    }
                    config_path = argv[++j];
                } else if (subarg.rfind("--config=", 0) == 0) {
                    config_path = subarg.substr(std::string("--config=").size());
                } else if (subarg == "--skip-boot-baseline-check") {
                    skip_boot_check = true;
                } else if (subarg == "-h" || subarg == "--help") {
                    printf("Usage: baseline-guard monitor [options]\n");
                    printf("Options:\n");
                    printf("  --db PATH    SQLite baseline DB path (enables baseline comparison)\n");
                    printf("  --skip-boot-baseline-check   skip full baseline check at startup\n");
                    printf("  -c PATH      YAML config file (optional when --db is used)\n");
                    printf("  -h, --help   display this message\n");
                    return 0;
                } else {
                    fprintf(stderr, "Error: unknown monitor option: %s\n", subarg.c_str());
                    return 1;
                }
                ++j;
            }

            if (monitor_db_path.empty()) {
                // 无 --db: 走原有 YAML 监控流程（需要 -c config）
                cmd = "monitor";
            } else {
                // 有 --db: 先检查数据库文件是否存在，避免启动后才报错
                if (access(monitor_db_path.c_str(), R_OK) != 0) {
                    fprintf(stderr, "Error: baseline DB not found or not readable: %s\n",
                            monitor_db_path.c_str());
                    return 1;
                }

                // 直接执行基线实时监控
                Logger::init("/var/log/baseline-guard");
                spdlog::info("[service_start] baseline-guard monitor --db {} starting, pid={}",
                             monitor_db_path, getpid());

                Config config;
                if (!config_path.empty()) {
                    if (!ends_with(config_path, ".yaml") && !ends_with(config_path, ".yml")) {
                        spdlog::error("[config_error] only yaml/yml config is supported now: {}", config_path);
                        return 1;
                    }
                    // M0-2：冷启动严格解析（坏配置带行号报错退出，不给空规则运行）
                    std::string parse_err;
                    if (!tryParseYamlFile(config_path, config, parse_err)) {
                        spdlog::error("[config_error] {}", parse_err);
                        return 1;
                    }
                    compute_inodes(config);
                    spdlog::info("[rules_loaded] config={}, rules={}", config_path, config.rules.size());
                }

                AlertManager alert_mgr;
                if (!config_path.empty()) {
                    alert_mgr.LoadConfig(config.alert, config.db);
                    alert_mgr.UpdateNotifyConfig(config.notify);
                }
                BaselineDB alert_db;  // 使用默认路径
                alert_mgr.SetDB(&alert_db);

                if (alert_mgr.IsEnabled()) {
                    spdlog::info("DingTalk alert enabled, throttle={}s", config.alert.throttle_seconds);
                }

                signal(SIGHUP, sighup_handler);
                int ret = 0;
                while (true) {
                    ret = do_monitor(config, alert_mgr, config_path, monitor_db_path, skip_boot_check);
                    if (!g_reload) {
                        break;
                    }
                    g_reload = false;
                    if (!config_path.empty()) {
                        spdlog::info("[rules_reload] SIGHUP received, reloading config from {}", config_path);
                        config = parseYamlFile(config_path);
                        compute_inodes(config);
                        spdlog::info("[rules_reload] config reloaded, rules={}", config.rules.size());
                    }
                }
                spdlog::info("[service_stop] monitor mode stopped, exit_code={}", ret);
                return ret;
            }
        } else if (cmd.empty()) {
            cmd = arg;
        } else {
            break;
        }
        ++i;
    }

    if (cmd == "alerts") {
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

    Logger::init("/var/log/baseline-guard");
    spdlog::info("[service_start] baseline-guard starting, pid={}", getpid());

    Config config;
    if (!ends_with(config_path, ".yaml") && !ends_with(config_path, ".yml")) {
        spdlog::error("[config_error] only yaml/yml config is supported now: {}", config_path);
        return 1;
    }

    config = parseYamlFile(config_path);

    spdlog::info("[rules_loaded] config={}, format=yaml, rules={}", config_path,
                 config.rules.size());

    printRules(config.rules);

    AlertManager alert_mgr;
    alert_mgr.LoadConfig(config.alert, config.db);
    alert_mgr.UpdateNotifyConfig(config.notify);
    alert_mgr.SetDB(&get_db());

    if (alert_mgr.IsEnabled()) {
        spdlog::info("DingTalk alert enabled, throttle={}s", config.alert.throttle_seconds);
    } else {
        spdlog::warn("DingTalk alert NOT configured (alerts will still be persisted to DB)");
    }
    spdlog::info("Alert retention: {} days, max {} records", config.db.retention_days,
                 config.db.retention_max_records);

    compute_inodes(config);

    if (cmd == "check") {
        spdlog::info("[service_start] check mode started");
        int ret = do_check(config, get_db());
        spdlog::info("[service_stop] check mode finished, exit_code={}", ret);
        return ret;
    } else if (cmd == "monitor") {
        // M0-2：冷启动严格解析（坏配置带行号报错退出，不给空规则运行）；
        // check 等命令仍走上方 lenient 解析，行为不变
        std::string parse_err;
        if (!tryParseYamlFile(config_path, config, parse_err)) {
            spdlog::error("[config_error] {}", parse_err);
            return 1;
        }
        compute_inodes(config);
        spdlog::info("[rules_loaded] config={}, rules={}", config_path, config.rules.size());

        signal(SIGHUP, sighup_handler);
        spdlog::info("[service_start] monitor mode started");

        int ret = 0;
        while (true) {
            ret = do_monitor(config, alert_mgr, config_path);
            if (!g_reload) {
                break;
            }
            g_reload = false;
            spdlog::info("[rules_reload] SIGHUP received, reloading config from {}", config_path);

            Config reloaded;
            if (tryParseYamlFile(config_path, reloaded, parse_err)) {
                config = std::move(reloaded);
                compute_inodes(config);
                spdlog::info("[rules_reload] config reloaded, rules={}", config.rules.size());
            } else {
                spdlog::error("[rules_reload] 失败，保留旧配置: {}", parse_err);
            }
        }

        spdlog::info("[service_stop] monitor mode stopped, exit_code={}", ret);
        return ret;
    } else {
        spdlog::error("Unknown command: {}", cmd);
        return 1;
    }
}
