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
#include <fstream>
#include <ctime>

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

std::string EscapeHtml(const std::string& raw) {
    std::string out;
    for (char c : raw) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            default: out += c;
        }
    }
    return out;
}

std::string GetCurrentTimeForHtml() {
    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t);
    std::stringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

bool NormalizeReportTime(const std::string& value, bool end_of_day, std::string& normalized) {
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

std::string SeverityClass(const std::string& severity) {
    if (severity == "critical" || severity == "high" ||
        severity == "medium" || severity == "low") {
        return "severity-" + severity;
    }
    return "";
}

// 生成 monitor 原始事件 HTML 报告
bool GenerateMonitorEventsHtml(const std::vector<AlertRecord>& records,
                               const std::string& output_path,
                               const std::string& start,
                               const std::string& end) {
    const int total = static_cast<int>(records.size());

    std::ofstream fs(output_path);
    if (!fs.is_open()) {
        return false;
    }

    fs << R"(<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>baseline-guard monitor 事件报告</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;max-width:1400px;margin:40px auto;padding:0 20px;color:#333}
h1{color:#1a1a1a;border-bottom:2px solid #dc3545;padding-bottom:10px}
.summary{display:flex;gap:20px;margin:20px 0}
.summary-box{padding:20px 40px;border-radius:8px;text-align:center;background:#f6f8fa}
table{width:100%;border-collapse:collapse;margin:20px 0;font-size:13px}
th{background:#f6f8fa;padding:12px;text-align:left;border-bottom:2px solid #dfe2e5;font-weight:600;white-space:nowrap}
td{padding:10px 12px;border-bottom:1px solid #eaecef}
tr:hover{background:#f6f8fa}
.severity-critical{color:#dc3545;font-weight:bold}
.severity-high{color:#fd7e14;font-weight:bold}
.severity-medium{color:#b8860b}
.severity-low{color:#6c757d}
.footer{margin-top:40px;padding-top:20px;border-top:1px solid #eaecef;color:#666;font-size:12px;text-align:center}
</style>
</head>
<body>
<h1>baseline-guard monitor 事件报告</h1>
<p>生成时间：)" << GetCurrentTimeForHtml() << R"(</p>
<p>主机：)" << EscapeHtml(GetHostname()) << R"(</p>
<p>筛选范围：)" << EscapeHtml(start.empty() ? "不限" : start)
       << " — " << EscapeHtml(end.empty() ? "不限" : end) << R"(</p>

<div class="summary">
<div class="summary-box"><h2>)" << total << R"(</h2><p>事件总数</p></div>
</div>

<table>
<thead>
<tr>
<th>时间</th>
<th>规则ID</th>
<th>规则名称</th>
<th>严重级别</th>
<th>文件路径</th>
<th>事件类型</th>
<th>进程/PID</th>
<th>用户/UID</th>
<th>预期→实际</th>
<th>动作</th>
</tr>
</thead>
<tbody>
)";

    for (const auto& r : records) {
        const std::string timestamp = NormalizeTimestamp(r.recorded_at);
        const std::string sev_class = SeverityClass(r.severity);
        const std::string details = r.expected.empty() || r.actual.empty()
            ? "-"
            : (EscapeHtml(r.expected) + " → " + EscapeHtml(r.actual));
        const std::string process = (r.process_name.empty() ? "-" : EscapeHtml(r.process_name))
            + " (pid=" + (r.pid > 0 ? std::to_string(r.pid) : "-") + ")";
        const std::string user = EscapeHtml(r.user_name.empty() ? "-" : r.user_name)
            + " (uid=" + EscapeHtml(r.uid.empty() ? "-" : r.uid) + ")";

        fs << "<tr>\n";
        fs << "<td>" << EscapeHtml(timestamp) << "</td>\n";
        fs << "<td><code>" << EscapeHtml(r.rule_id) << "</code></td>\n";
        fs << "<td>" << EscapeHtml(r.rule_name.empty() ? "-" : r.rule_name) << "</td>\n";
        fs << "<td class=\"" << sev_class << "\">" << EscapeHtml(r.severity) << "</td>\n";
        fs << "<td><code>" << EscapeHtml(r.file_path) << "</code></td>\n";
        fs << "<td>" << EscapeHtml(r.event_type.empty() ? "-" : r.event_type) << "</td>\n";
        fs << "<td>" << process << "</td>\n";
        fs << "<td>" << user << "</td>\n";
        fs << "<td>" << details << "</td>\n";
        fs << "<td>" << EscapeHtml(r.action_taken.empty() ? "-" : r.action_taken) << "</td>\n";
        fs << "</tr>\n";
    }

    fs << R"(</tbody>
</table>

<div class="footer">
<p>由 baseline-guard 自动生成 | https://github.com/xiaobaimao-linux/ebpf-baseline</p>
</div>

</body>
</html>
)";

    fs.close();
    return true;
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
            printf("  report                export monitor events to HTML\n");
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
                        fprintf(stderr, "Error: invalid time for %s: %s\n", subarg.c_str(), value.c_str());
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

            const auto events = db.GetMonitorEvents(start, end);
            if (!GenerateMonitorEventsHtml(events, output_path, start, end)) {
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
                } else if (subarg == "--report_html") {
                    fprintf(stderr, "Error: --report_html has moved; use baseline-guard report -o <file>\n");
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
                    fprintf(stderr, "Error: unknown alerts option: %s\n", subarg.c_str());
                    return 1;
                }
                ++j;
            }

            const auto alerts = db.GetAlerts(rule, limit, today);
            PrintAlerts(alerts);
            return 0;
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

    spdlog::info("[rules_loaded] config={}, format=yaml, rules={}",
                 config_path,
                 config.rules.size());

    printRules(config.rules);

    AlertManager alert_mgr;
    alert_mgr.LoadConfig(config.alert, config.db);
    alert_mgr.SetDB(&db);

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
        spdlog::error("Unknown command: {}", cmd);
        return 1;
    }
}
