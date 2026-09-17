#include "report_generator.hpp"
#include "commonfun.hpp"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>

std::string ReportGenerator::EscapeHtml(const std::string& raw) {
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

std::string ReportGenerator::GetCurrentTime() {
    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t);
    std::stringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

bool ReportGenerator::GenerateCheckHtml(const std::vector<CheckResult>& results,
                                        const std::string& output_path) {
    int total = results.size();
    int passed = std::count_if(results.begin(), results.end(),
                               [](const auto& r) { return r.passed; });
    int failed = total - passed;
    double pass_rate = total > 0 ? (passed * 100.0 / total) : 0.0;

    std::ofstream fs(output_path);
    if (!fs.is_open()) {
        return false;
    }

    fs << R"(<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>baseline-guard 基线核查报告</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;max-width:960px;margin:40px auto;padding:0 20px;color:#333}
h1{color:#1a1a1a;border-bottom:2px solid #0366d6;padding-bottom:10px}
.summary{display:flex;gap:20px;margin:20px 0}
.summary-box{flex:1;padding:20px;border-radius:8px;text-align:center}
.summary-box.total{background:#f6f8fa}
.summary-box.pass{background:#d4edda;color:#155724}
.summary-box.fail{background:#f8d7da;color:#721c24}
.summary-box h2{margin:0;font-size:36px}
.summary-box p{margin:5px 0 0;color:#666}
table{width:100%;border-collapse:collapse;margin:20px 0;font-size:14px}
th{background:#f6f8fa;padding:12px;text-align:left;border-bottom:2px solid #dfe2e5;font-weight:600}
td{padding:10px 12px;border-bottom:1px solid #eaecef}
tr:hover{background:#f6f8fa}
.status-pass{color:#28a745;font-weight:600}
.status-fail{color:#dc3545;font-weight:600}
.severity-critical{color:#dc3545}
.severity-high{color:#fd7e14}
.severity-medium{color:#ffc107}
.severity-low{color:#6c757d}
.footer{margin-top:40px;padding-top:20px;border-top:1px solid #eaecef;color:#666;font-size:12px;text-align:center}
</style>
</head>
<body>
<h1>🔒 baseline-guard 基线核查报告</h1>
<p>生成时间：)" << GetCurrentTime() << R"(</p>
<p>主机：)" << EscapeHtml(GetHostname()) << R"(</p>

<div class="summary">
<div class="summary-box total"><h2>)" << total << R"(</h2><p>检查项总数</p></div>
<div class="summary-box pass"><h2>)" << passed << R"(</h2><p>通过</p></div>
<div class="summary-box fail"><h2>)" << failed << R"(</h2><p>失败</p></div>
</div>

<p>通过率：<strong>)" << std::fixed << std::setprecision(1) << pass_rate << R"(%</strong></p>

<table>
<thead>
<tr>
<th>规则ID</th>
<th>规则名称</th>
<th>文件路径</th>
<th>预期值</th>
<th>实际值</th>
<th>状态</th>
<th>风险等级</th>
</tr>
</thead>
<tbody>
)";

    for (const auto& r : results) {
        std::string status_class = r.passed ? "status-pass" : "status-fail";
        std::string status_text = r.passed ? "✅ 通过" : "❌ 失败";
        std::string sev_class = "severity-" + r.severity;

        fs << "<tr>\n";
        fs << "<td>" << EscapeHtml(r.rule_id) << "</td>\n";
        fs << "<td>" << EscapeHtml(r.rule_name) << "</td>\n";
        fs << "<td><code>" << EscapeHtml(r.file_path) << "</code></td>\n";
        fs << "<td>" << EscapeHtml(r.expected) << "</td>\n";
        fs << "<td>" << EscapeHtml(r.actual) << "</td>\n";
        fs << "<td class=\"" << status_class << "\">" << status_text << "</td>\n";
        fs << "<td class=\"" << sev_class << "\">" << EscapeHtml(r.severity) << "</td>\n";
        fs << "</tr>\n";
    }

    fs << R"(</tbody>
</table>

<div class="footer">
<p>由 baseline-guard 自动生成 | https://github.com/xiaobaimao-linux/ebpf-baseline</p>
<p>如需技术支持，请联系：xiaobaimao-linux@proton.me</p>
</div>

</body>
</html>
)";

    fs.close();
    return true;
}





// 生成 monitor 原始事件 HTML 报告
bool ReportGenerator::GenerateMonitorEventsHtml(const std::vector<AlertRecord> &records,
                               const std::string &output_path, const std::string &start,
                               const std::string &end) {
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
<p>生成时间：)"
       << NowString() << R"(</p>
<p>主机：)"
       << EscapeHtml(GetHostname()) << R"(</p>
<p>筛选范围：)"
       << EscapeHtml(start.empty() ? "不限" : start) << " — "
       << EscapeHtml(end.empty() ? "不限" : end) << R"(</p>

<div class="summary">
<div class="summary-box"><h2>)"
       << total << R"(</h2><p>事件总数</p></div>
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

    for (const auto &r : records) {
        const std::string timestamp = NormalizeTimestamp(r.recorded_at);
        const std::string sev_class = SeverityClass(r.severity);
        const std::string details = r.expected.empty() || r.actual.empty()
                                        ? "-"
                                        : (EscapeHtml(r.expected) + " → " + EscapeHtml(r.actual));
        const std::string process = (r.process_name.empty() ? "-" : EscapeHtml(r.process_name)) +
                                    " (pid=" + (r.pid > 0 ? std::to_string(r.pid) : "-") + ")";
        const std::string user = EscapeHtml(r.user_name.empty() ? "-" : r.user_name) +
                                 " (uid=" + EscapeHtml(r.uid.empty() ? "-" : r.uid) + ")";

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

