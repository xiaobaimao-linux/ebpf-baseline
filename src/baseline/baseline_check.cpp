#include "baseline_check.hpp"

#include "baseline_db.hpp"
#include "utils.hpp"

#include <sys/stat.h>

#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {
namespace fs = std::filesystem;

struct CheckOptions {
    std::string db_path = "/var/lib/baseline-guard/baseline.db";
    std::string output_file;  // HTML report path; empty = console only
};

enum class CheckStatus { ok, file_missing, baseline_tamper };

struct CheckFinding {
    std::string file_path;
    CheckStatus status = CheckStatus::ok;
    std::vector<std::string> diffs;  // human-readable diff items
};

std::string NowIso() {
    const auto now = std::chrono::system_clock::now();
    const auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::localtime(&time);
    char buffer[32] = {};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &tm);
    return buffer;
}

std::string EscapeHtml(const std::string& raw) {
    std::string out;
    for (char c : raw) {
        switch (c) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            default:   out += c;
        }
    }
    return out;
}

void PrintUsage() {
    std::cout << "Usage: baseline-guard baseline check [options]\n"
              << "Offline baseline integrity check: compare disk files against baseline entries.\n"
              << "\n"
              << "Options:\n"
              << "  --db PATH             SQLite database path\n"
              << "  -o, --output FILE     output HTML audit report file path\n"
              << "  -h, --help            display this message\n"
              << "\n"
              << "Examples:\n"
              << "  baseline-guard baseline check\n"
              << "  baseline-guard baseline check --db baseline.db\n"
              << "  baseline-guard baseline check -o ./check-report.html\n";
}

bool ParseOptions(int argc, char* argv[], CheckOptions& options, bool& help,
                  std::string& error) {
    for (int i = 0; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            help = true;
            return true;
        }
        auto take_value = [&](const std::string& option, std::string& target) {
            if (i + 1 >= argc) {
                error = "missing value for " + option;
                return false;
            }
            target = argv[++i];
            return true;
        };
        if (arg == "--db") {
            if (!take_value(arg, options.db_path)) return false;
        } else if (arg.rfind("--db=", 0) == 0) {
            options.db_path = arg.substr(5);
        } else if (arg == "-o" || arg == "--output") {
            if (!take_value(arg, options.output_file)) return false;
        } else if (arg.rfind("--output=", 0) == 0) {
            options.output_file = arg.substr(9);
        } else {
            error = "unknown check option: " + arg;
            return false;
        }
    }
    if (options.db_path.empty()) {
        error = "--db must not be empty";
        return false;
    }
    return true;
}

// Compare disk file against baseline entry, return finding
CheckFinding CheckOneEntry(const CheckEntry& entry) {
    CheckFinding finding;
    finding.file_path = entry.file_path;

    struct stat st = {};
    if (lstat(entry.file_path.c_str(), &st) != 0) {
        finding.status = CheckStatus::file_missing;
        finding.diffs.push_back("file does not exist on disk");
        return finding;
    }

    // Compare hash
    std::string actual_hash;
    try {
        actual_hash = compute_sha256(entry.file_path);
    } catch (const std::exception& ex) {
        finding.status = CheckStatus::baseline_tamper;
        finding.diffs.push_back(std::string("hash compute error: ") + ex.what());
        return finding;
    }
    if (actual_hash != entry.hash) {
        finding.diffs.push_back("hash mismatch (expected: " + entry.hash.substr(0, 16) +
                                "..., actual: " + actual_hash.substr(0, 16) + "...)");
    }

    // Compare permission
    std::string actual_perm = mode_to_string(st.st_mode & 0777);
    if (actual_perm != entry.permission) {
        finding.diffs.push_back("permission changed (expected: " + entry.permission +
                                ", actual: " + actual_perm + ")");
    }

    // Compare uid
    if (static_cast<int64_t>(st.st_uid) != entry.uid) {
        finding.diffs.push_back("uid changed (expected: " + std::to_string(entry.uid) +
                                ", actual: " + std::to_string(st.st_uid) + ")");
    }

    // Compare gid
    if (static_cast<int64_t>(st.st_gid) != entry.gid) {
        finding.diffs.push_back("gid changed (expected: " + std::to_string(entry.gid) +
                                ", actual: " + std::to_string(st.st_gid) + ")");
    }

    // Compare mtime
    if (static_cast<int64_t>(st.st_mtime) != entry.mtime) {
        finding.diffs.push_back("mtime changed (expected: " + std::to_string(entry.mtime) +
                                ", actual: " + std::to_string(st.st_mtime) + ")");
    }

    if (!finding.diffs.empty()) {
        finding.status = CheckStatus::baseline_tamper;
    }
    return finding;
}

// Print console summary
void PrintConsoleSummary(const std::vector<CheckFinding>& findings,
                         const std::string& db_path) {
    int ok_count = 0, missing_count = 0, tamper_count = 0;
    for (const auto& f : findings) {
        switch (f.status) {
            case CheckStatus::ok:            ++ok_count;     break;
            case CheckStatus::file_missing:  ++missing_count; break;
            case CheckStatus::baseline_tamper: ++tamper_count; break;
        }
    }
    int total = static_cast<int>(findings.size());

    std::cout << "=== Baseline Check Summary ===\n"
              << "Database: " << db_path << "\n"
              << "Checked at: " << NowIso() << "\n"
              << "\n"
              << "Total entries: " << total << "\n"
              << "  OK:              " << ok_count << "\n"
              << "  File missing:    " << missing_count << "\n"
              << "  Baseline tamper: " << tamper_count << "\n";

    // Print details for non-ok entries
    bool has_issues = (missing_count + tamper_count) > 0;
    if (has_issues) {
        std::cout << "\n--- Issues ---\n";
        for (const auto& f : findings) {
            if (f.status == CheckStatus::ok) continue;
            std::string status_str = (f.status == CheckStatus::file_missing)
                                         ? "MISSING"
                                         : "TAMPER";
            std::cout << "[" << status_str << "] " << f.file_path << "\n";
            for (const auto& diff : f.diffs) {
                std::cout << "  - " << diff << "\n";
            }
        }
    } else {
        std::cout << "\nAll baseline entries are consistent. No issues found.\n";
    }
}

// Generate HTML report
bool GenerateCheckHtml(const std::vector<CheckFinding>& findings,
                       const std::string& output_path,
                       const std::string& db_path) {
    int ok_count = 0, missing_count = 0, tamper_count = 0;
    for (const auto& f : findings) {
        switch (f.status) {
            case CheckStatus::ok:            ++ok_count;     break;
            case CheckStatus::file_missing:  ++missing_count; break;
            case CheckStatus::baseline_tamper: ++tamper_count; break;
        }
    }
    int total = static_cast<int>(findings.size());
    double pass_rate = total > 0 ? (ok_count * 100.0 / total) : 0.0;

    std::ofstream fs(output_path);
    if (!fs.is_open()) {
        return false;
    }

    fs << R"(<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>baseline-guard 基线一致性核查报告</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;max-width:960px;margin:40px auto;padding:0 20px;color:#333}
h1{color:#1a1a1a;border-bottom:2px solid #0366d6;padding-bottom:10px}
.summary{display:flex;gap:20px;margin:20px 0}
.summary-box{flex:1;padding:20px;border-radius:8px;text-align:center}
.summary-box.total{background:#f6f8fa}
.summary-box.ok{background:#d4edda;color:#155724}
.summary-box.missing{background:#fff3cd;color:#856404}
.summary-box.tamper{background:#f8d7da;color:#721c24}
.summary-box h2{margin:0;font-size:36px}
.summary-box p{margin:5px 0 0;color:#666}
table{width:100%;border-collapse:collapse;margin:20px 0;font-size:14px}
th{background:#f6f8fa;padding:12px;text-align:left;border-bottom:2px solid #dfe2e5;font-weight:600}
td{padding:10px 12px;border-bottom:1px solid #eaecef;vertical-align:top}
tr:hover{background:#f6f8fa}
.status-ok{color:#28a745;font-weight:600}
.status-missing{color:#ffc107;font-weight:600}
.status-tamper{color:#dc3545;font-weight:600}
.diff-item{margin:2px 0;font-size:13px;color:#555}
.meta{color:#666;font-size:13px;margin-bottom:20px}
.footer{margin-top:40px;padding-top:20px;border-top:1px solid #eaecef;color:#666;font-size:12px;text-align:center}
</style>
</head>
<body>
<h1>&#128274; baseline-guard 基线一致性核查报告</h1>
<p class="meta">)" << EscapeHtml(NowIso()) << R"(</p>
<p class="meta">Database: )" << EscapeHtml(db_path) << R"(</p>

<div class="summary">
<div class="summary-box total"><h2>)" << total << R"(</h2><p>检查项总数</p></div>
<div class="summary-box ok"><h2>)" << ok_count << R"(</h2><p>正常</p></div>
<div class="summary-box missing"><h2>)" << missing_count << R"(</h2><p>文件消失</p></div>
<div class="summary-box tamper"><h2>)" << tamper_count << R"(</h2><p>基线篡改</p></div>
</div>
<p>通过率: )" << std::fixed << std::setprecision(1) << pass_rate << R"(%</p>
)";

    // Issues table
    bool has_issues = (missing_count + tamper_count) > 0;
    if (has_issues) {
        fs << R"(<h2>异常详情</h2>
<table>
<thead><tr><th>状态</th><th>文件路径</th><th>差异项</th></tr></thead>
<tbody>
)";
        for (const auto& f : findings) {
            if (f.status == CheckStatus::ok) continue;
            std::string status_class, status_text;
            if (f.status == CheckStatus::file_missing) {
                status_class = "status-missing";
                status_text = "MISSING";
            } else {
                status_class = "status-tamper";
                status_text = "TAMPER";
            }
            fs << "<tr><td class=\"" << status_class << "\">" << status_text << "</td>"
               << "<td>" << EscapeHtml(f.file_path) << "</td><td>";
            for (const auto& diff : f.diffs) {
                fs << "<div class=\"diff-item\">- " << EscapeHtml(diff) << "</div>";
            }
            fs << "</td></tr>\n";
        }
        fs << "</tbody></table>\n";
    } else {
        fs << "<p style=\"color:#28a745;font-weight:600\">&#10004; 所有基线条目与磁盘文件一致，未发现异常。</p>\n";
    }

    fs << R"(<div class="footer">baseline-guard baseline check &mdash; generated at )"
       << EscapeHtml(NowIso()) << "</div>\n</body>\n</html>\n";

    return true;
}

}  // namespace

int RunBaselineCheck(int argc, char* argv[]) {
    CheckOptions options;
    bool help = false;
    std::string error;
    if (!ParseOptions(argc, argv, options, help, error)) {
        std::cerr << "Error: " << error << "\n";
        PrintUsage();
        return 2;
    }
    if (help) {
        PrintUsage();
        return 0;
    }

    // Check database file exists
    std::error_code ec;
    if (!fs::exists(options.db_path, ec) || ec) {
        std::cerr << "Error: database file not found: " << options.db_path << "\n";
        return 1;
    }

    try {
        BaselineDB db(options.db_path);
        auto entries = db.GetAllBaselineEntries();

        if (entries.empty()) {
            std::cout << "No baseline entries found in database. Nothing to check.\n";
            return 0;
        }

        std::vector<CheckFinding> findings;
        findings.reserve(entries.size());
        for (const auto& entry : entries) {
            findings.push_back(CheckOneEntry(entry));
        }

        // Output
        if (!options.output_file.empty()) {
            if (!GenerateCheckHtml(findings, options.output_file, options.db_path)) {
                std::cerr << "Error: failed to generate HTML report: "
                          << options.output_file << "\n";
                return 1;
            }
            std::cout << "Check report generated: " << options.output_file << "\n";
        }
        PrintConsoleSummary(findings, options.db_path);

        // Return non-zero if issues found
        bool has_issues = std::any_of(findings.begin(), findings.end(),
                                       [](const CheckFinding& f) {
                                           return f.status != CheckStatus::ok;
                                       });
        return has_issues ? 1 : 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}
