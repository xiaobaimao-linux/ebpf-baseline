#include "baseline_check.hpp"

#include "alert_manager.hpp"
#include "baseline_db.hpp"
#include "commonfun.hpp"
#include "config.hpp"
#include "report_generator.hpp"
#include "utils.hpp"

#include <nlohmann/json.hpp>

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
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
using json = nlohmann::json;

constexpr const char* kRuleId   = "baseline-check";
constexpr const char* kRuleName = "离线基线核查";

struct CheckOptions {
    std::string db_path = "/var/lib/baseline-guard/baseline.db";
    std::string path_filter;
    std::string report_html;
    std::string config_path;
    bool json_output  = false;
    bool send_webhook = false;
};

struct CheckFinding {
    std::string file_path;
    std::string event_type;   // missing / hash_changed / perm_changed / access_failed
    std::string severity;     // high / medium
    std::string expected;
    std::string actual;
    std::string details;
};

// ── helpers ──────────────────────────────────────────────────────────

std::string NowIso() {
    const auto now = std::chrono::system_clock::now();
    const auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::localtime(&time);
    char buffer[32] = {};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &tm);
    return buffer;
}

void PrintUsage() {
    std::cout << "Usage: baseline-guard baseline check [options]\n"
              << "Offline baseline integrity check against SQLite baseline entries.\n"
              << "\n"
              << "Options:\n"
              << "  --db PATH             SQLite database path\n"
              << "  --path-filter PATTERN SQL LIKE pattern to filter baseline entries\n"
              << "  --report_html FILE    write deviation report to HTML file\n"
              << "  --json                output structured JSON array\n"
              << "  --send-webhook        push deviations to DingTalk (requires --config)\n"
              << "  -c, --config PATH     YAML config file (for DingTalk webhook)\n"
              << "  -h, --help            display this message\n"
              << "\n"
              << "Examples:\n"
              << "  baseline-guard baseline check\n"
              << "  baseline-guard baseline check --path-filter \"/etc%\"\n"
              << "  baseline-guard baseline check --send-webhook -c config.yaml\n"
              << "  baseline-guard baseline check --path-filter \"/etc%\" --report_html check.html\n"
              << "  baseline-guard baseline check --json\n";
}

bool ParseOptions(int argc, char* argv[], CheckOptions& options, bool& help,
                  std::string& error) {
    for (int i = 0; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            help = true;
            return true;
        }
        auto take_value = [&](const std::string& opt, std::string& target) {
            if (i + 1 >= argc) {
                error = "missing value for " + opt;
                return false;
            }
            target = argv[++i];
            return true;
        };
        if (arg == "--db") {
            if (!take_value(arg, options.db_path)) return false;
        } else if (arg.rfind("--db=", 0) == 0) {
            options.db_path = arg.substr(5);
        } else if (arg == "--path-filter") {
            if (!take_value(arg, options.path_filter)) return false;
        } else if (arg.rfind("--path-filter=", 0) == 0) {
            options.path_filter = arg.substr(14);
        } else if (arg == "--report_html") {
            if (!take_value(arg, options.report_html)) return false;
        } else if (arg.rfind("--report_html=", 0) == 0) {
            options.report_html = arg.substr(14);
        } else if (arg == "--json") {
            options.json_output = true;
        } else if (arg == "--send-webhook") {
            options.send_webhook = true;
        } else if (arg == "-c" || arg == "--config") {
            if (!take_value(arg, options.config_path)) return false;
        } else if (arg.rfind("--config=", 0) == 0) {
            options.config_path = arg.substr(9);
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

// ── comparison ───────────────────────────────────────────────────────

// Compare one baseline entry against disk.  Returns empty finding when OK.
CheckFinding CheckOneEntry(const CheckEntry& entry) {
    CheckFinding f;
    f.file_path = entry.file_path;

    struct stat st = {};
    if (lstat(entry.file_path.c_str(), &st) != 0) {
        f.event_type = "missing";
        f.severity   = "high";
        f.expected   = "file exists";
        f.actual     = "file missing";
        f.details    = "baseline entry exists but file not found on disk";
        return f;
    }

    // sha256
    std::string actual_hash;
    try {
        actual_hash = compute_sha256(entry.file_path);
    } catch (const std::exception& ex) {
        f.event_type = "access_failed";
        f.severity   = "medium";
        f.expected   = "hash computable";
        f.actual     = std::string("error: ") + ex.what();
        f.details    = "cannot compute sha256";
        return f;
    }

    if (actual_hash != entry.hash) {
        f.event_type = "hash_changed";
        f.severity   = "high";
        f.expected   = "sha256:" + entry.hash.substr(0, 16) + "...";
        f.actual     = "sha256:" + actual_hash.substr(0, 16) + "...";
        f.details    = "file content has changed";
        return f;
    }

    // hash matches — check permission / uid / gid (no mtime)
    std::string actual_perm = mode_to_string(st.st_mode & 0777);
    bool perm_diff = (actual_perm != entry.permission);
    bool uid_diff  = (static_cast<int64_t>(st.st_uid) != entry.uid);
    bool gid_diff  = (static_cast<int64_t>(st.st_gid) != entry.gid);

    if (perm_diff || uid_diff || gid_diff) {
        f.event_type = "perm_changed";
        f.severity   = "medium";
        std::string exp_parts, act_parts;
        if (perm_diff) {
            exp_parts += "mode=" + entry.permission;
            act_parts += "mode=" + actual_perm;
        }
        if (uid_diff) {
            if (!exp_parts.empty()) exp_parts += ", ";
            exp_parts += "uid=" + std::to_string(entry.uid);
            if (!act_parts.empty()) act_parts += ", ";
            act_parts += "uid=" + std::to_string(st.st_uid);
        }
        if (gid_diff) {
            if (!exp_parts.empty()) exp_parts += ", ";
            exp_parts += "gid=" + std::to_string(entry.gid);
            if (!act_parts.empty()) act_parts += ", ";
            act_parts += "gid=" + std::to_string(st.st_gid);
        }
        f.expected = exp_parts;
        f.actual   = act_parts;
        f.details  = "permission/ownership changed (hash unchanged)";
        return f;
    }

    // all OK — return empty finding
    return f;
}

// ── output: console ──────────────────────────────────────────────────

void PrintConsoleTable(const std::vector<CheckFinding>& findings) {
    if (findings.empty()) {
        std::cout << "No baseline deviation found." << std::endl;
        return;
    }

    std::cout << std::left
              << std::setw(16) << "EVENT_TYPE"
              << std::setw(10) << "SEVERITY"
              << std::setw(48) << "FILE_PATH"
              << std::setw(40) << "DETAILS"
              << std::endl;
    std::cout << std::string(114, '-') << std::endl;

    for (const auto& f : findings) {
        std::string path_disp = f.file_path;
        if (path_disp.size() > 46) {
            path_disp = "..." + path_disp.substr(path_disp.size() - 43);
        }
        std::cout << std::left
                  << std::setw(16) << f.event_type
                  << std::setw(10) << f.severity
                  << std::setw(48) << path_disp
                  << std::setw(40) << f.details
                  << std::endl;
    }
    std::cout << "\nTotal deviations: " << findings.size() << std::endl;
}

// ── output: JSON ─────────────────────────────────────────────────────

void PrintJson(const std::vector<CheckFinding>& findings) {
    json arr = json::array();
    for (const auto& f : findings) {
        json obj;
        obj["file_path"]   = f.file_path;
        obj["event_type"]  = f.event_type;
        obj["severity"]    = f.severity;
        obj["expected"]    = f.expected;
        obj["actual"]      = f.actual;
        obj["details"]     = f.details;
        obj["checked_at"]  = NowIso();
        arr.push_back(obj);
    }
    std::cout << arr.dump(2) << std::endl;
}

// ── output: HTML (reuse ReportGenerator) ─────────────────────────────

bool WriteHtmlReport(const std::vector<CheckFinding>& findings,
                     const std::string& output_path) {
    std::vector<CheckResult> results;
    for (const auto& f : findings) {
        CheckResult cr;
        cr.rule_id   = kRuleId;
        cr.rule_name = kRuleName;
        cr.file_path = f.file_path;
        cr.expected  = f.expected;
        cr.actual    = f.actual;
        cr.passed    = false;
        cr.severity  = f.severity;
        results.push_back(cr);
    }
    ReportGenerator rg;
    return rg.GenerateCheckHtml(results, output_path);
}

// ── alerts: write to DB + optional DingTalk ──────────────────────────

void WriteAlerts(const std::vector<CheckFinding>& findings,
                 const CheckOptions& options) {
    if (findings.empty()) return;

    AlertManager alert_mgr;

    // Only load DingTalk config when --send-webhook AND --config provided
    if (options.send_webhook && !options.config_path.empty()) {
        if (!ends_with(options.config_path, ".yaml") &&
            !ends_with(options.config_path, ".yml")) {
            std::cerr << "Warning: only YAML config is supported, "
                      << "DingTalk will not be available\n";
        } else {
            try {
                Config config = parseYamlFile(options.config_path);
                alert_mgr.LoadConfig(config.alert, config.db);
            } catch (const std::exception& ex) {
                std::cerr << "Warning: failed to load config '"
                          << options.config_path << "': " << ex.what()
                          << "\n  Alerts will be persisted to DB but "
                          << "DingTalk will not be available.\n";
            }
        }
    } else if (options.send_webhook && options.config_path.empty()) {
        std::cerr << "Warning: --send-webhook requires --config to specify "
                  << "YAML config with DingTalk webhook.\n"
                  << "  Alerts will be persisted to DB but DingTalk "
                  << "will not be sent.\n";
    }

    alert_mgr.SetDB(nullptr);  // we'll use our own DB handle
    BaselineDB alert_db(options.db_path);
    alert_mgr.SetDB(&alert_db);

    for (const auto& f : findings) {
        AlertEvent event;
        event.rule_id      = kRuleId;
        event.rule_name    = std::string("[离线基线核查] ") + kRuleName;
        event.severity     = f.severity;
        event.file_path    = f.file_path;
        event.expected     = f.expected;
        event.actual       = f.actual;
        event.event_type   = f.event_type;
        event.action_taken = "report_only";
        event.timestamp    = NowIso();

        if (options.send_webhook && alert_mgr.IsEnabled()) {
            alert_mgr.SendDingTalk(event);   // handles throttle + DB write
        } else {
            // Persist to DB only (no DingTalk)
            AlertRecord record;
            record.rule_id      = event.rule_id;
            record.rule_name    = event.rule_name;
            record.severity     = event.severity;
            record.file_path    = event.file_path;
            record.expected     = event.expected;
            record.actual       = event.actual;
            record.event_type   = event.event_type;
            record.action_taken = event.action_taken;
            record.dingtalk_sent = false;
            record.recorded_at  = event.timestamp;
            alert_db.SaveAlert(record);
        }
    }
}

}  // namespace

// ── entry point ──────────────────────────────────────────────────────

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

        // Use ListBaselineEntries to support path-filter
        ListResult lr = db.ListBaselineEntries(options.path_filter, 0, 0);

        if (lr.entries.empty()) {
            if (options.json_output) {
                std::cout << "[]" << std::endl;
            } else {
                std::cout << "No baseline entries found"
                          << (options.path_filter.empty()
                                  ? "."
                                  : " matching '" + options.path_filter + "'.")
                          << std::endl;
            }
            return 0;
        }

        // Compare each entry against disk
        std::vector<CheckFinding> findings;
        for (const auto& entry : lr.entries) {
            CheckEntry ce;
            ce.file_path    = entry.file_path;
            ce.file_type    = entry.file_type;
            ce.hash         = entry.hash;
            ce.permission   = entry.permission;
            ce.uid          = entry.uid;
            ce.gid          = entry.gid;
            ce.owner        = entry.owner;
            ce.grp          = entry.grp;
            ce.file_size    = entry.file_size;
            ce.mtime        = entry.mtime;
            ce.snapshot_id  = entry.snapshot_id;
            ce.label        = entry.label;
            ce.recorded_at  = entry.recorded_at;

            CheckFinding f = CheckOneEntry(ce);
            if (!f.event_type.empty()) {
                findings.push_back(std::move(f));
            }
        }

        // 1. Write alerts to DB (always, regardless of output mode)
        WriteAlerts(findings, options);

        // 2. Output
        if (options.json_output) {
            PrintJson(findings);
        } else if (!options.report_html.empty()) {
            if (!WriteHtmlReport(findings, options.report_html)) {
                std::cerr << "Error: failed to generate HTML report: "
                          << options.report_html << "\n";
                return 1;
            }
            // --report_html: console does NOT print deviation details
            std::cout << "Check report generated: " << options.report_html << "\n";
            std::cout << "Deviations found: " << findings.size() << "\n";
        } else {
            PrintConsoleTable(findings);
        }

        return findings.empty() ? 0 : 1;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}
