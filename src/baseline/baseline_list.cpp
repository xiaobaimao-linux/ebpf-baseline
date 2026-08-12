#include "baseline_list.hpp"

#include "baseline_db.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

namespace {
namespace fs = std::filesystem;
using json = nlohmann::json;

struct ListOptions {
    std::string db_path = "/var/lib/baseline-guard/baseline.db";
    std::string path_filter;
    int limit = 0;       // 0 = 不限制
    int offset = 0;
    bool json_output = false;
};

void PrintUsage() {
    std::cout << "Usage: baseline-guard baseline list [options]\n"
              << "List baseline entries from the SQLite database.\n"
              << "\n"
              << "Options:\n"
              << "  --db PATH                SQLite database path\n"
              << "  --path-filter PATTERN    SQL LIKE pattern to filter file_path\n"
              << "                           (use % as wildcard, e.g. \"/etc/ssh/%\")\n"
              << "  --limit N                maximum number of rows to return\n"
              << "  --offset N               pagination offset (default: 0)\n"
              << "  --json                   output structured JSON\n"
              << "  -h, --help               display this message\n"
              << "\n"
              << "Examples:\n"
              << "  baseline-guard baseline list --limit 50\n"
              << "  baseline-guard baseline list --path-filter \"/etc/ssh/%\"\n"
              << "  baseline-guard baseline list --path-filter \"/etc/%\" --limit 50 --offset 50\n"
              << "  baseline-guard baseline list --path-filter \"/etc/%\" --json > etc-baseline.json\n";
}

bool ParseOptions(int argc, char* argv[], ListOptions& options, bool& help,
                  std::string& error) {
    bool end_options = false;
    for (int i = 0; i < argc; ++i) {
        const std::string arg = argv[i];
        if (!end_options && arg == "--") {
            end_options = true;
            continue;
        }
        if (!end_options && (arg == "-h" || arg == "--help")) {
            help = true;
            return true;
        }
        auto take_int = [&](const std::string& option, int& target) {
            if (i + 1 >= argc) {
                error = "missing value for " + option;
                return false;
            }
            try {
                target = std::stoi(argv[++i]);
                if (target < 0) {
                    error = option + " must be non-negative";
                    return false;
                }
            } catch (...) {
                error = "invalid integer value for " + option + ": " + std::string(argv[i]);
                return false;
            }
            return true;
        };
        auto take_value = [&](const std::string& option, std::string& target) {
            if (i + 1 >= argc) {
                error = "missing value for " + option;
                return false;
            }
            target = argv[++i];
            return true;
        };
        if (!end_options && arg == "--json") {
            options.json_output = true;
        } else if (!end_options && arg == "--db") {
            if (!take_value(arg, options.db_path)) return false;
        } else if (!end_options && arg.rfind("--db=", 0) == 0) {
            options.db_path = arg.substr(5);
        } else if (!end_options && arg == "--path-filter") {
            if (!take_value(arg, options.path_filter)) return false;
        } else if (!end_options && arg.rfind("--path-filter=", 0) == 0) {
            options.path_filter = arg.substr(14);
        } else if (!end_options && arg == "--limit") {
            if (!take_int(arg, options.limit)) return false;
        } else if (!end_options && arg.rfind("--limit=", 0) == 0) {
            try {
                options.limit = std::stoi(arg.substr(8));
                if (options.limit < 0) {
                    error = "--limit must be non-negative";
                    return false;
                }
            } catch (...) {
                error = "invalid integer value for --limit";
                return false;
            }
        } else if (!end_options && arg == "--offset") {
            if (!take_int(arg, options.offset)) return false;
        } else if (!end_options && arg.rfind("--offset=", 0) == 0) {
            try {
                options.offset = std::stoi(arg.substr(9));
                if (options.offset < 0) {
                    error = "--offset must be non-negative";
                    return false;
                }
            } catch (...) {
                error = "invalid integer value for --offset";
                return false;
            }
        } else if (!end_options && !arg.empty() && arg[0] == '-') {
            error = "unknown list option: " + arg;
            return false;
        } else {
            error = "unexpected positional argument: " + arg;
            return false;
        }
    }
    if (options.db_path.empty()) {
        error = "--db must not be empty";
        return false;
    }
    return true;
}

// 文本表格输出
void PrintTextTable(const ListResult& result, const ListOptions& options) {
    if (result.entries.empty()) {
        std::cout << "No baseline entries found." << std::endl;
        return;
    }

    // 警告：条目超100且未指定limit
    if (result.total_count > 100 && options.limit == 0) {
        std::cerr << "Warning: " << result.total_count
                  << " entries match the filter. "
                  << "Consider using --limit to avoid large output." << std::endl;
    }

    // 表头
    std::cout << std::left
              << std::setw(48) << "FILE_PATH"
              << std::setw(10) << "TYPE"
              << std::setw(12) << "PERMISSION"
              << std::setw(8) << "UID"
              << std::setw(8) << "GID"
              << std::setw(12) << "SIZE"
              << std::setw(20) << "RECORDED_AT"
              << std::setw(16) << "LABEL"
              << std::endl;

    std::cout << std::string(134, '-') << std::endl;

    for (const auto& entry : result.entries) {
        // 路径过长时截断
        std::string path_display = entry.file_path;
        if (path_display.size() > 46) {
            path_display = "..." + path_display.substr(path_display.size() - 43);
        }

        std::cout << std::left
                  << std::setw(48) << path_display
                  << std::setw(10) << entry.file_type
                  << std::setw(12) << entry.permission
                  << std::setw(8) << entry.uid
                  << std::setw(8) << entry.gid
                  << std::setw(12) << entry.file_size
                  << std::setw(20) << entry.recorded_at
                  << std::setw(16) << entry.label
                  << std::endl;
    }

    // 分页信息
    if (options.limit > 0 || options.offset > 0) {
        std::cout << "\nShowing " << result.entries.size() << " of "
                  << result.total_count << " entries";
        if (options.offset > 0) {
            std::cout << " (offset=" << options.offset << ")";
        }
        if (options.limit > 0) {
            std::cout << " (limit=" << options.limit << ")";
        }
        std::cout << std::endl;
    } else {
        std::cout << "\nTotal: " << result.total_count << " entries" << std::endl;
    }
}

// JSON 输出
void PrintJson(const ListResult& result) {
    json root;
    root["total_count"] = result.total_count;
    root["count"] = static_cast<int>(result.entries.size());

    json entries = json::array();
    for (const auto& entry : result.entries) {
        json obj;
        obj["file_path"] = entry.file_path;
        obj["file_type"] = entry.file_type;
        obj["hash"] = entry.hash;
        obj["permission"] = entry.permission;
        obj["uid"] = entry.uid;
        obj["gid"] = entry.gid;
        obj["owner"] = entry.owner;
        obj["grp"] = entry.grp;
        obj["file_size"] = entry.file_size;
        obj["mtime"] = entry.mtime;
        obj["snapshot_id"] = entry.snapshot_id;
        obj["label"] = entry.label;
        obj["recorded_at"] = entry.recorded_at;
        entries.push_back(obj);
    }
    root["entries"] = entries;

    std::cout << root.dump(2) << std::endl;
}

}  // namespace

int RunBaselineList(int argc, char* argv[]) {
    ListOptions options;
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

    // 检查数据库文件是否存在
    std::error_code ec;
    if (!fs::exists(options.db_path, ec) || ec) {
        std::cerr << "Error: database file not found: " << options.db_path << "\n";
        return 1;
    }

    try {
        BaselineDB db(options.db_path);
        ListResult result = db.ListBaselineEntries(options.path_filter,
                                                    options.limit,
                                                    options.offset);

        if (options.json_output) {
            PrintJson(result);
        } else {
            PrintTextTable(result, options);
        }
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}
