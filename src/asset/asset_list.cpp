#include "asset_list.hpp"

#include "baseline_db.hpp"
#include "utils.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <iomanip>
#include <iostream>
#include <set>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;
using json = nlohmann::json;

struct ListOptions {
    std::string db_path = "/var/lib/baseline-guard/baseline.db";
    std::string asset_type;
    int limit = 0;  // 0 = 不限制
    int offset = 0;
    bool json_output = false;
};

const std::set<std::string> kKnownTypes = {"package", "port", "process", "autostart",
                                           "cron"};

void PrintUsage() {
    std::cout << "Usage: baseline-guard asset list [options]\n"
              << "List host assets from the SQLite assets table.\n"
              << "\n"
              << "Options:\n"
              << "  --type T     filter by asset type: package|port|process|autostart|cron\n"
              << "  --db PATH    SQLite database path\n"
              << "  --limit N    maximum number of rows to return\n"
              << "  --offset N   pagination offset (default: 0)\n"
              << "  --json       output structured JSON\n"
              << "  -h, --help   display this message\n"
              << "\n"
              << "Examples:\n"
              << "  baseline-guard asset list --type package\n"
              << "  baseline-guard asset list --json > assets.json\n";
}

bool ParseOptions(int argc, char* argv[], ListOptions& options, bool& help,
                  std::string& error) {
    auto take_int = [&](int& i, const std::string& option, int& target) {
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
            error = "invalid integer value for " + option;
            return false;
        }
        return true;
    };
    for (int i = 0; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            help = true;
            return true;
        }
        if (arg == "--db") {
            if (!TakeArgValue(i, argc, argv, arg, options.db_path)) {
                error = "missing value for --db";
                return false;
            }
        } else if (arg.rfind("--db=", 0) == 0) {
            options.db_path = arg.substr(5);
        } else if (arg == "--type") {
            if (!TakeArgValue(i, argc, argv, arg, options.asset_type)) {
                error = "missing value for --type";
                return false;
            }
        } else if (arg.rfind("--type=", 0) == 0) {
            options.asset_type = arg.substr(7);
        } else if (arg == "--limit") {
            if (!take_int(i, arg, options.limit)) return false;
        } else if (arg.rfind("--limit=", 0) == 0) {
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
        } else if (arg == "--offset") {
            if (!take_int(i, arg, options.offset)) return false;
        } else if (arg.rfind("--offset=", 0) == 0) {
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
        } else if (arg == "--json") {
            options.json_output = true;
        } else {
            error = "unknown list option: " + arg;
            return false;
        }
    }
    if (options.db_path.empty()) {
        error = "--db must not be empty";
        return false;
    }
    if (!options.asset_type.empty() && kKnownTypes.count(options.asset_type) == 0) {
        error = "unknown asset type: " + options.asset_type +
                " (expected package|port|process|autostart|cron)";
        return false;
    }
    return true;
}

void PrintTextTable(const std::vector<AssetRecord>& records, int64_t total_count,
                    const ListOptions& options) {
    if (records.empty()) {
        std::cout << "No assets found." << std::endl;
        return;
    }
    if (total_count > 100 && options.limit == 0) {
        std::cerr << "Warning: " << total_count
                  << " assets match the filter. Consider using --limit to avoid large "
                     "output."
                  << std::endl;
    }
    std::cout << std::left << std::setw(10) << "TYPE" << std::setw(56) << "NAME"
              << std::setw(21) << "FIRST_SEEN" << std::setw(21) << "LAST_SEEN"
              << "DETAIL" << std::endl;
    std::cout << std::string(140, '-') << std::endl;
    for (const auto& record : records) {
        std::string name_display = record.name;
        if (name_display.size() > 54) {
            name_display = name_display.substr(0, 51) + "...";
        }
        std::string detail_display = record.detail_json;
        if (detail_display.size() > 60) {
            detail_display = detail_display.substr(0, 57) + "...";
        }
        std::cout << std::left << std::setw(10) << record.asset_type << std::setw(56)
                  << name_display << std::setw(21) << record.first_seen << std::setw(21)
                  << record.last_seen << detail_display << std::endl;
    }
    std::cout << "\nTotal: " << total_count << " assets" << std::endl;
}

void PrintJson(const std::vector<AssetRecord>& records, int64_t total_count) {
    json root;
    root["total_count"] = total_count;
    root["count"] = static_cast<int>(records.size());
    json assets = json::array();
    for (const auto& record : records) {
        json obj;
        obj["id"] = record.id;
        obj["asset_type"] = record.asset_type;
        obj["name"] = record.name;
        json detail = json::object();
        if (!record.detail_json.empty()) {
            const json parsed = json::parse(record.detail_json, nullptr, false);
            detail = parsed.is_object() ? parsed : json(record.detail_json);
        }
        obj["detail_json"] = detail;
        obj["first_seen"] = record.first_seen;
        obj["last_seen"] = record.last_seen;
        assets.push_back(obj);
    }
    root["assets"] = assets;
    std::cout << root.dump(2) << std::endl;
}

} // namespace

int RunAssetList(int argc, char* argv[]) {
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

    std::error_code ec;
    if (!fs::exists(options.db_path, ec) || ec) {
        std::cerr << "Error: database file not found: " << options.db_path << "\n";
        return 1;
    }

    try {
        BaselineDB db(options.db_path);
        const int64_t total_count = db.CountAssets(options.asset_type);
        const std::vector<AssetRecord> records =
            db.GetAssets(options.asset_type, options.limit, options.offset);
        if (options.json_output) {
            PrintJson(records, total_count);
        } else {
            PrintTextTable(records, total_count, options);
        }
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}
