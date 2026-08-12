#include "baseline_delete.hpp"

#include "baseline_db.hpp"

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace {
namespace fs = std::filesystem;

struct DeleteOptions {
    std::string db_path = "/var/lib/baseline-guard/baseline.db";
    std::vector<std::string> paths;
    bool recursive = false;
};

std::string NormalizePath(const std::string& value) {
    std::error_code ec;
    fs::path path = fs::absolute(fs::path(value), ec);
    if (ec) {
        throw std::runtime_error("cannot normalize path '" + value + "': " + ec.message());
    }
    return path.lexically_normal().string();
}

void PrintUsage() {
    std::cout << "Usage: baseline-guard baseline delete [options] PATH...\n"
              << "Delete baseline entries for the specified paths.\n"
              << "\n"
              << "Options:\n"
              << "  --db PATH             SQLite database path\n"
              << "  --recurse             when a directory path is given, also delete\n"
              << "                        all entries whose file_path starts with that\n"
              << "                        directory prefix\n"
              << "  -h, --help            display this message\n"
              << "\n"
              << "Examples:\n"
              << "  baseline-guard baseline delete /etc/passwd --db baseline.db\n"
              << "  baseline-guard baseline delete /etc --recurse --db baseline.db\n"
              << "  baseline-guard baseline delete /etc/passwd /root/.ssh --recurse\n";
}

bool ParseOptions(int argc, char* argv[], DeleteOptions& options, bool& help,
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
        auto take_value = [&](const std::string& option, std::string& target) {
            if (i + 1 >= argc) {
                error = "missing value for " + option;
                return false;
            }
            target = argv[++i];
            return true;
        };
        if (!end_options && arg == "--recurse") {
            options.recursive = true;
        } else if (!end_options && arg == "--db") {
            std::string value;
            if (!take_value(arg, value)) return false;
            options.db_path = value;
        } else if (!end_options && arg.rfind("--db=", 0) == 0) {
            options.db_path = arg.substr(5);
        } else if (!end_options && !arg.empty() && arg[0] == '-') {
            error = "unknown delete option: " + arg;
            return false;
        } else {
            options.paths.push_back(arg);
        }
    }
    if (options.paths.empty()) {
        error = "at least one file or directory path is required";
        return false;
    }
    if (options.db_path.empty()) {
        error = "--db must not be empty";
        return false;
    }
    return true;
}

}  // namespace

int RunBaselineDelete(int argc, char* argv[]) {
    DeleteOptions options;
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

    // 标准化路径
    for (auto& path : options.paths) {
        path = NormalizePath(path);
    }
    // 去重
    std::sort(options.paths.begin(), options.paths.end());
    options.paths.erase(std::unique(options.paths.begin(), options.paths.end()),
                        options.paths.end());

    try {
        BaselineDB db(options.db_path);
        int deleted = db.DeleteBaselineEntries(options.paths, options.recursive);

        if (deleted == 0) {
            std::cout << "No matching baseline entries found. Nothing deleted.\n";
        } else {
            std::cout << "Deleted " << deleted << " baseline entr"
                      << (deleted == 1 ? "y" : "ies") << ".\n";
            for (const auto& path : options.paths) {
                std::cout << "  " << path << (options.recursive ? " (recursive)" : "") << "\n";
            }
        }
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}
