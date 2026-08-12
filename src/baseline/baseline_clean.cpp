#include "baseline_clean.hpp"

#include "baseline_db.hpp"

#include <sys/stat.h>

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace {
namespace fs = std::filesystem;

struct CleanOptions {
    std::string db_path = "/var/lib/baseline-guard/baseline.db";
    bool dry_run = false;
};

void PrintUsage() {
    std::cout << "Usage: baseline-guard baseline clean [options]\n"
              << "Clean orphan baseline entries (files no longer exist on disk).\n"
              << "\n"
              << "Options:\n"
              << "  --db PATH             SQLite database path\n"
              << "  --dry-run             preview orphan entries without deleting\n"
              << "  -h, --help            display this message\n"
              << "\n"
              << "Examples:\n"
              << "  baseline-guard baseline clean --dry-run\n"
              << "  baseline-guard baseline clean --db baseline.db\n";
}

bool ParseOptions(int argc, char* argv[], CleanOptions& options, bool& help,
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
        if (arg == "--dry-run") {
            options.dry_run = true;
        } else if (arg == "--db") {
            if (!take_value(arg, options.db_path)) return false;
        } else if (arg.rfind("--db=", 0) == 0) {
            options.db_path = arg.substr(5);
        } else {
            error = "unknown clean option: " + arg;
            return false;
        }
    }
    if (options.db_path.empty()) {
        error = "--db must not be empty";
        return false;
    }
    return true;
}

// Check if file exists on disk using lstat
bool FileExistsOnDisk(const std::string& path) {
    struct stat st = {};
    return lstat(path.c_str(), &st) == 0;
}

}  // namespace

int RunBaselineClean(int argc, char* argv[]) {
    CleanOptions options;
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
            std::cout << "No baseline entries found. Nothing to clean.\n";
            return 0;
        }

        // Find orphan entries (file no longer exists on disk)
        std::vector<std::string> orphan_paths;
        for (const auto& entry : entries) {
            if (!FileExistsOnDisk(entry.file_path)) {
                orphan_paths.push_back(entry.file_path);
            }
        }

        if (orphan_paths.empty()) {
            std::cout << "No orphan baseline entries found. Nothing to clean.\n";
            return 0;
        }

        if (options.dry_run) {
            std::cout << "=== Dry Run: Orphan Baseline Entries ===\n"
                      << "The following " << orphan_paths.size()
                      << " entries would be deleted:\n\n";
            for (const auto& path : orphan_paths) {
                std::cout << "  " << path << "\n";
            }
            std::cout << "\nRun without --dry-run to actually delete these entries.\n";
            return 0;
        }

        // Actually delete orphan entries
        int deleted = db.DeleteBaselineEntries(orphan_paths, false, "orphan-clean");

        std::cout << "Cleaned " << deleted << " orphan baseline entr"
                  << (deleted == 1 ? "y" : "ies") << ".\n";
        std::cout << "Audit records written with source: orphan-clean\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}
