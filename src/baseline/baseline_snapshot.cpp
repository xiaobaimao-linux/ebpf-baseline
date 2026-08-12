#include "baseline_snapshot.hpp"

#include "baseline_db.hpp"
#include "utils.hpp"

#include <fnmatch.h>
#include <sys/stat.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

namespace {
namespace fs = std::filesystem;

struct SnapshotOptions {
    std::string db_path = "/var/lib/baseline-guard/baseline.db";
    std::string label = "default";
    std::vector<std::string> paths;
    std::vector<std::string> excludes;
    bool recursive = true;
};

struct CollectedSnapshot {
    std::vector<SnapshotEntry> entries;
    std::vector<SnapshotScope> scopes;
};

std::string NormalizePath(const std::string& value) {
    std::error_code ec;
    fs::path path = fs::absolute(fs::path(value), ec);
    if (ec) {
        throw std::runtime_error("cannot normalize path '" + value + "': " + ec.message());
    }
    return path.lexically_normal().string();
}

bool IsWithin(const std::string& path, const std::string& root) {
    return path == root ||
           (path.size() > root.size() && path.compare(0, root.size(), root) == 0 &&
            path[root.size()] == '/');
}

bool MatchesExclude(const std::string& path, const std::vector<std::string>& excludes) {
    const fs::path fs_path(path);
    const std::string basename = fs_path.filename().string();
    for (const auto& pattern : excludes) {
        if (path == pattern || IsWithin(path, pattern) ||
            fnmatch(pattern.c_str(), path.c_str(), 0) == 0 ||
            fnmatch(pattern.c_str(), basename.c_str(), 0) == 0) {
            return true;
        }
    }
    return false;
}

std::string NowIso() {
    const auto now = std::chrono::system_clock::now();
    const auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::localtime(&time);
    char buffer[32] = {};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &tm);
    return buffer;
}

std::string Join(const std::vector<std::string>& values) {
    std::ostringstream output;
    for (size_t i = 0; i < values.size(); ++i) {
        if (i != 0) output << '\n';
        output << values[i];
    }
    return output.str();
}

void PrintUsage() {
    std::cout << "Usage: baseline-guard baseline snapshot [options] PATH...\n"
              << "Options:\n"
              << "  --db PATH             SQLite database path\n"
              << "  --label NAME          snapshot label (default: default)\n"
              << "  --exclude PATH        exclude path or glob; may be repeated\n"
              << "  --no-recurse          scan only direct child files of directories\n"
              << "  -h, --help            display this message\n";
}

bool ReadEntry(const fs::path& path, SnapshotEntry& entry, std::string& error) {
    struct stat st = {};
    if (lstat(path.c_str(), &st) != 0) {
        error = "cannot stat '" + path.string() + "'";
        return false;
    }
    if (!S_ISREG(st.st_mode)) {
        return false;
    }

    entry.file_path = path.string();
    entry.file_type = "regular";
    entry.permission = mode_to_string(st.st_mode & 0777);
    entry.uid = static_cast<std::int64_t>(st.st_uid);
    entry.gid = static_cast<std::int64_t>(st.st_gid);
    entry.owner = std::to_string(st.st_uid);
    entry.grp = std::to_string(st.st_gid);
    entry.file_size = static_cast<std::int64_t>(st.st_size);
    entry.mtime = static_cast<std::int64_t>(st.st_mtime);
    try {
        entry.hash = compute_sha256(entry.file_path);
    } catch (const std::exception& ex) {
        error = ex.what();
        return false;
    }
    return true;
}

bool CollectPath(const std::string& root, const SnapshotOptions& options,
                 CollectedSnapshot& collected, std::unordered_set<std::string>& seen,
                 std::string& error) {
    const fs::path path(root);
    std::error_code ec;
    const fs::file_status status = fs::symlink_status(path, ec);
    if (ec || status.type() == fs::file_type::not_found) {
        error = "path does not exist: " + root;
        return false;
    }
    if (MatchesExclude(root, options.excludes)) {
        return true;
    }

    if (fs::is_regular_file(status)) {
        SnapshotEntry entry;
        if (!ReadEntry(path, entry, error)) return false;
        if (seen.insert(entry.file_path).second) collected.entries.push_back(std::move(entry));
        collected.scopes.push_back({root, true, true});
        return true;
    }
    if (!fs::is_directory(status)) {
        error = "unsupported path type: " + root;
        return false;
    }

    collected.scopes.push_back({root, options.recursive, false});
    if (options.recursive) {
        fs::recursive_directory_iterator iterator(
            path, fs::directory_options::skip_permission_denied, ec);
        fs::recursive_directory_iterator end;
        while (iterator != end) {
            const std::string current = NormalizePath(iterator->path().string());
            if (MatchesExclude(current, options.excludes)) {
                if (iterator->is_directory(ec)) iterator.disable_recursion_pending();
                iterator.increment(ec);
                continue;
            }
            if (ec) {
                error = "cannot traverse '" + root + "'";
                return false;
            }
            if (iterator->is_regular_file(ec)) {
                SnapshotEntry entry;
                if (!ReadEntry(iterator->path(), entry, error)) return false;
                if (seen.insert(entry.file_path).second) collected.entries.push_back(std::move(entry));
            }
            iterator.increment(ec);
        }
    } else {
        fs::directory_iterator iterator(path, fs::directory_options::skip_permission_denied, ec);
        fs::directory_iterator end;
        while (iterator != end) {
            const std::string current = NormalizePath(iterator->path().string());
            if (!MatchesExclude(current, options.excludes) && iterator->is_regular_file(ec)) {
                SnapshotEntry entry;
                if (!ReadEntry(iterator->path(), entry, error)) return false;
                if (seen.insert(entry.file_path).second) collected.entries.push_back(std::move(entry));
            }
            iterator.increment(ec);
        }
    }
    if (ec) {
        error = "cannot traverse '" + root + "'";
        return false;
    }
    return true;
}

bool ParseOptions(int argc, char* argv[], SnapshotOptions& options, bool& help, std::string& error) {
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
        if (!end_options && (arg == "--no-recurse")) {
            options.recursive = false;
        } else if (!end_options && (arg == "--db" || arg == "--label" || arg == "--exclude")) {
            std::string value;
            if (!take_value(arg, value)) return false;
            if (arg == "--db") options.db_path = value;
            else if (arg == "--label") options.label = value;
            else options.excludes.push_back(value);
        } else if (!end_options && arg.rfind("--db=", 0) == 0) {
            options.db_path = arg.substr(5);
        } else if (!end_options && arg.rfind("--label=", 0) == 0) {
            options.label = arg.substr(8);
        } else if (!end_options && arg.rfind("--exclude=", 0) == 0) {
            options.excludes.push_back(arg.substr(10));
        } else if (!end_options && !arg.empty() && arg[0] == '-') {
            error = "unknown snapshot option: " + arg;
            return false;
        } else {
            options.paths.push_back(arg);
        }
    }
    if (options.paths.empty()) {
        error = "at least one file or directory path is required";
        return false;
    }
    if (options.db_path.empty() || options.label.empty()) {
        error = "--db and --label must not be empty";
        return false;
    }
    return true;
}

}  // namespace

int RunBaselineSnapshot(int argc, char* argv[]) {
    SnapshotOptions options;
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

    for (auto& path : options.paths) path = NormalizePath(path);
    for (auto& path : options.excludes) path = NormalizePath(path);
    const std::string normalized_db_path = NormalizePath(options.db_path);
    options.excludes.push_back(normalized_db_path);
    std::sort(options.paths.begin(), options.paths.end());
    options.paths.erase(std::unique(options.paths.begin(), options.paths.end()), options.paths.end());

    CollectedSnapshot collected;
    std::unordered_set<std::string> seen;
    for (const auto& path : options.paths) {
        if (!CollectPath(path, options, collected, seen, error)) {
            std::cerr << "Error: " << error << "\n";
            return 1;
        }
    }
    std::sort(collected.entries.begin(), collected.entries.end(),
              [](const SnapshotEntry& left, const SnapshotEntry& right) {
                  return left.file_path < right.file_path;
              });

    const std::string started_at = NowIso();
    const std::string snapshot_id = started_at + "-" + std::to_string(getpid());
    const std::string finished_at = NowIso();
    SnapshotStats stats;
    stats.scanned = static_cast<std::int64_t>(collected.entries.size());
    try {
        BaselineDB db(options.db_path);
        if (!db.ApplySnapshot(snapshot_id, options.label, collected.entries, collected.scopes,
                              options.excludes, options.recursive, Join(options.paths),
                              Join(options.excludes), started_at, finished_at, stats, error)) {
            std::cerr << "Error: failed to save snapshot: " << error << "\n";
            return 1;
        }
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }

    std::cout << "Baseline snapshot completed\n"
              << "Snapshot ID: " << snapshot_id << "\n"
              << "Label: " << options.label << "\n"
              << "Scanned files: " << stats.scanned << "\n"
              << "Added: " << stats.added << "\n"
              << "Modified: " << stats.modified << "\n"
              << "Deleted: " << stats.removed << "\n"
              << "Unchanged: " << stats.unchanged << "\n";
    return 0;
}
