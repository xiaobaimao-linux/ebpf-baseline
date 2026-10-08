#include "model_file_collector.hpp"

#include <nlohmann/json.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <set>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;
using json = nlohmann::json;

// 模型文件扩展名（小写比较）
const std::set<std::string> kModelExts = {".pt", ".safetensors", ".gguf", ".onnx",
                                          ".ckpt"};

// 单目录递归深度上限（目录本身为第 1 层，文件相对扫描根 ≤4 层）
constexpr int kMaxDepth = 4;

std::string LowerExt(const fs::path& path) {
    std::string ext = path.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return ext;
}

// file_time_type → epoch 秒（C++17 无 clock_cast，用双时钟差值近似换算）
std::time_t ToTimeT(fs::file_time_type ftime) {
    const auto now_file = fs::file_time_type::clock::now();
    const auto now_sys = std::chrono::system_clock::now();
    return std::chrono::system_clock::to_time_t(
        std::chrono::time_point_cast<std::chrono::system_clock::duration>(
            ftime - now_file + now_sys));
}

// epoch 秒 → 本地 ISO 时间（与其他资产 detail 口径一致）
std::string EpochToIso(std::time_t epoch) {
    std::tm tm_value = {};
    localtime_r(&epoch, &tm_value);
    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &tm_value);
    return buffer;
}

} // namespace

std::vector<std::string> DefaultModelScanDirs() {
    std::string home;
    const char* env_home = std::getenv("HOME");
    if (env_home != nullptr) {
        home = env_home;
    }
    return {home + "/.cache/huggingface", "/data", "/models"};
}

std::vector<AssetItem> CollectModelFiles(const std::vector<std::string>& dirs) {
    std::vector<AssetItem> items;
    for (const auto& dir_raw : dirs) {
        if (dir_raw.empty()) {
            continue;
        }
        // 支持配置里的 ~ 前缀（yaml 不展开）
        std::string dir = dir_raw;
        if (dir[0] == '~' && (dir.size() == 1 || dir[1] == '/')) {
            const char* env_home = std::getenv("HOME");
            if (env_home == nullptr) {
                continue;
            }
            dir = std::string(env_home) + dir.substr(1);
        }
        std::error_code ec;
        if (!fs::is_directory(dir, ec) || ec) {
            spdlog::debug("[asset] model scan dir not available, skip: {}", dir);
            continue;  // 不存在/权限不足属正常，跳过
        }
        fs::recursive_directory_iterator end;
        fs::recursive_directory_iterator it(
            dir, fs::directory_options::skip_permission_denied, ec);
        if (ec) {
            spdlog::debug("[asset] cannot open model scan dir {}: {}", dir,
                          ec.message());
            continue;
        }
        // recursive_directory_iterator 默认不跟随目录符号链接
        for (; it != end; it.increment(ec)) {
            if (ec) {
                spdlog::debug("[asset] iterate {} stopped: {}", dir, ec.message());
                break;
            }
            const fs::path& path = it->path();
            std::error_code status_ec;
            if (fs::is_directory(it->symlink_status(status_ec))) {
                if (it.depth() >= kMaxDepth - 1) {
                    it.disable_recursion_pending();  // 深度封顶
                }
                continue;
            }
            // 符号链接文件不跟随、不记录
            if (fs::is_symlink(it->symlink_status(status_ec))) {
                continue;
            }
            if (!fs::is_regular_file(it->symlink_status(status_ec))) {
                continue;
            }
            if (it.depth() >= kMaxDepth) {
                continue;  // 相对扫描根超过 4 层
            }
            const std::string ext = LowerExt(path);
            if (kModelExts.count(ext) == 0) {
                continue;
            }
            const uint64_t size = fs::file_size(path, status_ec) ;
            std::string mtime;
            if (!status_ec) {
                const auto ftime = fs::last_write_time(path, status_ec);
                if (!status_ec) {
                    mtime = EpochToIso(ToTimeT(ftime));
                }
            }
            json detail;
            detail["path"] = path.string();
            detail["ext"] = ext;
            detail["size_bytes"] = status_ec ? -1 : static_cast<int64_t>(size);
            detail["mtime"] = mtime;
            items.push_back({"model_file", path.string(), detail.dump()});
        }
    }
    return items;
}
