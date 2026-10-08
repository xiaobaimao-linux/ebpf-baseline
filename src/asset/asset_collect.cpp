#include "asset_collect.hpp"

#include "asset_collector.hpp"
#include "baseline_db.hpp"
#include "commonfun.hpp"
#include "gpu_collector.hpp"
#include "model_file_collector.hpp"
#include "utils.hpp"

#include <spdlog/spdlog.h>
#include <yaml-cpp/yaml.h>

#include <exception>
#include <iostream>
#include <string>
#include <vector>

namespace {

struct CollectOptions {
    std::string db_path = "/var/lib/baseline-guard/baseline.db";
    std::string config_path;  // 可选：读 asset.model_scan_dirs，缺省用内置默认目录
};

void PrintUsage() {
    std::cout << "Usage: baseline-guard asset collect [options]\n"
              << "Collect host assets (packages, listening ports, processes,\n"
              << "autostart entries, cron jobs, GPUs, model files) into the SQLite\n"
              << "assets table.\n"
              << "\n"
              << "Options:\n"
              << "  --db PATH       SQLite database path\n"
              << "  -c, --config PATH  config.yaml with asset.model_scan_dirs\n"
              << "                     (default scan dirs: ~/.cache/huggingface /data /models)\n"
              << "  -h, --help      display this message\n"
              << "\n"
              << "Examples:\n"
              << "  baseline-guard asset collect\n"
              << "  baseline-guard asset collect --db /tmp/assets.db -c config.yaml\n";
}

// 从 config.yaml 读 asset.model_scan_dirs；读取失败/缺节点记 warn 用默认目录
std::vector<std::string> LoadModelScanDirs(const std::string& config_path) {
    if (config_path.empty()) {
        return DefaultModelScanDirs();
    }
    try {
        const YAML::Node root = YAML::LoadFile(config_path);
        const YAML::Node dirs = root["asset"]["model_scan_dirs"];
        std::vector<std::string> out;
        if (dirs && dirs.IsSequence()) {
            for (const auto& item : dirs) {
                if (item && item.IsScalar()) {
                    out.push_back(item.as<std::string>());
                }
            }
        }
        if (!out.empty()) {
            return out;
        }
        spdlog::warn("[asset_collect] {} has no asset.model_scan_dirs, use defaults",
                     config_path);
    } catch (const YAML::Exception& ex) {
        spdlog::warn("[asset_collect] failed to parse {}: {}, use default scan dirs",
                     config_path, ex.what());
    }
    return DefaultModelScanDirs();
}

bool ParseOptions(int argc, char* argv[], CollectOptions& options, bool& help,
                  std::string& error) {
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
        } else if (arg == "-c" || arg == "--config") {
            if (!TakeArgValue(i, argc, argv, arg, options.config_path)) {
                error = "missing value for " + arg;
                return false;
            }
        } else if (arg.rfind("--config=", 0) == 0) {
            options.config_path = arg.substr(9);
        } else {
            error = "unknown collect option: " + arg;
            return false;
        }
    }
    if (options.db_path.empty()) {
        error = "--db must not be empty";
        return false;
    }
    return true;
}

// 单类采集失败仅记 warn 降级，不影响其他四类
template <typename F>
std::vector<AssetItem> SafeCollect(const char* type, F&& fn) {
    try {
        return fn();
    } catch (const std::exception& ex) {
        spdlog::warn("[asset_collect] {} collector failed: {}", type, ex.what());
    } catch (...) {
        spdlog::warn("[asset_collect] {} collector failed: unknown error", type);
    }
    return {};
}

} // namespace

int RunAssetCollect(int argc, char* argv[]) {
    CollectOptions options;
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

    try {
        BaselineDB db(options.db_path);
        const std::vector<std::string> model_scan_dirs =
            LoadModelScanDirs(options.config_path);

        struct CollectedBatch {
            const char* type;
            std::vector<AssetItem> items;
        };
        const std::vector<CollectedBatch> batches = {
            {"package", SafeCollect("package", CollectPackages)},
            {"port", SafeCollect("port", CollectPorts)},
            {"process", SafeCollect("process", CollectProcesses)},
            {"autostart", SafeCollect("autostart", CollectAutostart)},
            {"cron", SafeCollect("cron", CollectCron)},
            {"gpu", SafeCollect("gpu", CollectGpus)},
            {"model_file",
             SafeCollect("model_file",
                         [&] { return CollectModelFiles(model_scan_dirs); })},
        };

        int total_new = 0;
        int total_updated = 0;
        std::cout << std::left;
        for (const auto& batch : batches) {
            std::vector<AssetRecord> records;
            records.reserve(batch.items.size());
            for (const auto& item : batch.items) {
                AssetRecord record;
                record.asset_type = item.asset_type;
                record.name = item.name;
                record.detail_json = item.detail_json;
                records.push_back(std::move(record));
            }
            // 同批次内 (asset_type, name) 去重由存储层保证（端口 SO_REUSEPORT 等场景保留首条）
            AssetUpsertResult result = db.UpsertAssets(records);
            total_new += result.inserted;
            total_updated += result.updated;
            std::cout << "  " << batch.type << ": " << records.size() << " items (new "
                      << result.inserted << ", updated " << result.updated << ")"
                      << std::endl;
        }
        std::cout << "Asset collection finished. total new=" << total_new
                  << ", updated=" << total_updated << std::endl;
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}
