// 单元测试：模型文件发现（目录跳过/深度限制/符号链接不跟随/字段正确性）
// 编译见 tests/Makefile test_model_files

#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <unistd.h>
#include <vector>

#include <nlohmann/json.hpp>

#include "model_file_collector.hpp"

namespace fs = std::filesystem;
using json = nlohmann::json;

static fs::path g_root;

static void MakeFile(const fs::path& path, uint64_t size) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.seekp(static_cast<std::streamoff>(size) - 1);
    out.put('\0');
}

// 10 个不同大小、分布在不同深度的模型文件
static const std::vector<std::pair<std::string, uint64_t>> kModels = {
    {"a.pt", 1},
    {"b.safetensors", 10},
    {"c.gguf", 100},
    {"d.onnx", 1000},
    {"e.ckpt", 4096},
    {"l1/f.pt", 10000},
    {"l1/l2/g.safetensors", 65536},
    {"l1/l2/l3/h.gguf", 1048576},
    {"l1/l2/l3/i.onnx", 1234567},
    {"l1/l2/j.CKPT", 7777},  // 扩展名大小写不敏感
};

// ====== MDL-001: 10/10 检出且大小字段正确 ======
void test_scan_found_all() {
    for (const auto& [rel, size] : kModels) {
        MakeFile(g_root / rel, size);
    }
    // 非模型文件不应检出
    MakeFile(g_root / "readme.txt", 64);
    MakeFile(g_root / "l1/config.json", 128);
    // 第 5 层深度的模型文件不应检出（深度上限 4）
    MakeFile(g_root / "d1/d2/d3/d4/deep.pt", 2048);
    // 符号链接不跟随、不记录
    fs::create_symlink(g_root / "a.pt", g_root / "link.pt");
    fs::create_directory_symlink(g_root / "l1", g_root / "l1_link");

    const auto items = CollectModelFiles({g_root.string()});
    assert(items.size() == kModels.size());

    std::map<std::string, uint64_t> want;
    for (const auto& [rel, size] : kModels) {
        want[(g_root / rel).string()] = size;
    }
    for (const auto& item : items) {
        assert(item.asset_type == "model_file");
        const json detail = json::parse(item.detail_json);
        assert(detail["path"].get<std::string>() == item.name);
        auto it = want.find(item.name);
        assert(it != want.end());
        assert(detail["size_bytes"].get<int64_t>() == static_cast<int64_t>(it->second));
        assert(!detail["mtime"].get<std::string>().empty());
        assert(!detail["ext"].get<std::string>().empty());
        want.erase(it);
    }
    assert(want.empty());
    printf("  [PASS] MDL-001: 10/10 检出且字段正确\n");
}

// ====== MDL-002: 不存在目录跳过不报错 ======
void test_missing_dir() {
    const auto items = CollectModelFiles(
        {"/tmp/baseline_guard_no_such_dir_xyz", g_root.string()});
    assert(items.size() == kModels.size());  // 存在的目录照常扫描
    printf("  [PASS] MDL-002: 不存在目录跳过\n");
}

// ====== MDL-003: 权限不足目录跳过不报错（root 运行 chmod 000 仍可读，则跳过该断言）======
void test_denied_dir() {
    const fs::path denied = g_root / "denied";
    fs::create_directories(denied);
    MakeFile(denied / "hidden.pt", 512);
    fs::permissions(denied, fs::perms::none);
    const auto items = CollectModelFiles({denied.string()});
    if (geteuid() != 0) {
        assert(items.empty());
    }
    fs::permissions(denied, fs::perms::owner_all);
    printf("  [PASS] MDL-003: 权限不足目录跳过\n");
}

// ====== MDL-004: 默认目录列表含约定路径 ======
void test_default_dirs() {
    const auto dirs = DefaultModelScanDirs();
    assert(dirs.size() == 3);
    assert(dirs[0].find("/.cache/huggingface") != std::string::npos);
    assert(dirs[0].find('~') == std::string::npos);  // ~ 已展开
    assert(dirs[1] == "/data");
    assert(dirs[2] == "/models");
    printf("  [PASS] MDL-004: 默认扫描目录\n");
}

int main() {
    g_root = fs::path("/tmp") /
             ("baseline_guard_modeltest_" + std::to_string(getpid()));
    fs::remove_all(g_root);
    fs::create_directories(g_root);

    test_scan_found_all();
    test_missing_dir();
    test_denied_dir();
    test_default_dirs();

    fs::remove_all(g_root);
    printf("All model_file tests passed!\n");
    return 0;
}
