#include "utils.hpp"
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <openssl/evp.h>
#include <sstream>

string mode_to_string(mode_t mode) {
    char buf[10] = {0};
    buf[0] = (mode & S_IRUSR) ? 'r' : '-';
    buf[1] = (mode & S_IWUSR) ? 'w' : '-';
    buf[2] = (mode & S_IXUSR) ? 'x' : '-';
    buf[3] = (mode & S_IRGRP) ? 'r' : '-';
    buf[4] = (mode & S_IWGRP) ? 'w' : '-';
    buf[5] = (mode & S_IXGRP) ? 'x' : '-';
    buf[6] = (mode & S_IROTH) ? 'r' : '-';
    buf[7] = (mode & S_IWOTH) ? 'w' : '-';
    buf[8] = (mode & S_IXOTH) ? 'x' : '-';
    return string(buf, 9);
}

void log_pass(const std::string &name, const std::string &msg) {
    spdlog::info("\033[32m[PASS]\033[0m {}: {}", name, msg);
}

void log_fail(const std::string &name, const std::string &msg) {
    spdlog::error("\033[31m[FAIL]\033[0m {}: {}", name, msg);
}

string compute_sha256(const string &path) {
    ifstream file(path, ios::binary);
    if (!file) {
        throw runtime_error("无法打开文件: " + path);
    }

    // 创建并初始化 EVP_MD_CTX
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw runtime_error("EVP_MD_CTX_new 失败");
    }

    // 初始化 SHA-256 摘要运算
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("EVP_DigestInit_ex 失败");
    }

    // 分块读取并更新哈希
    const size_t buffer_size = 8192;
    char buffer[buffer_size];

    while (file.read(buffer, buffer_size)) {
        if (EVP_DigestUpdate(ctx, buffer, buffer_size) != 1) {
            EVP_MD_CTX_free(ctx);
            throw runtime_error("EVP_DigestUpdate 失败");
        }
    }
    if (file.gcount() > 0) {
        if (EVP_DigestUpdate(ctx, buffer, file.gcount()) != 1) {
            EVP_MD_CTX_free(ctx);
            throw runtime_error("EVP_DigestUpdate 失败");
        }
    }

    // 获取最终的哈希值
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("EVP_DigestFinal_ex 失败");
    }

    // 释放上下文
    EVP_MD_CTX_free(ctx);

    // 转换为十六进制字符串
    stringstream ss;
    for (unsigned int i = 0; i < hash_len; ++i) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

std::string NormalizePath(const std::string& value) {
    std::error_code ec;
    std::filesystem::path path = std::filesystem::absolute(std::filesystem::path(value), ec);
    if (ec) {
        throw std::runtime_error("cannot normalize path '" + value + "': " + ec.message());
    }
    return path.lexically_normal().string();
}

bool TakeArgValue(int& idx, int argc, char* argv[], const std::string& /*opt*/, std::string& target) {
    if (idx + 1 >= argc) {
        return false;
    }
    target = argv[++idx];
    return true;
}

PermOwnershipDiff ComparePermOwnership(mode_t actual_mode, uid_t actual_uid, gid_t actual_gid,
                                       const std::string& expected_perm,
                                       int64_t expected_uid, int64_t expected_gid) {
    PermOwnershipDiff diff;
    std::string actual_perm = mode_to_string(actual_mode);
    bool perm_diff = (actual_perm != expected_perm);
    bool uid_diff  = (static_cast<int64_t>(actual_uid) != expected_uid);
    bool gid_diff  = (static_cast<int64_t>(actual_gid) != expected_gid);

    if (!perm_diff && !uid_diff && !gid_diff)
        return diff;

    diff.has_diff = true;
    std::string exp_parts, act_parts;
    if (perm_diff) {
        exp_parts += "mode=" + expected_perm;
        act_parts += "mode=" + actual_perm;
    }
    if (uid_diff) {
        if (!exp_parts.empty()) exp_parts += ", ";
        exp_parts += "uid=" + std::to_string(expected_uid);
        if (!act_parts.empty()) act_parts += ", ";
        act_parts += "uid=" + std::to_string(actual_uid);
    }
    if (gid_diff) {
        if (!exp_parts.empty()) exp_parts += ", ";
        exp_parts += "gid=" + std::to_string(expected_gid);
        if (!act_parts.empty()) act_parts += ", ";
        act_parts += "gid=" + std::to_string(actual_gid);
    }
    diff.expected = exp_parts;
    diff.actual   = act_parts;
    return diff;
}