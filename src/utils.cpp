#include "utils.hpp"
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