// 单元测试：工具函数
// 编译: g++ -std=c++17 -I../../include -I../../src -o test_utils test_utils.cpp ../../src/utils.cpp $(pkg-config --libs openssl) -lfmt

#include <cassert>
#include <cstdio>
#include <fstream>
#include <iostream>
#include "utils.hpp"

std::string write_temp_file(const std::string &content) {
    std::string path = "/tmp/testfile_" + std::to_string(getpid()) + ".txt";
    std::ofstream f(path, std::ios::binary);
    f << content;
    return path;
}

// ====== UTL-001: SHA256计算 ======
void test_sha256() {
    std::string path = write_temp_file("hello");
    std::string hash = compute_sha256(path);
    std::remove(path.c_str());
    assert(hash.length() == 64); // 256bit = 64 hex chars
    assert(hash == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    printf("  [PASS] UTL-001: SHA256计算\n");
}

// ====== UTL-002: SHA256不存在的文件 ======
void test_sha256_not_found() {
    bool threw = false;
    try {
        compute_sha256("/tmp/nonexist_123456");
    } catch (const std::runtime_error &e) {
        threw = true;
    }
    assert(threw);
    printf("  [PASS] UTL-002: SHA256不存在的文件\n");
}

// ====== UTL-003~005: mode转字符串 ======
void test_mode_string() {
    assert(mode_to_string(0644) == "rw-r--r--");
    assert(mode_to_string(0777) == "rwxrwxrwx");
    assert(mode_to_string(0000) == "---------");
    assert(mode_to_string(0755) == "rwxr-xr-x");
    printf("  [PASS] UTL-003~005: mode转字符串\n");
}

int main() {
    printf("=== test_utils ===\n");
    test_sha256();
    test_sha256_not_found();
    test_mode_string();
    printf("=== all utils tests passed ===\n");
    return 0;
}
