// 单元测试：工具函数
// 编译: g++ -std=c++17 -I../../include -I../../src -o test_utils test_utils.cpp ../../src/utils.cpp $(pkg-config --libs openssl) -lfmt

#include <cassert>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <sys/stat.h>
#include "utils.hpp"

std::string write_temp_file(const std::string &content, const std::string &name = "testfile") {
    std::string path = "/tmp/" + name + "_" + std::to_string(getpid()) + ".txt";
    std::ofstream f(path, std::ios::binary);
    f << content;
    return path;
}

// ====== UTL-001: SHA256计算-hello ======
void test_sha256_hello() {
    std::string path = write_temp_file("hello");
    std::string hash = compute_sha256(path);
    std::remove(path.c_str());
    assert(hash.length() == 64); // 256bit = 64 hex chars
    assert(hash == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    printf("  [PASS] UTL-001: SHA256计算-hello\n");
}

// ====== UTL-002: SHA256空文件 ======
void test_sha256_empty() {
    std::string path = write_temp_file("");
    std::string hash = compute_sha256(path);
    std::remove(path.c_str());
    assert(hash.length() == 64);
    // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    assert(hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    printf("  [PASS] UTL-002: SHA256空文件\n");
}

// ====== UTL-003: SHA256大文件 ======
void test_sha256_large() {
    std::string content(1024 * 1024, 'A'); // 1MB of 'A'
    std::string path = write_temp_file(content, "largefile");
    std::string hash = compute_sha256(path);
    std::remove(path.c_str());
    assert(hash.length() == 64);
    // 已知1MB 'A'的SHA256
    assert(hash == "b3106c0b878988430108d3e4a4e4d66c63ef6f84f5ff2e21ef9975acffe36222");
    printf("  [PASS] UTL-003: SHA256大文件(1MB)\n");
}

// ====== UTL-004: SHA256不存在的文件 ======
void test_sha256_not_found() {
    bool threw = false;
    try {
        compute_sha256("/tmp/nonexist_123456789");
    } catch (const std::runtime_error &e) {
        threw = true;
    }
    assert(threw);
    printf("  [PASS] UTL-004: SHA256不存在的文件\n");
}

// ====== UTL-005~010: mode转字符串 ======
void test_mode_string() {
    assert(mode_to_string(0644) == "rw-r--r--");
    assert(mode_to_string(0777) == "rwxrwxrwx");
    assert(mode_to_string(0000) == "---------");
    assert(mode_to_string(0755) == "rwxr-xr-x");
    assert(mode_to_string(0400) == "r--------");
    assert(mode_to_string(01777) == "rwxrwxrwt"); // sticky bit
    assert(mode_to_string(02755) == "rwxr-sr-x"); // setgid
    assert(mode_to_string(04755) == "rwsr-xr-x"); // setuid
    printf("  [PASS] UTL-005~012: mode转字符串全覆盖\n");
}

// ====== UTL-013: log_pass输出 ======
void test_log_pass() {
    // 只需确保不崩溃即可
    log_pass("TEST-RULE", "test message");
    printf("  [PASS] UTL-013: log_pass输出\n");
}

// ====== UTL-014: log_fail输出 ======
void test_log_fail() {
    log_fail("TEST-RULE", "test failure message");
    printf("  [PASS] UTL-014: log_fail输出\n");
}

int main() {
    printf("=== test_utils ===\n");
    test_sha256_hello();
    test_sha256_empty();
    test_sha256_large();
    test_sha256_not_found();
    test_mode_string();
    test_log_pass();
    test_log_fail();
    printf("=== all utils tests passed ===\n");
    return 0;
}
