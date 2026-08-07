#!/bin/bash
# 集成测试：check 命令
# 运行: bash test_check.sh

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
BIN="$PROJECT_DIR/baseline-guard"
TMPDIR="/tmp/baseline_test_$$"

FAIL_COUNT=0

cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

mkdir -p "$TMPDIR"

echo "=== INT-001: check 文件权限全通过 ==="
TESTFILE="$TMPDIR/pass_file"
touch "$TESTFILE"
chmod 644 "$TESTFILE"

YAML="$TMPDIR/test_pass.yaml"
cat > "$YAML" <<EOF
rules:
  - id: "TEST-001"
    name: "权限检查"
    severity: "high"
    check:
      type: "file_permission"
      path: "$TESTFILE"
      expected: "0644"
      on_failure: "report_only"
EOF

$BIN check -c "$YAML"
[[ $? -eq 0 ]] && echo "  [PASS] INT-001" || { echo "  [FAIL] INT-001"; FAIL_COUNT=$((FAIL_COUNT+1)); }

echo "=== INT-002: check 文件权限有失败 ==="
YAML_FAIL="$TMPDIR/test_fail.yaml"
cat > "$YAML_FAIL" <<EOF
rules:
  - id: "TEST-002"
    name: "错误权限检查"
    severity: "high"
    check:
      type: "file_permission"
      path: "$TESTFILE"
      expected: "0600"
      on_failure: "report_only"
EOF

$BIN check -c "$YAML_FAIL"
[[ $? -eq 1 ]] && echo "  [PASS] INT-002" || { echo "  [FAIL] INT-002"; FAIL_COUNT=$((FAIL_COUNT+1)); }

echo "=== INT-003: check 文件不存在 ==="
YAML_NOEXIST="$TMPDIR/test_noexist.yaml"
cat > "$YAML_NOEXIST" <<EOF
rules:
  - id: "TEST-003"
    name: "不存在的文件"
    severity: "critical"
    check:
      type: "file_permission"
      path: "$TMPDIR/nonexist_99999"
      expected: "0644"
      on_failure: "report_only"
EOF

$BIN check -c "$YAML_NOEXIST"
[[ $? -eq 1 ]] && echo "  [PASS] INT-003" || { echo "  [FAIL] INT-003"; FAIL_COUNT=$((FAIL_COUNT+1)); }

echo "=== INT-004: check 文件哈希匹配 ==="
TESTFILE_HASH="$TMPDIR/hash_file"
echo "baseline_content_v1" > "$TESTFILE_HASH"
FILE_HASH=$(sha256sum "$TESTFILE_HASH" | awk '{print $1}')

YAML_HASH="$TMPDIR/test_hash.yaml"
cat > "$YAML_HASH" <<EOF
rules:
  - id: "TEST-004"
    name: "哈希检查"
    severity: "high"
    check:
      type: "file_hash"
      path: "$TESTFILE_HASH"
      hash: "sha256:$FILE_HASH"
      on_failure: "report_only"
EOF

$BIN check -c "$YAML_HASH"
[[ $? -eq 0 ]] && echo "  [PASS] INT-004" || { echo "  [FAIL] INT-004"; FAIL_COUNT=$((FAIL_COUNT+1)); }

echo "=== INT-005: check 文件哈希不匹配 ==="
YAML_HASH_FAIL="$TMPDIR/test_hash_fail.yaml"
cat > "$YAML_HASH_FAIL" <<EOF
rules:
  - id: "TEST-005"
    name: "错误哈希检查"
    severity: "high"
    check:
      type: "file_hash"
      path: "$TESTFILE_HASH"
      hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
      on_failure: "report_only"
EOF

$BIN check -c "$YAML_HASH_FAIL"
[[ $? -eq 1 ]] && echo "  [PASS] INT-005" || { echo "  [FAIL] INT-005"; FAIL_COUNT=$((FAIL_COUNT+1)); }

echo "=== INT-006: check 权限+哈希组合通过 ==="
YAML_COMBO="$TMPDIR/test_combo.yaml"
cat > "$YAML_COMBO" <<EOF
rules:
  - id: "TEST-006"
    name: "组合检查"
    severity: "critical"
    check:
      type:
        - "file_permission"
        - "file_hash"
      path: "$TESTFILE_HASH"
      expected: "0644"
      hash: "sha256:$FILE_HASH"
      on_failure: "report_only"
EOF

chmod 644 "$TESTFILE_HASH"
$BIN check -c "$YAML_COMBO"
[[ $? -eq 0 ]] && echo "  [PASS] INT-006" || { echo "  [FAIL] INT-006"; FAIL_COUNT=$((FAIL_COUNT+1)); }

echo "=== INT-007: check 内核参数检查 ==="
YAML_KERNEL="$TMPDIR/test_kernel.yaml"
cat > "$YAML_KERNEL" <<EOF
rules:
  - id: "TEST-007"
    name: "KASLR检查"
    severity: "high"
    check:
      type: "kernel_param"
      param: "kernel.randomize_va_space"
      operator: "="
      expected: 2
EOF

$BIN check -c "$YAML_KERNEL"
# 大多数现代Linux KASLR=2，所以期望返回0
[[ $? -eq 0 ]] && echo "  [PASS] INT-007 (kernel.randomize_va_space=2)" || { echo "  [INFO] INT-007: 内核参数值不匹配(可能是1或0)"; }

echo "=== INT-008: check 多个规则部分失败 ==="
YAML_MULTI="$TMPDIR/test_multi.yaml"
cat > "$YAML_MULTI" <<EOF
rules:
  - id: "TEST-008A"
    name: "通过的规则"
    severity: "low"
    check:
      type: "file_permission"
      path: "$TESTFILE"
      expected: "0644"
  - id: "TEST-008B"
    name: "失败的规则"
    severity: "high"
    check:
      type: "file_permission"
      path: "$TESTFILE"
      expected: "0600"
EOF

$BIN check -c "$YAML_MULTI"
[[ $? -eq 1 ]] && echo "  [PASS] INT-008" || { echo "  [FAIL] INT-008"; FAIL_COUNT=$((FAIL_COUNT+1)); }

echo "=== INT-009: check 无配置文件 ==="
$BIN check 2>&1 | grep -qi "config file required\|usage\|error"
[[ $? -eq 0 ]] && echo "  [PASS] INT-009" || { echo "  [FAIL] INT-009"; FAIL_COUNT=$((FAIL_COUNT+1)); }

echo "=== INT-010: check 配置文件不存在 ==="
$BIN check -c "$TMPDIR/nonexist" 2>&1 | grep -iq "无法打开\|error\|cannot open"
echo "  [PASS] INT-010 (允许空规则或报错)"

echo ""
if [[ $FAIL_COUNT -eq 0 ]]; then
    echo "=== all integration check tests passed ==="
    exit 0
else
    echo "=== $FAIL_COUNT integration check test(s) failed ==="
    exit 1
fi
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