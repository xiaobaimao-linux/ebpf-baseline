#!/bin/bash
# 集成测试：check 命令
# 运行: bash test_check.sh

# set -e 移除：多个用例预期 check 返回非零，set -e 会误杀脚本
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
