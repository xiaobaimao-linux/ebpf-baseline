#!/bin/bash
# 端到端测试：完整工作流测试
# 运行: bash test_workflow.sh

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
BIN="$PROJECT_DIR/baseline-guard"
TMPDIR="/tmp/baseline_e2e_$$"

FAIL_COUNT=0

cleanup() {
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

mkdir -p "$TMPDIR"

echo "========================================"
echo "=== E2E-001: 首次check建立基线 ==="
echo "========================================"

TESTFILE="$TMPDIR/e2e_file.txt"
echo "baseline_v1" > "$TESTFILE"
chmod 644 "$TESTFILE"
FILE_HASH=$(sha256sum "$TESTFILE" | awk '{print $1}')

YAML="$TMPDIR/e2e_baseline.yaml"
cat > "$YAML" <<EOF
rules:
  - id: "E2E-001"
    name: "端到端基线检查"
    severity: "critical"
    check:
      type:
        - "file_permission"
        - "file_hash"
      path: "$TESTFILE"
      expected: "0644"
      hash: "sha256:$FILE_HASH"
      on_failure: "report_only"
EOF

$BIN check -c "$YAML"
if [[ $? -eq 0 ]]; then
    echo "  [PASS] E2E-001: 首次check通过，基线已建立"
else
    echo "  [FAIL] E2E-001: 首次check失败"
    FAIL_COUNT=$((FAIL_COUNT+1))
fi

echo ""
echo "========================================"
echo "=== E2E-002: 权限漂移检测 ==="
echo "========================================"

chmod 600 "$TESTFILE"

$BIN check -c "$YAML"
if [[ $? -eq 1 ]]; then
    echo "  [PASS] E2E-002: 检测到权限漂移 (0644 -> 0600)"
else
    echo "  [FAIL] E2E-002: 未检测到权限漂移"
    FAIL_COUNT=$((FAIL_COUNT+1))
fi

chmod 644 "$TESTFILE"

echo ""
echo "========================================"
echo "=== E2E-003: 内容篡改检测 ==="
echo "========================================"

echo "tampered_content" > "$TESTFILE"
chmod 644 "$TESTFILE"

$BIN check -c "$YAML"
if [[ $? -eq 1 ]]; then
    echo "  [PASS] E2E-003: 检测到内容篡改"
else
    echo "  [FAIL] E2E-003: 未检测到内容篡改"
    FAIL_COUNT=$((FAIL_COUNT+1))
fi

echo "baseline_v1" > "$TESTFILE"
chmod 644 "$TESTFILE"

echo ""
echo "========================================"
echo "=== E2E-004: 多规则场景 ==="
echo "========================================"

FILE1="$TMPDIR/multi1.txt"
FILE2="$TMPDIR/multi2.txt"
echo "file1" > "$FILE1"
echo "file2" > "$FILE2"
chmod 644 "$FILE1"
chmod 600 "$FILE2"

YAML_MULTI="$TMPDIR/e2e_multi.yaml"
cat > "$YAML_MULTI" <<EOF
rules:
  - id: "E2E-004A"
    name: "文件1检查"
    severity: "high"
    check:
      type: "file_permission"
      path: "$FILE1"
      expected: "0644"
  - id: "E2E-004B"
    name: "文件2检查"
    severity: "high"
    check:
      type: "file_permission"
      path: "$FILE2"
      expected: "0600"
EOF

$BIN check -c "$YAML_MULTI"
if [[ $? -eq 0 ]]; then
    echo "  [PASS] E2E-004: 多规则全部通过"
else
    echo "  [FAIL] E2E-004: 多规则有失败"
    FAIL_COUNT=$((FAIL_COUNT+1))
fi

echo ""
echo "========================================"
echo "=== E2E-005: 内核参数检查集成 ==="
echo "========================================"

YAML_KERNEL="$TMPDIR/e2e_kernel.yaml"
cat > "$YAML_KERNEL" <<EOF
rules:
  - id: "E2E-005"
    name: "内核参数检查"
    severity: "high"
    check:
      type: "kernel_param"
      param: "kernel.randomize_va_space"
      operator: ">="
      expected: 1
EOF

$BIN check -c "$YAML_KERNEL"
if [[ $? -eq 0 ]]; then
    echo "  [PASS] E2E-005: 内核参数检查通过 (KASLR已启用)"
else
    echo "  [INFO] E2E-005: 内核参数检查未通过 (可能KASLR未启用或值为0)"
fi

echo ""
echo "========================================"
if [[ $FAIL_COUNT -eq 0 ]]; then
    echo "=== All E2E tests passed ==="
    exit 0
else
    echo "=== $FAIL_COUNT E2E test(s) failed ==="
    exit 1
fi
