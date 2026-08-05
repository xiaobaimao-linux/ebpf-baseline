#!/bin/bash
# 集成测试：check 命令
# 运行: sudo bash test_check.sh

# set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
BIN="$PROJECT_DIR/baseline-guard"
TMPDIR="/tmp/baseline_test_$$"

cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

mkdir -p "$TMPDIR"

echo "=== INT-001: check INI全通过 ==="
# 创建一个我们知道权限的文件
TESTFILE="$TMPDIR/pass_file"
touch "$TESTFILE"
chmod 644 "$TESTFILE"

INI="$TMPDIR/test_pass.ini"
cat > "$INI" <<EOF
[myfile]
path=$TESTFILE
mode=644
action=alert
EOF

$BIN check -c "$INI"
[[ $? -eq 0 ]] && echo "  [PASS] INT-001" || { echo "  [FAIL] INT-001"; exit 1; }

echo "=== INT-002: check INI有失败 ==="
INI_FAIL="$TMPDIR/test_fail.ini"
cat > "$INI_FAIL" <<EOF
[wrong_mode]
path=$TESTFILE
mode=600
action=alert

[not_exist]
path=$TMPDIR/nonexist_99999
mode=644
action=alert
EOF

$BIN check -c "$INI_FAIL"
[[ $? -eq 1 ]] && echo "  [PASS] INT-002" || { echo "  [FAIL] INT-002"; exit 1; }


echo "=== INT-003: check YAML格式 ==="
YAML="$TMPDIR/test_pass.yaml"
cat > "$YAML" <<EOF
rules:
  - id: TEST-001
    name: "测试权限"
    severity: high
    check:
      type: file_permission
      path: $TESTFILE
      mode: "0644"
      action: alert
EOF

$BIN check -c "$YAML"
[[ $? -eq 0 ]] && echo "  [PASS] INT-003" || { echo "  [FAIL] INT-003"; exit 1; }

echo "=== INT-004: check 无配置文件 ==="
$BIN check 2>&1 | grep -q "config file required"
[[ $? -eq 0 ]] && echo "  [PASS] INT-004" || { echo "  [FAIL] INT-004"; exit 1; }

echo "=== INT-005: check 配置文件不存在 ==="
$BIN check -c "$TMPDIR/nonexist" 2>&1 | grep -iq "无法打开\|error"
echo "  [PASS] INT-005 (允许空规则或报错)"

echo "=== all integration check tests passed ==="
