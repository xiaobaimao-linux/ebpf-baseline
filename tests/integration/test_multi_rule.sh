#!/bin/bash
# 集成测试：同一文件多条监控规则应各自独立生效（R13 缺陷单：inode map 碰撞）
# 背景：monitor_actions map 以 inode 为 key、单 monitor_rule 为 value，
#       同文件多条规则后写覆盖先写（BPF 侧与用户态 FileRuleTable 均 last-wins）。
# 运行: sudo bash tests/integration/test_multi_rule.sh

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
BIN="$PROJECT_DIR/baseline-guard"
TMPDIR="/tmp/baseline_multirule_test_$$"
MONITOR_LOG="$TMPDIR/monitor.log"
MONITOR_PID=""
FAIL_COUNT=0

cleanup() {
    [[ -n "$MONITOR_PID" ]] && kill -TERM "$MONITOR_PID" 2>/dev/null || true
    sleep 0.5
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

mkdir -p "$TMPDIR"

F1="$TMPDIR/multi_target.txt"    # read + write + chmod 三条规则
F2="$TMPDIR/multi_target2.txt"   # 两条 write 规则（同事件类型多规则）
echo "init" > "$F1"
echo "init" > "$F2"
chmod 644 "$F1" "$F2"

YAML="$TMPDIR/multi_rule.yaml"
cat > "$YAML" <<EOF
rules:
  - id: "MR-READ-001"
    name: "多规则-读"
    severity: "high"
    monitor:
      path: "$F1"
      events: ["read"]
      action: "alert"
  - id: "MR-WRITE-001"
    name: "多规则-写"
    severity: "critical"
    monitor:
      path: "$F1"
      events: ["write"]
      action: "alert"
  - id: "MR-CHMOD-001"
    name: "多规则-chmod"
    severity: "medium"
    monitor:
      path: "$F1"
      events: ["chmod"]
      action: "alert"
  - id: "MR-W2-001"
    name: "双写规则-甲"
    severity: "high"
    monitor:
      path: "$F2"
      events: ["write"]
      action: "alert"
  - id: "MR-W2-002"
    name: "双写规则-乙"
    severity: "medium"
    monitor:
      path: "$F2"
      events: ["write"]
      action: "alert"
EOF

"$BIN" monitor -c "$YAML" > "$MONITOR_LOG" 2>&1 &
MONITOR_PID=$!
sleep 2
if ! kill -0 "$MONITOR_PID" 2>/dev/null; then
    echo "  [FAIL] MR-000: monitor 未能启动"
    cat "$MONITOR_LOG"
    exit 1
fi
echo "=== 触发：cat(read) / 追加(write) / chmod / F2 写入 ==="
cat "$F1" > /dev/null
sleep 0.3
echo "x" >> "$F1"
sleep 0.3
chmod 600 "$F1"
sleep 0.3
echo "x" >> "$F2"
sleep 2

READ_N=$(grep -c "VIOLATION: $F1 .*-> read" "$MONITOR_LOG" || true)
WRITE_F1_N=$(grep "VIOLATION: $F1 " "$MONITOR_LOG" | grep -c "\-> write" || true)
TOTAL_F1_N=$(grep -c "VIOLATION: $F1 " "$MONITOR_LOG" || true)
WRITE_F2_N=$(grep -c "VIOLATION: $F2 " "$MONITOR_LOG" || true)

echo "read告警=$READ_N F1write告警=$WRITE_F1_N F1总告警=$TOTAL_F1_N F2write告警=$WRITE_F2_N"

echo "=== MR-101: read 规则独立生效 ==="
if [[ "$READ_N" -ge 1 ]]; then
    echo "  [PASS] MR-101: read 事件触发 read 规则告警"
else
    echo "  [FAIL] MR-101: read 事件无告警（read 规则被同 inode 其他规则覆盖）"
    FAIL_COUNT=$((FAIL_COUNT+1))
fi

echo "=== MR-102: write 规则独立生效 ==="
if [[ "$WRITE_F1_N" -ge 1 ]]; then
    echo "  [PASS] MR-102: write 事件触发 write 规则告警"
else
    echo "  [FAIL] MR-102: write 事件无告警"
    FAIL_COUNT=$((FAIL_COUNT+1))
fi

echo "=== MR-103: chmod 规则独立生效（F1 至少 3 条告警）==="
if [[ "$TOTAL_F1_N" -ge 3 ]]; then
    echo "  [PASS] MR-103: read/write/chmod 三条规则均生效"
else
    echo "  [FAIL] MR-103: F1 告警数 $TOTAL_F1_N < 3（有规则被覆盖）"
    FAIL_COUNT=$((FAIL_COUNT+1))
fi

echo "=== MR-104: 同事件类型双规则各自告警（F2 恰好 2 条）==="
if [[ "$WRITE_F2_N" -eq 2 ]]; then
    echo "  [PASS] MR-104: 两条 write 规则各自独立告警"
else
    echo "  [FAIL] MR-104: F2 write 告警数 $WRITE_F2_N != 2"
    FAIL_COUNT=$((FAIL_COUNT+1))
fi

if [[ "$FAIL_COUNT" -eq 0 ]]; then
    echo "test_multi_rule: all tests passed"
else
    echo "test_multi_rule: $FAIL_COUNT test(s) failed"
fi
exit "$FAIL_COUNT"
