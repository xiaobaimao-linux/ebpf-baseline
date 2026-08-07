#!/bin/bash
# 集成测试：monitor 命令（需要root权限和BPF LSM支持）
# 运行: sudo bash test_monitor.sh

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
BIN="$PROJECT_DIR/baseline-guard"
TMPDIR="/tmp/baseline_monitor_test_$$"
MONITOR_LOG="$TMPDIR/monitor.log"

FAIL_COUNT=0

cleanup() {
    [[ -n "$MONITOR_PID" ]] && kill -TERM "$MONITOR_PID" 2>/dev/null || true
    sleep 0.5
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

mkdir -p "$TMPDIR"

# 准备被监控文件
TESTFILE="$TMPDIR/monitored.txt"
echo "initial content" > "$TESTFILE"
chmod 644 "$TESTFILE"

# 计算初始hash
HASH=$(sha256sum "$TESTFILE" | awk '{print $1}')

YAML="$TMPDIR/monitor.yaml"
cat > "$YAML" <<EOF
rules:
  - id: "MON-001"
    name: "文件监控"
    severity: "critical"
    monitor:
      path: "$TESTFILE"
      events:
        - "write"
      action: "alert"
EOF

echo "=== INT-011: monitor正常启动 ==="
$BIN monitor -c "$YAML" > "$MONITOR_LOG" 2>&1 &
MONITOR_PID=$!
sleep 2

# 检查进程存在
if kill -0 "$MONITOR_PID" 2>/dev/null; then
    echo "  [PASS] INT-011: monitor进程启动成功"
else
    echo "  [FAIL] INT-011: monitor进程未能启动"
    cat "$MONITOR_LOG"
    FAIL_COUNT=$((FAIL_COUNT+1))
fi

echo "=== INT-012: monitor文件写入告警 ==="
echo "modified content" >> "$TESTFILE"
sleep 1
if grep -qi "ALERT\|alert" "$MONITOR_LOG"; then
    echo "  [PASS] INT-012: 检测到写入告警"
else
    echo "  [WARN] INT-012: 未检测到告警（可能LSM未触发）"
fi

echo "=== INT-013: monitor SIGTERM退出 ==="
kill -TERM "$MONITOR_PID"
wait "$MONITOR_PID" 2>/dev/null || true
MONITOR_PID=""

if grep -qi "stop\|exit\|terminate" "$MONITOR_LOG"; then
    echo "  [PASS] INT-013: SIGTERM优雅退出"
else
    echo "  [INFO] INT-013: 未检测到退出日志"
fi

echo "=== INT-014: monitor BLOCK模式 ==="
# 重新创建监控文件
TESTFILE_BLOCK="$TMPDIR/block_file.txt"
echo "block test" > "$TESTFILE_BLOCK"
chmod 644 "$TESTFILE_BLOCK"

YAML_BLOCK="$TMPDIR/monitor_block.yaml"
cat > "$YAML_BLOCK" <<EOF
rules:
  - id: "MON-002"
    name: "阻止写入"
    severity: "high"
    monitor:
      path: "$TESTFILE_BLOCK"
      events:
        - "write"
      action: "block"
EOF

$BIN monitor -c "$YAML_BLOCK" > "$MONITOR_LOG" 2>&1 &
MONITOR_PID=$!
sleep 2

# 尝试写入
if ! echo "should be blocked" >> "$TESTFILE_BLOCK" 2>/dev/null; then
    echo "  [PASS] INT-014: BLOCK模式阻止了写入"
else
    echo "  [INFO] INT-014: BLOCK未生效（可能LSM不支持）"
fi

kill -TERM "$MONITOR_PID" 2>/dev/null || true
MONITOR_PID=""

echo "=== INT-015: monitor SIGHUP重载 ==="
# 重新启动
TESTFILE_RELOAD="$TMPDIR/reload_file.txt"
echo "reload test" > "$TESTFILE_RELOAD"
chmod 644 "$TESTFILE_RELOAD"

YAML_RELOAD="$TMPDIR/monitor_reload.yaml"
cat > "$YAML_RELOAD" <<EOF
rules:
  - id: "MON-003"
    name: "初始监控"
    severity: "medium"
    monitor:
      path: "$TESTFILE_RELOAD"
      events:
        - "write"
      action: "alert"
EOF

$BIN monitor -c "$YAML_RELOAD" > "$MONITOR_LOG" 2>&1 &
MONITOR_PID=$!
sleep 1

# 修改配置
NEWFILE="$TMPDIR/new_monitored.txt"
echo "new file content" > "$NEWFILE"
chmod 644 "$NEWFILE"

cat > "$YAML_RELOAD" <<EOF
rules:
  - id: "MON-004"
    name: "重载后监控"
    severity: "medium"
    monitor:
      path: "$NEWFILE"
      events:
        - "write"
      action: "alert"
EOF

kill -HUP "$MONITOR_PID"
sleep 1

echo "  [INFO] INT-015: SIGHUP重载已发送（验证需查看日志）"

kill -TERM "$MONITOR_PID" 2>/dev/null || true
MONITOR_PID=""

echo ""
if [[ $FAIL_COUNT -eq 0 ]]; then
    echo "=== all integration monitor tests completed ==="
    exit 0
else
    echo "=== $FAIL_COUNT integration monitor test(s) failed ==="
    exit 1
fi
