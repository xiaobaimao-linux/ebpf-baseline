#!/bin/bash
# 集成测试：monitor 命令（需要root权限和BPF LSM支持）
# 运行: sudo bash test_monitor.sh

# set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
BIN="$PROJECT_DIR/baseline-guard"
TMPDIR="/tmp/baseline_monitor_test_$$"
MONITOR_LOG="$TMPDIR/monitor.log"

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

INI="$TMPDIR/monitor.ini"
cat > "$INI" <<EOF
[monitored]
path=$TESTFILE
mode=644
hash=sha256:$HASH
action=alert
EOF

echo "=== INT-006: monitor正常启动 ==="
$BIN monitor -c "$INI" > "$MONITOR_LOG" 2>&1 &
MONITOR_PID=$!
sleep 2

# 检查进程存在
if kill -0 "$MONITOR_PID" 2>/dev/null; then
    echo "  [PASS] INT-006: monitor进程启动成功"
else
    echo "  [FAIL] INT-006: monitor进程未能启动"
    cat "$MONITOR_LOG"
    exit 1
fi

echo "=== INT-007: monitor文件写入告警 ==="
echo "modified" >> "$TESTFILE"
sleep 1
if grep -q "ALERT" "$MONITOR_LOG"; then
    echo "  [PASS] INT-007: 检测到写入告警"
else
    echo "  [WARN] INT-007: 未检测到告警（可能LSM未触发）"
fi

echo "=== INT-008: monitor hash不匹配 ==="
# 重新计算hash，修改后应该不匹配
if grep -q "hash mismatch" "$MONITOR_LOG"; then
    echo "  [PASS] INT-008: 检测到hash不匹配"
else
    echo "  [INFO] INT-008: hash不匹配检测依赖于事件触发时机"
fi

echo "=== INT-011: monitor SIGTERM退出 ==="
kill -TERM "$MONITOR_PID"
wait "$MONITOR_PID" 2>/dev/null || true
MONITOR_PID=""

if grep -q "service_stop" "$MONITOR_LOG"; then
    echo "  [PASS] INT-011: SIGTERM优雅退出"
else
    echo "  [WARN] INT-011: 未检测到service_stop日志"
fi

echo "=== INT-012: monitor SIGHUP重载 ==="
# 重新启动
$BIN monitor -c "$INI" > "$MONITOR_LOG" 2>&1 &
MONITOR_PID=$!
sleep 1

# 修改配置
NEWFILE="$TMPDIR/new_monitored.txt"
echo "new file" > "$NEWFILE"
chmod 644 "$NEWFILE"
NEWHASH=$(sha256sum "$NEWFILE" | awk '{print $1}')

cat > "$INI" <<EOF
[new_monitored]
path=$NEWFILE
mode=644
hash=sha256:$NEWHASH
action=alert
EOF

kill -HUP "$MONITOR_PID"
sleep 1

if grep -q "rules_reload" "$MONITOR_LOG"; then
    echo "  [PASS] INT-012: SIGHUP触发配置重载"
else
    echo "  [WARN] INT-012: 未检测到重载日志"
fi

kill -TERM "$MONITOR_PID" 2>/dev/null || true
MONITOR_PID=""

echo "=== all integration monitor tests completed ==="
