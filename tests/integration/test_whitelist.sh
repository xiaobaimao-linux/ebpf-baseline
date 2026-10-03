#!/bin/bash
# 集成测试：进程白名单过滤 + SIGHUP 热加载（需要 root 和 BPF LSM 支持）
# 运行: sudo bash test_whitelist.sh
# 覆盖: WL-001~005（白名单抑制 / 未豁免告警 / 父链维度 / 伪装防护 / 热加载）

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
BIN="$PROJECT_DIR/baseline-guard"
WLDIR="/tmp/wl_$$"
MONITOR_LOG="$WLDIR/monitor.log"
HELPERS_DIR="$SCRIPT_DIR/helpers"
WL_WRITER="$HELPERS_DIR/wl_writer"
WL_PARENT="$HELPERS_DIR/wl_parent"

FAIL_COUNT=0
MONITOR_PID=""

cleanup() {
    [[ -n "$MONITOR_PID" ]] && kill -TERM "$MONITOR_PID" 2>/dev/null || true
    sleep 0.3
    rm -rf "$WLDIR"
}
trap cleanup EXIT

mkdir -p "$WLDIR"
make -C "$PROJECT_DIR" wl_helpers >/dev/null   # 确保 wl_writer/wl_parent 已编译

PROTECTED="$WLDIR/protected.txt"
echo "initial" > "$PROTECTED"
chmod 644 "$PROTECTED"

YAML="$WLDIR/wl.yaml"

# 各版本 whitelist 片段（4 空格缩进起，供 write_yaml 内嵌）
wl_tee_block() {
    cat <<EOF
    whitelist:
      - exe: "/usr/bin/tee"
EOF
}

wl_tee_writer_block() {
    cat <<EOF
    whitelist:
      - exe: "/usr/bin/tee"
      - exe: "$WL_WRITER"
        parent_chain:
          - "$WL_PARENT"
EOF
}

wl_tee_writer_dd_block() {
    cat <<EOF
    whitelist:
      - exe: "/usr/bin/tee"
      - exe: "$WL_WRITER"
        parent_chain:
          - "$WL_PARENT"
      - exe: "/usr/bin/dd"
EOF
}

# $1 = whitelist 片段（空串则无白名单）
write_yaml() {
    cat > "$YAML" <<EOF
rules:
  - id: "WL-TEST-001"
    name: "白名单测试规则"
    severity: "medium"
    monitor:
      path: "$PROTECTED"
      events:
        - "write"
      action: "alert"
$1
EOF
}

start_monitor() {
    $BIN monitor -c "$YAML" > "$MONITOR_LOG" 2>&1 &
    MONITOR_PID=$!
    sleep 2
}

stop_monitor() {
    [[ -n "$MONITOR_PID" ]] && kill -TERM "$MONITOR_PID" 2>/dev/null || true
    wait "$MONITOR_PID" 2>/dev/null || true
    MONITOR_PID=""
}

violation_count() {
    grep -c "VIOLATION: $PROTECTED " "$MONITOR_LOG" 2>/dev/null || true
}

hup_and_wait() {
    kill -HUP "$MONITOR_PID"
    sleep 1
}

# ═══ 阶段 A：WL-001 tee 白名单抑制 + WL-002 dd 不在白名单告警 ═══
write_yaml "$(wl_tee_block)"
start_monitor
BASE_PID="$MONITOR_PID"

echo "=== WL-001: 白名单进程写文件被抑制（dd 对照证明事件通道活跃）==="
V_BEFORE=$(violation_count)
echo "x" | /usr/bin/tee "$PROTECTED" >/dev/null
sleep 1
V_TEE=$(violation_count)
/usr/bin/dd if=/dev/zero of="$PROTECTED" bs=1 count=1 conv=notrunc 2>/dev/null
sleep 1
V_DD=$(violation_count)
if [[ "$V_TEE" == "$V_BEFORE" ]] && [[ "$V_DD" -gt "$V_TEE" ]]; then
    echo "  [PASS] WL-001: tee 写未产生告警（抑制），dd 对照告警正常（通道活跃）"
else
    echo "  [FAIL] WL-001: 期望 tee 抑制+dd 告警，VIOLATION $V_BEFORE→tee:$V_TEE→dd:$V_DD"
    FAIL_COUNT=$((FAIL_COUNT+1))
fi

echo "=== WL-002: 非白名单进程写文件产生告警 ==="
V_BEFORE=$(violation_count)
/usr/bin/dd if=/dev/zero of="$PROTECTED" bs=1 count=1 conv=notrunc 2>/dev/null
sleep 1
if [[ "$(violation_count)" -gt "$V_BEFORE" ]] && grep -q "VIOLATION: $PROTECTED .* by dd/" "$MONITOR_LOG"; then
    echo "  [PASS] WL-002: dd 写产生告警（含 comm/pid 上下文）"
else
    echo "  [FAIL] WL-002: 期望 dd 告警，实际 VIOLATION=$(violation_count)"
    FAIL_COUNT=$((FAIL_COUNT+1))
fi

# ═══ 阶段 B：WL-003 父链维度（HUP 热加载加入 writer/parent 条目）═══
write_yaml "$(wl_tee_writer_block)"
hup_and_wait
if ! grep -q "config reloaded (1 rules)" "$MONITOR_LOG"; then
    echo "  [FAIL] WL-003 前置: 热加载未生效"
    FAIL_COUNT=$((FAIL_COUNT+1))
fi

echo "=== WL-003: parent_chain 父链维度 ==="
V_BEFORE=$(violation_count)
"$WL_PARENT" "$WL_WRITER" "$PROTECTED"
sleep 1
if [[ "$(violation_count)" == "$V_BEFORE" ]]; then
    echo "  [PASS] WL-003a: 经 wl_parent 调用 wl_writer 被抑制（父链命中）"
else
    echo "  [FAIL] WL-003a: 经父进程调用应被抑制，VIOLATION $V_BEFORE→$(violation_count)"
    FAIL_COUNT=$((FAIL_COUNT+1))
fi

V_BEFORE=$(violation_count)
"$WL_WRITER" "$PROTECTED"
sleep 1
if [[ "$(violation_count)" -gt "$V_BEFORE" ]]; then
    echo "  [PASS] WL-003b: 直接调用 wl_writer 产生告警（无父链）"
else
    echo "  [FAIL] WL-003b: 直接调用应告警，实际 VIOLATION=$(violation_count)"
    FAIL_COUNT=$((FAIL_COUNT+1))
fi

# ═══ 阶段 C：WL-004 伪装防护（cp 副本路径不同 → 不豁免）═══
echo "=== WL-004: 复制体 tee 不豁免（按路径非文件名匹配）==="
cp /usr/bin/tee "$WLDIR/tee_copy"
chmod 755 "$WLDIR/tee_copy"
V_BEFORE=$(violation_count)
echo "x" | "$WLDIR/tee_copy" "$PROTECTED" >/dev/null
sleep 1
if [[ "$(violation_count)" -gt "$V_BEFORE" ]]; then
    echo "  [PASS] WL-004: 副本 tee 写照常告警"
else
    echo "  [FAIL] WL-004: 副本 tee 应按路径不匹配告警，实际 VIOLATION=$(violation_count)"
    FAIL_COUNT=$((FAIL_COUNT+1))
fi

# ═══ 阶段 D：WL-005 热加载全周期（monitor pid 不变）═══
echo "=== WL-005: SIGHUP 热加载（加条目→删条目→改坏语法）==="
write_yaml "$(wl_tee_writer_dd_block)"    # ① 加入 dd 白名单
hup_and_wait
V_BEFORE=$(violation_count)
/usr/bin/dd if=/dev/zero of="$PROTECTED" bs=1 count=1 conv=notrunc 2>/dev/null
sleep 1
if [[ "$(violation_count)" == "$V_BEFORE" ]] && kill -0 "$MONITOR_PID" 2>/dev/null && [[ "$MONITOR_PID" == "$BASE_PID" ]]; then
    echo "  [PASS] WL-005a: 加白名单条目+HUP 后 dd 由告警变抑制（pid=$MONITOR_PID 不变）"
else
    echo "  [FAIL] WL-005a: 期望抑制且进程不重启，VIOLATION $V_BEFORE→$(violation_count)"
    FAIL_COUNT=$((FAIL_COUNT+1))
fi

write_yaml "$(wl_tee_writer_block)"       # ② 删除 dd 白名单条目
hup_and_wait
V_BEFORE=$(violation_count)
/usr/bin/dd if=/dev/zero of="$PROTECTED" bs=1 count=1 conv=notrunc 2>/dev/null
sleep 1
if [[ "$(violation_count)" -gt "$V_BEFORE" ]] && [[ "$MONITOR_PID" == "$BASE_PID" ]]; then
    echo "  [PASS] WL-005b: 删除条目+HUP 后 dd 恢复告警（pid 不变）"
else
    echo "  [FAIL] WL-005b: 期望恢复告警，VIOLATION $V_BEFORE→$(violation_count)"
    FAIL_COUNT=$((FAIL_COUNT+1))
fi

cat > "$YAML" <<EOF                       # ③ 改坏 yaml 语法
rules:
  - id: "WL-TEST-001"
    name: "坏配置"
    monitor: [}
EOF
hup_and_wait
V_BEFORE=$(violation_count)
/usr/bin/dd if=/dev/zero of="$PROTECTED" bs=1 count=1 conv=notrunc 2>/dev/null
sleep 1
if grep -q "config_reload.*失败" "$MONITOR_LOG" && [[ "$(violation_count)" -gt "$V_BEFORE" ]] && [[ "$MONITOR_PID" == "$BASE_PID" ]]; then
    echo "  [PASS] WL-005c: 坏语法+HUP 报 error 且旧配置继续生效（pid 不变）"
else
    echo "  [FAIL] WL-005c: 期望 error 日志+旧配置告警，VIOLATION $V_BEFORE→$(violation_count)"
    grep -q "config_reload.*失败" "$MONITOR_LOG" || echo "       （缺 error 日志）"
    FAIL_COUNT=$((FAIL_COUNT+1))
fi

stop_monitor

echo ""
if [[ $FAIL_COUNT -eq 0 ]]; then
    echo "=== all whitelist integration tests passed ==="
    exit 0
else
    echo "=== $FAIL_COUNT whitelist integration test(s) failed ==="
    exit 1
fi
