#!/bin/bash
# 集成测试：DNS 查询采集 + 权限事件四类遥测（setuid/capset/ptrace/module_load）
# 运行: sudo bash test_dns_priv_collection.sh
#
# 对应验收项：
#   DNS-001: dig <marker>.example.com → network.dns 事件，domain 含 example.com，
#            comm/pid 与 dig 一致
#   PRIV-001: sudo -u nobody id      → priv.setuid 事件，target_id == nobody 的 uid
#   PRIV-002: trig_capset（CAP_NET_RAW）→ priv.capset 事件，comm/pid 与 helper 一致
#   PRIV-003: trig_ptrace（ATTACH/DETACH）→ priv.ptrace 事件，
#            request=PTRACE_ATTACH，target_pid == 子进程 pid
#   PRIV-004: modprobe dummy         → priv.module_load 事件，name=dummy（测完 rmmod）
#   NEG-001: 两开关均 false           → 重复以上全部触发，无任何 network.dns / priv.* 日志
#
# 防串扰：$$ 唯一标记（查询域名/临时目录/配置文件/child pid 文件）；
#         断言精确匹配本脚本 monitor 日志中的 JSON 片段。
# 清理：trap EXIT 杀本脚本启动的进程、rmmod dummy（若测试前已加载则恢复）、删临时目录，
#       可重复执行。

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
BIN="$PROJECT_DIR/baseline-guard"
TMPDIR="/tmp/baseline_dnspriv_test_$$"
MONITOR_LOG="$TMPDIR/monitor.log"

MARKER="dp$$"
DNS_DOMAIN="${MARKER}.example.com"

FAIL_COUNT=0
SKIP_COUNT=0
MONITOR_PID=""
DUMMY_WAS_LOADED=0

cleanup() {
    [ -n "$MONITOR_PID" ] && kill -TERM "$MONITOR_PID" 2>/dev/null
    [ -n "$MONITOR_PID" ] && wait "$MONITOR_PID" 2>/dev/null
    rmmod dummy 2>/dev/null
    # 若测试前 dummy 已加载，恢复现场
    if [ "$DUMMY_WAS_LOADED" -eq 1 ]; then
        modprobe dummy 2>/dev/null
    fi
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

# 等待日志出现某片段，$1=pattern $2=timeout秒
wait_for_log() {
    local deadline=$((SECONDS + $2))
    while [ "$SECONDS" -lt "$deadline" ]; do
        grep -qF "$1" "$MONITOR_LOG" 2>/dev/null && return 0
        sleep 0.2
    done
    return 1
}

start_monitor() { # $1=network $2=dns $3=privilege
    local yaml="$TMPDIR/telemetry_${1}_${2}_${3}.yaml"
    cat > "$yaml" <<EOF
rules:
  - id: "DNSPRIV-TEST-001"
    name: "DNS/权限遥测测试占位规则"
    severity: "low"
    monitor:
      path: "$TMPDIR/marker_$MARKER.txt"
      events:
        - "read"
      action: "alert"
telemetry:
  network: $1
  dns: $2
  privilege: $3
EOF
    : > "$MONITOR_LOG"
    "$BIN" monitor -c "$yaml" > "$MONITOR_LOG" 2>&1 &
    MONITOR_PID=$!
    if ! wait_for_log "Monitoring started" 10; then
        echo "  [FAIL] monitor 启动失败（network=$1 dns=$2 privilege=$3）:"
        cat "$MONITOR_LOG"
        return 1
    fi
    return 0
}

stop_monitor() {
    [ -n "$MONITOR_PID" ] && kill -TERM "$MONITOR_PID" 2>/dev/null
    [ -n "$MONITOR_PID" ] && wait "$MONITOR_PID" 2>/dev/null
    MONITOR_PID=""
}

mkdir -p "$TMPDIR"
touch "$TMPDIR/marker_$MARKER.txt"

# ── 前置检查 ──────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo "=== 需要 root 运行（eBPF 加载）: sudo bash $0 ==="
    exit 2
fi

DNS_TOOL=""
if command -v dig >/dev/null 2>&1; then
    DNS_TOOL="dig"
elif command -v nslookup >/dev/null 2>&1; then
    DNS_TOOL="nslookup"
fi

HELPERS_BUILT=0
if command -v gcc >/dev/null 2>&1; then
    if gcc -O2 -Wall -o "$TMPDIR/trig_capset" "$SCRIPT_DIR/helpers/trig_capset.c" 2>"$TMPDIR/cc_capset.log" \
       && gcc -O2 -Wall -o "$TMPDIR/trig_ptrace" "$SCRIPT_DIR/helpers/trig_ptrace.c" 2>"$TMPDIR/cc_ptrace.log"; then
        HELPERS_BUILT=1
    else
        echo "  [WARN] helpers 编译失败:"
        cat "$TMPDIR"/cc_*.log
    fi
fi

SUDO_OK=0
command -v sudo >/dev/null 2>&1 && SUDO_OK=1
NOBODY_UID=""
if id nobody >/dev/null 2>&1; then
    NOBODY_UID=$(id -u nobody)
fi

if lsmod 2>/dev/null | awk '{print $1}' | grep -qx dummy; then
    DUMMY_WAS_LOADED=1
fi
DUMMY_OK=0
if [ -d /sys/module/dummy ] || modprobe -n dummy 2>/dev/null; then
    DUMMY_OK=1
fi

# ══════════════════════════════════════════════════════════════════
echo "=== DNS-001: dig 触发 network.dns ==="
if [ -z "$DNS_TOOL" ]; then
    echo "  [SKIP] DNS-001: 缺少 dig 与 nslookup"
    SKIP_COUNT=$((SKIP_COUNT+1))
elif ! start_monitor true true false; then
    FAIL_COUNT=$((FAIL_COUNT+1))
else
    "$DNS_TOOL" +time=2 +tries=1 "$DNS_DOMAIN" >/dev/null 2>&1 &
    DNS_PID=$!
    wait "$DNS_PID" 2>/dev/null
    sleep 1

    # dig 会把网络线程 comm 重命名为 isc-net-*（内核态真实值），归属以 exe 为准
    DNS_EXE=$(command -v "$DNS_TOOL")
    DNS_LINE=$(grep -F '"event_type":"network.dns"' "$MONITOR_LOG" \
               | grep -F "\"domain\":\"$DNS_DOMAIN\"" | head -1)
    if [ -n "$DNS_LINE" ] \
       && echo "$DNS_LINE" | grep -qF "\"pid\":$DNS_PID" \
       && echo "$DNS_LINE" | grep -qF "\"exe\":\"$DNS_EXE\""; then
        DNS_COMM=$(echo "$DNS_LINE" | sed -n 's/.*"comm":"\([^"]*\)".*/\1/p')
        echo "  [PASS] DNS-001: network.dns 命中（domain=$DNS_DOMAIN, pid=$DNS_PID, exe=$DNS_EXE, comm=$DNS_COMM）"
        echo "         $DNS_LINE"
    else
        echo "  [FAIL] DNS-001: 未找到期望的 network.dns 事件（domain=$DNS_DOMAIN, pid=$DNS_PID）"
        grep "network\." "$MONITOR_LOG" | tail -5
        FAIL_COUNT=$((FAIL_COUNT+1))
    fi
    stop_monitor
fi

# ══════════════════════════════════════════════════════════════════
echo "=== PRIV-001: sudo -u nobody 触发 priv.setuid ==="
if [ "$SUDO_OK" -eq 0 ] || [ -z "$NOBODY_UID" ]; then
    echo "  [SKIP] PRIV-001: 缺少 sudo 或 nobody 用户"
    SKIP_COUNT=$((SKIP_COUNT+1))
elif ! start_monitor false false true; then
    FAIL_COUNT=$((FAIL_COUNT+1))
else
    sudo -u nobody id >/dev/null 2>&1
    sleep 1

    # sudo 会依次调用 setuid(0)/setresuid(-1)/setgid/setuid(nobody)，
    # 只要存在任一 target_id==nobody uid 的 priv.setuid 事件即算命中
    SETUID_LINE=$(grep -F '"event_type":"priv.setuid"' "$MONITOR_LOG" \
                  | grep -F "\"target_id\":$NOBODY_UID" | head -1)
    if [ -n "$SETUID_LINE" ]; then
        echo "  [PASS] PRIV-001: priv.setuid 命中（target_id=$NOBODY_UID == nobody uid）"
        echo "         $SETUID_LINE"
    else
        echo "  [FAIL] PRIV-001: 未找到 target_id=$NOBODY_UID 的 priv.setuid 事件"
        grep "priv\." "$MONITOR_LOG" | tail -5
        FAIL_COUNT=$((FAIL_COUNT+1))
    fi
    stop_monitor
fi

# ══════════════════════════════════════════════════════════════════
echo "=== PRIV-002: trig_capset 触发 priv.capset ==="
if [ "$HELPERS_BUILT" -eq 0 ]; then
    echo "  [SKIP] PRIV-002: helpers 未编译成功"
    SKIP_COUNT=$((SKIP_COUNT+1))
elif ! start_monitor false false true; then
    FAIL_COUNT=$((FAIL_COUNT+1))
else
    "$TMPDIR/trig_capset" >"$TMPDIR/capset.out" 2>&1 &
    HELPER_PID=$!
    wait "$HELPER_PID" 2>/dev/null
    sleep 1

    CAPSET_LINE=$(grep -F '"event_type":"priv.capset"' "$MONITOR_LOG" \
                  | grep -F '"comm":"trig_capset"' \
                  | grep -F "\"pid\":$HELPER_PID" | head -1)
    if [ -n "$CAPSET_LINE" ]; then
        echo "  [PASS] PRIV-002: priv.capset 命中（comm=trig_capset, pid=$HELPER_PID, $(tail -1 "$TMPDIR/capset.out")）"
        echo "         $CAPSET_LINE"
    else
        echo "  [FAIL] PRIV-002: 未找到 comm=trig_capset 的 priv.capset 事件"
        grep "priv\." "$MONITOR_LOG" | tail -5
        FAIL_COUNT=$((FAIL_COUNT+1))
    fi
    stop_monitor
fi

# ══════════════════════════════════════════════════════════════════
echo "=== PRIV-003: trig_ptrace 触发 priv.ptrace ==="
if [ "$HELPERS_BUILT" -eq 0 ]; then
    echo "  [SKIP] PRIV-003: helpers 未编译成功"
    SKIP_COUNT=$((SKIP_COUNT+1))
elif ! start_monitor false false true; then
    FAIL_COUNT=$((FAIL_COUNT+1))
else
    "$TMPDIR/trig_ptrace" "$TMPDIR/child_$MARKER.pid" >/dev/null 2>&1
    CHILD_PID=$(cat "$TMPDIR/child_$MARKER.pid" 2>/dev/null)
    sleep 1

    PTRACE_LINE=""
    [ -n "$CHILD_PID" ] && \
        PTRACE_LINE=$(grep -F '"event_type":"priv.ptrace"' "$MONITOR_LOG" \
                      | grep -F '"request":"PTRACE_ATTACH"' \
                      | grep -F "\"target_pid\":$CHILD_PID" | head -1)
    if [ -n "$PTRACE_LINE" ]; then
        echo "  [PASS] PRIV-003: priv.ptrace 命中（request=PTRACE_ATTACH, target_pid=$CHILD_PID == 子进程 pid）"
        echo "         $PTRACE_LINE"
    else
        echo "  [FAIL] PRIV-003: 未找到 request=PTRACE_ATTACH/target_pid=$CHILD_PID 的 priv.ptrace 事件"
        grep "priv\." "$MONITOR_LOG" | tail -5
        FAIL_COUNT=$((FAIL_COUNT+1))
    fi
    stop_monitor
fi

# ══════════════════════════════════════════════════════════════════
echo "=== PRIV-004: modprobe dummy 触发 priv.module_load ==="
if [ "$DUMMY_OK" -eq 0 ]; then
    echo "  [SKIP] PRIV-004: dummy 模块不可用"
    SKIP_COUNT=$((SKIP_COUNT+1))
elif ! start_monitor false false true; then
    FAIL_COUNT=$((FAIL_COUNT+1))
else
    # 若 dummy 已加载，先移除再加载，确保 module_load 触发
    rmmod dummy 2>/dev/null
    sleep 0.5
    if ! modprobe dummy 2>"$TMPDIR/modprobe.log"; then
        echo "  [SKIP] PRIV-004: modprobe dummy 失败: $(cat "$TMPDIR/modprobe.log")"
        SKIP_COUNT=$((SKIP_COUNT+1))
        stop_monitor
    else
        sleep 1
        MOD_LINE=$(grep -F '"event_type":"priv.module_load"' "$MONITOR_LOG" | grep -F '"name":"dummy"' | head -1)
        if [ -n "$MOD_LINE" ]; then
            echo "  [PASS] PRIV-004: priv.module_load 命中（name=dummy）"
            echo "         $MOD_LINE"
        else
            echo "  [FAIL] PRIV-004: 未找到 name=dummy 的 priv.module_load 事件"
            grep "priv\." "$MONITOR_LOG" | tail -5
            FAIL_COUNT=$((FAIL_COUNT+1))
        fi
        rmmod dummy 2>/dev/null
        stop_monitor
    fi
fi

# ══════════════════════════════════════════════════════════════════
echo "=== NEG-001: telemetry 全关时零 DNS/权限事件 ==="
if ! start_monitor false false false; then
    FAIL_COUNT=$((FAIL_COUNT+1))
else
    # 依次重复以上全部触发
    if [ -n "$DNS_TOOL" ]; then
        "$DNS_TOOL" +time=2 +tries=1 "$DNS_DOMAIN" >/dev/null 2>&1 &
        wait $! 2>/dev/null
    fi
    [ "$SUDO_OK" -eq 1 ] && [ -n "$NOBODY_UID" ] && sudo -u nobody id >/dev/null 2>&1
    [ "$HELPERS_BUILT" -eq 1 ] && "$TMPDIR/trig_capset" >/dev/null 2>&1
    [ "$HELPERS_BUILT" -eq 1 ] && "$TMPDIR/trig_ptrace" "$TMPDIR/child_neg_$MARKER.pid" >/dev/null 2>&1
    if [ "$DUMMY_OK" -eq 1 ]; then
        rmmod dummy 2>/dev/null
        modprobe dummy 2>/dev/null
    fi
    sleep 2
    stop_monitor
    rmmod dummy 2>/dev/null

    if ! grep -qE '"event_type":"(network\.dns|priv\.)' "$MONITOR_LOG"; then
        echo "  [PASS] NEG-001: 两开关均 false，无任何 network.dns / priv.* 事件"
    else
        echo "  [FAIL] NEG-001: 开关全关时仍出现遥测事件"
        grep -E '"event_type":"(network\.dns|priv\.)' "$MONITOR_LOG" | tail -5
        FAIL_COUNT=$((FAIL_COUNT+1))
    fi
fi

# ── 汇总 ──────────────────────────────────────────────────────────
echo ""
if [ "$FAIL_COUNT" -eq 0 ]; then
    echo "=== DNS/权限采集测试完成: PASS（skip=$SKIP_COUNT）==="
    exit 0
else
    echo "=== DNS/权限采集测试完成: $FAIL_COUNT FAILED（skip=$SKIP_COUNT）==="
    exit 1
fi
