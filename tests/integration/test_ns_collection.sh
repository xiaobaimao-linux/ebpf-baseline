#!/usr/bin/env bash
# test_ns_collection.sh — 命名空间事件采集集成测试
#
# 覆盖验收项：
#   NS-001  mount -t tmpfs        → ns.mount（source/target/fstype/comm）
#   NS-002  unshare --mount --uts → ns.unshare（flags 解码含 NEWNS）
#   NS-003  nsenter -t 1 -m       → ns.setns（nstype 解码正确）
#   NEG-001 telemetry.privilege=false 重复触发 → 零 ns.* 日志
#
# 前置：make 已编译出 ./baseline-guard；以 root 运行（sudo bash tests/integration/test_ns_collection.sh）。
# 可重复执行：唯一挂载点（PID 派生）+ 日志行窗口标记防串扰 + trap EXIT 清理（杀进程、umount、删临时文件）。
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT" || exit 1

BIN="$REPO_ROOT/baseline-guard"
SRC_CFG="$REPO_ROOT/baselines/default.yaml"

if [[ $EUID -ne 0 ]]; then
    echo "请以 root 运行: sudo bash tests/integration/test_ns_collection.sh"
    exit 1
fi
if [[ ! -x "$BIN" ]]; then
    echo "未找到 $BIN，请先 make"
    exit 1
fi

WORK="$(mktemp -d /tmp/ns_col_test.XXXXXX)"
CFG_ON="$WORK/telemetry_on.yaml"
CFG_OFF="$WORK/telemetry_off.yaml"
LOG_ON="$WORK/monitor_on.log"
LOG_OFF="$WORK/monitor_off.log"
MNT="/tmp/mnt_ns_test_$$"   # 本进程唯一挂载点，防与其他用例/历史日志串扰

PASS=0
FAIL=0
WIN_START=1   # wait_line 的行窗口起点；各触发前更新为当前日志行号+1

ok()  { PASS=$((PASS + 1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }

cleanup() {
    pkill -x baseline-guard 2>/dev/null
    if mountpoint -q "$MNT" 2>/dev/null; then
        umount "$MNT" 2>/dev/null
    fi
    rm -rf "$WORK" "$MNT"
}
trap cleanup EXIT

# 防上次失败运行残留的 monitor 干扰本次断言
pkill -x baseline-guard 2>/dev/null
sleep 0.5

# ── 配置准备：ON=default.yaml 打开 privilege；OFF=原样（privilege: false）──
sed 's/^\([[:space:]]*\)privilege: false/\1privilege: true/' "$SRC_CFG" > "$CFG_ON"
cp "$SRC_CFG" "$CFG_OFF"
if ! grep -q '^[[:space:]]*privilege: true' "$CFG_ON" || ! grep -q '^[[:space:]]*privilege: false' "$CFG_OFF"; then
    echo "临时配置生成失败（sed privilege 开关未生效）"
    exit 1
fi

# wait_line LOG PATTERN TIMEOUT：自全局 WIN_START 行起在 LOG 中轮询含 PATTERN 的行；
# 命中则输出该行返回 0，超时返回 1。行窗口 + 唯一挂载点双重防串扰。
wait_line() {
    local log="$1" pat="$2" deadline=$((SECONDS + $3)) line=""
    while (( SECONDS < deadline )); do
        line=$(tail -n +"$WIN_START" "$log" 2>/dev/null | grep -m1 -F "$pat")
        if [[ -n "$line" ]]; then
            printf '%s' "$line"
            return 0
        fi
        sleep 0.2
    done
    return 1
}

wait_log() {  # wait_log LOG PATTERN TIMEOUT：只等行出现，不输出
    wait_line "$1" "$2" "$3" >/dev/null
}

dump_window() {  # 断言失败时打印窗口内事件行，便于定位
    echo "  --- 窗口内事件行（第 $WIN_START 行起）---"
    tail -n +"$WIN_START" "$1" 2>/dev/null | grep '"event_type"' | tail -5 | sed 's/^/  /'
    echo "  ---"
}

start_monitor() {  # start_monitor CFG LOG
    : > "$2"
    WIN_START=1   # 新日志文件，行窗口从头计
    "$BIN" --monitor -c "$1" > "$2" 2>&1 &
}

stop_monitor() {
    pkill -x baseline-guard 2>/dev/null
    sleep 0.5
}

# ═══════════════ 阶段 1：telemetry.privilege=true ═══════════════
echo "== 阶段 1: telemetry.privilege=true =="
start_monitor "$CFG_ON" "$LOG_ON"
if ! wait_log "$LOG_ON" "Monitoring started" 15; then
    bad "monitor 启动（Monitoring started 未出现）"
    tail -5 "$LOG_ON" | sed 's/^/  /'
    echo "结果: $PASS PASS, $FAIL FAIL"
    exit 1
fi
if ! wait_log "$LOG_ON" "[bpf_program_loaded] priv_watch attached" 15; then
    bad "priv_watch 挂载（attach 日志未出现）"
    tail -5 "$LOG_ON" | sed 's/^/  /'
    echo "结果: $PASS PASS, $FAIL FAIL"
    exit 1
fi
ok "monitor 启动且 priv_watch 已挂载"

# ── NS-001: mount → ns.mount ──
sleep 1
mkdir -p "$MNT"
WIN_START=$(( $(wc -l < "$LOG_ON") + 1 ))
mount -t tmpfs none "$MNT"
line=$(wait_line "$LOG_ON" "\"target\":\"$MNT\"" 6)
if [[ -z "$line" ]]; then
    bad "NS-001 ns.mount 事件未出现（target=$MNT）"
    dump_window "$LOG_ON"
elif grep -qF '"event_type":"ns.mount"' <<<"$line" \
  && grep -qF '"source":"none"' <<<"$line" \
  && grep -qF '"fstype":"tmpfs"' <<<"$line" \
  && grep -qF '"comm":"mount"' <<<"$line"; then
    ok "NS-001 ns.mount（source/target/fstype/comm 正确）"
else
    bad "NS-001 ns.mount 字段不匹配: $line"
fi
if mountpoint -q "$MNT"; then
    umount "$MNT"
fi

# ── NS-002: unshare --mount --uts → ns.unshare（flags=CLONE_NEWNS|CLONE_NEWUTS=0x04020000=67239936）──
sleep 1
WIN_START=$(( $(wc -l < "$LOG_ON") + 1 ))
unshare --mount --uts true
line=$(wait_line "$LOG_ON" '"event_type":"ns.unshare"' 6)
if [[ -z "$line" ]]; then
    bad "NS-002 ns.unshare 事件未出现"
    dump_window "$LOG_ON"
elif grep -qF '"comm":"unshare"' <<<"$line" \
  && grep -qF '"flags":67239936' <<<"$line" \
  && grep -qF '"names":["NEWNS","NEWUTS"]' <<<"$line"; then
    ok "NS-002 ns.unshare（flags 解码含 NEWNS）"
else
    bad "NS-002 ns.unshare 字段不匹配: $line"
fi

# ── NS-003: nsenter -t 1 -m → ns.setns（nstype=CLONE_NEWNS 0x20000=131072）──
sleep 1
WIN_START=$(( $(wc -l < "$LOG_ON") + 1 ))
nsenter -t 1 -m true
line=$(wait_line "$LOG_ON" '"event_type":"ns.setns"' 6)
if [[ -z "$line" ]]; then
    bad "NS-003 ns.setns 事件未出现"
    dump_window "$LOG_ON"
elif grep -qF '"comm":"nsenter"' <<<"$line" \
  && grep -qF '"nstype":131072' <<<"$line" \
  && grep -qF '"nstype_name":"NEWNS"' <<<"$line"; then
    ok "NS-003 ns.setns（nstype 解码正确）"
else
    bad "NS-003 ns.setns 字段不匹配: $line"
fi

stop_monitor

# ═══════════════ 阶段 2：telemetry.privilege=false（NEG-001）═══════════════
echo "== 阶段 2: telemetry.privilege=false =="
start_monitor "$CFG_OFF" "$LOG_OFF"
if ! wait_log "$LOG_OFF" "Monitoring started" 15; then
    bad "NEG-001 monitor 启动（Monitoring started 未出现）"
    tail -5 "$LOG_OFF" | sed 's/^/  /'
    echo "结果: $PASS PASS, $FAIL FAIL"
    exit 1
fi
if grep -q "priv_watch attached" "$LOG_OFF"; then
    bad "NEG-001 privilege=false 时 priv_watch 不应挂载"
fi
sleep 2   # 无 attach 日志可等，固定给 monitor 主循环留初始化时间

WIN_START=$(( $(wc -l < "$LOG_OFF") + 1 ))
mkdir -p "$MNT"
mount -t tmpfs none "$MNT"
unshare --mount --uts true
nsenter -t 1 -m true
sleep 3
if mountpoint -q "$MNT"; then
    umount "$MNT"
fi
if tail -n +"$WIN_START" "$LOG_OFF" | grep -q '"event_type":"ns\.'; then
    bad "NEG-001 privilege=false 仍出现 ns.* 事件"
    dump_window "$LOG_OFF"
else
    ok "NEG-001 privilege=false 零 ns.* 日志"
fi

stop_monitor

echo "结果: $PASS PASS, $FAIL FAIL"
[[ $FAIL -eq 0 ]]
