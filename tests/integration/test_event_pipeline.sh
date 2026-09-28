#!/bin/bash
# 集成测试：事件总线（解析→路由）+ 落库管道 + 进程树缓存 + 富化器
# 覆盖验收项：BUS-002 / BUS-003 / PIPE-001~004 / NEG-001
#
# 运行（需 root + BPF LSM）:
#   sudo bash tests/integration/test_event_pipeline.sh
#
# 设计：
#   - 唯一标记防串扰：每次运行用独立 TMPDIR（含 PID）+ 独立 events.db +
#     唯一域名 token（RUN_ID 派生），不与他人/前次运行的数据混淆。
#   - trap EXIT 清理：停 monitor、杀压测进程、删压测 db、还原现场。
#   - 可重复执行：全部现场现场自建自清，不依赖前次状态。

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
BIN="$PROJECT_DIR/baseline-guard"
FLOOD="$PROJECT_DIR/tests/integration/helpers/pipe_flood"
RUN_TESTS="$PROJECT_DIR/tests/run_tests.sh"
TEST_MONITOR="$SCRIPT_DIR/test_monitor.sh"
TEST_CHECK="$SCRIPT_DIR/test_check.sh"

TMPDIR="/tmp/baseline_pipeline_$$"
RUN_ID="$$$(date +%s)"
MON_PID=""
FAIL_COUNT=0
PASS_COUNT=0

# 唯一标记（防串扰）
DNS_TOKEN="pipe$RUN_ID.test.example.com"        # PIPE-001 dns
PID_TOKEN="pid$RUN_ID.test.example.com"         # PIPE-001 dns（pid 精确校验专用）
CHAIN_TOKEN="chain$RUN_ID.test.example.com"     # PIPE-002 dns
EVENTS_DB="$TMPDIR/events.db"
MON_LOG="$TMPDIR/monitor.log"
MON_CFG="$TMPDIR/monitor.yaml"
MONITORED="$TMPDIR/monitored.txt"

cleanup() {
    if [[ -n "$MON_PID" ]]; then
        kill -TERM "$MON_PID" 2>/dev/null
        for _ in {1..25}; do kill -0 "$MON_PID" 2>/dev/null || break; sleep 0.2; done
        kill -KILL "$MON_PID" 2>/dev/null
        wait "$MON_PID" 2>/dev/null
    fi
    pkill -x pipe_flood 2>/dev/null
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

pass() { echo "  [PASS] $1"; PASS_COUNT=$((PASS_COUNT+1)); }
fail() { echo "  [FAIL] $1"; FAIL_COUNT=$((FAIL_COUNT+1)); }
info() { echo "  [INFO] $1"; }

mkdir -p "$TMPDIR"

# sqlite3 查询辅助（抑制错误输出）
q() { sqlite3 "$1" "$2" 2>/dev/null; }

# 启动 monitor（telemetry 全开，store 按参数，独立 events.db）
start_monitor() {
    local store_flag="$1" db="$2"
    cat > "$MON_CFG" <<EOF
rules:
  - id: "PIPE-FILE-001"
    name: "pipeline file monitor"
    severity: "medium"
    monitor:
      path: "$MONITORED"
      events:
        - "write"
      action: "alert"
telemetry:
  network: true
  dns: true
  privilege: true
  store: $store_flag
  events_db: "$db"
  queue_hi: 32768
  queue_lo: 65536
  batch_size: 500
  batch_ms: 200
EOF
    echo "init" > "$MONITORED"
    "$BIN" monitor -c "$MON_CFG" > "$MON_LOG" 2>&1 &
    MON_PID=$!
    for _ in {1..50}; do
        grep -q "Monitoring started" "$MON_LOG" 2>/dev/null && return 0
        kill -0 "$MON_PID" 2>/dev/null || { echo "  monitor 启动失败"; return 1; }
        sleep 0.2
    done
    return 0
}

stop_monitor() {
    [[ -n "$MON_PID" ]] || return 0
    kill -TERM "$MON_PID" 2>/dev/null
    for _ in {1..25}; do kill -0 "$MON_PID" 2>/dev/null || break; sleep 0.2; done
    kill -KILL "$MON_PID" 2>/dev/null
    wait "$MON_PID" 2>/dev/null
    MON_PID=""
}

# 触发 PIPE-001 流量（curl/dig/sudo/unshare/mount/exec）
trigger_traffic() {
    local dns_domain="$1"
    curl -s -m 5 "http://1.1.1.1/?r=$RUN_ID" -o /dev/null 2>&1        # network connect（connect 即触发，不依赖外网连通）
    dig +short "$dns_domain" > /dev/null 2>&1                        # dns query
    sudo -u nobody id > /dev/null 2>&1                               # priv setuid
    unshare -m true 2>/dev/null                                      # ns unshare
    mkdir -p "$TMPDIR/mnt"
    unshare -m sh -c "mount -t tmpfs none '$TMPDIR/mnt' && umount '$TMPDIR/mnt'" 2>/dev/null  # ns mount
    /bin/true                                                        # process exec
}

echo "############################################################"
echo "# 事件总线 + 落库管道 + 进程树富化 集成测试 (RUN_ID=$RUN_ID)"
echo "############################################################"
echo "TMPDIR=$TMPDIR"

# ══════════════════════════════════════════════════════════════
echo "=== BUS-003: 既有回归（run_tests.sh + test_check.sh + test_monitor.sh）==="
# ══════════════════════════════════════════════════════════════
bash "$RUN_TESTS"   > "$TMPDIR/run_tests.log" 2>&1;   rc_run=$?
bash "$TEST_CHECK"  > "$TMPDIR/test_check.log" 2>&1;  rc_check=$?
bash "$TEST_MONITOR" > "$TMPDIR/test_monitor.log" 2>&1; rc_monitor=$?
if [[ $rc_run -eq 0 && $rc_check -eq 0 && $rc_monitor -eq 0 ]]; then
    pass "BUS-003: run_tests=$rc_run test_check=$rc_check test_monitor=$rc_monitor 全绿"
else
    fail "BUS-003: run_tests=$rc_run test_check=$rc_check test_monitor=$rc_monitor（详见 $TMPDIR/*.log）"
fi

# ══════════════════════════════════════════════════════════════
echo "=== PIPE-001: 各类遥测事件落库（network/dns/priv/ns/process exec）==="
# ══════════════════════════════════════════════════════════════
rm -f "$EVENTS_DB"
start_monitor true "$EVENTS_DB" || { fail "PIPE-001: monitor 启动失败"; }
sleep 1
dig +short "$PID_TOKEN" > /dev/null 2>&1 & DIG_PID=$!
trigger_traffic "$DNS_TOKEN"
wait $DIG_PID 2>/dev/null
sleep 2   # 等批量落库刷新（batch_ms=200ms，留余量）

# 各类行存在性
n_network=$(q "$EVENTS_DB" "SELECT count(*) FROM events WHERE category='network' AND action='connect';")
n_dns=$(q "$EVENTS_DB" "SELECT count(*) FROM events WHERE category='dns' AND action='query';")
n_priv=$(q "$EVENTS_DB" "SELECT count(*) FROM events WHERE category='priv' AND action='setuid';")
n_ns_unshare=$(q "$EVENTS_DB" "SELECT count(*) FROM events WHERE category='ns' AND action='unshare';")
n_ns_mount=$(q "$EVENTS_DB" "SELECT count(*) FROM events WHERE category='ns' AND action='mount';")
n_exec=$(q "$EVENTS_DB" "SELECT count(*) FROM events WHERE category='process' AND action='exec';")
# exe 正确（curl 发起 connect）
n_curl=$(q "$EVENTS_DB" "SELECT count(*) FROM events WHERE category='network' AND exe LIKE '%curl%';")
# pid 正确（专用 PID_TOKEN 的 dns 事件 pid == dig 进程 pid）
dns_pid=$(q "$EVENTS_DB" "SELECT pid FROM events WHERE category='dns' AND payload LIKE '%$PID_TOKEN%' ORDER BY ts_ns DESC LIMIT 1;")
# payload 可 json_extract（取 process.pid / dns.domain）
n_jsonpid=$(q "$EVENTS_DB" "SELECT count(*) FROM events WHERE json_extract(payload,'$.process.pid') IS NOT NULL;")
dns_domain=$(q "$EVENTS_DB" "SELECT json_extract(payload,'$.dns.domain') FROM events WHERE category='dns' AND payload LIKE '%$DNS_TOKEN%' ORDER BY ts_ns DESC LIMIT 1;")

p1_ok=1
[[ "$n_network" -gt 0 ]] || { fail "PIPE-001: 缺 network/connect 行"; p1_ok=0; }
[[ "$n_dns" -gt 0 ]]     || { fail "PIPE-001: 缺 dns/query 行"; p1_ok=0; }
[[ "$n_priv" -gt 0 ]]    || { fail "PIPE-001: 缺 priv/setuid 行"; p1_ok=0; }
[[ "$n_ns_unshare" -gt 0 || "$n_ns_mount" -gt 0 ]] || { fail "PIPE-001: 缺 ns(unshare/mount) 行"; p1_ok=0; }
[[ "$n_exec" -gt 0 ]]    || { fail "PIPE-001: 缺 process/exec 行"; p1_ok=0; }
[[ "$n_curl" -gt 0 ]]    || { fail "PIPE-001: network 行 exe 非 curl"; p1_ok=0; }
[[ "$dns_pid" == "$DIG_PID" ]] || { fail "PIPE-001: dns 事件 pid($dns_pid) != dig pid($DIG_PID)"; p1_ok=0; }
[[ "$n_jsonpid" -gt 0 ]] || { fail "PIPE-001: payload 无法 json_extract process.pid"; p1_ok=0; }
[[ "$dns_domain" == *"$DNS_TOKEN"* ]] || { fail "PIPE-001: dns.domain($dns_domain) 不含 token"; p1_ok=0; }
[[ $p1_ok -eq 1 ]] && pass "PIPE-001: network=$n_network dns=$n_dns priv=$n_priv ns(u/m)=$n_ns_unshare/$n_ns_mount exec=$n_exec curl=$n_curl dig_pid=$dns_pid json_extract=OK"

# ══════════════════════════════════════════════════════════════
echo "=== PIPE-002: 4 层 bash 嵌套 dig → 祖先链 ≥5 且自近及远 ==="
# ══════════════════════════════════════════════════════════════
# 5 层嵌套 bash：每层 'INNER & wait' 强制 fork 出独立子 bash（comm=bash），
# 避免 bash -c 对单命令 exec 优化导致中间层塌缩；dig 为最深叶子。
c="dig +short $CHAIN_TOKEN"
for _ in 1 2 3 4 5; do
    arg="$c & wait"
    c="bash -c $(printf '%q' "$arg")"
done
bash -c "$c" > /dev/null 2>&1
sleep 2

chain_payload=$(q "$EVENTS_DB" "SELECT payload FROM events WHERE category='dns' AND payload LIKE '%$CHAIN_TOKEN%' ORDER BY ts_ns DESC LIMIT 1;")
if [[ -z "$chain_payload" ]]; then
    fail "PIPE-002: 未找到 chain dns 事件（domain=$CHAIN_TOKEN）"
else
    alen=$(echo "$chain_payload" | jq '.process.ancestors | length' 2>/dev/null)
    nbash=$(echo "$chain_payload" | jq '[.process.ancestors[].comm] | map(select(.=="bash")) | length' 2>/dev/null)
    a0comm=$(echo "$chain_payload" | jq -r '.process.ancestors[0].comm' 2>/dev/null)
    dig_ppid=$(echo "$chain_payload" | jq '.process.ppid' 2>/dev/null)
    a0pid=$(echo "$chain_payload" | jq '.process.ancestors[0].pid' 2>/dev/null)
    p2_ok=1
    [[ "$alen" =~ ^[0-9]+$ && "$alen" -ge 5 ]] || { fail "PIPE-002: 祖先链长度 $alen < 5"; p2_ok=0; }
    [[ "$nbash" -ge 4 ]] || { fail "PIPE-002: 链中 bash 层数 $nbash < 4"; p2_ok=0; }
    [[ "$a0comm" == "bash" ]] || { fail "PIPE-002: 最近祖先 comm=$a0comm 非 bash"; p2_ok=0; }
    [[ "$a0pid" == "$dig_ppid" ]] || { fail "PIPE-002: 顺序非自近及远(ancestors[0].pid=$a0pid != dig.ppid=$dig_ppid)"; p2_ok=0; }
    [[ $p2_ok -eq 1 ]] && pass "PIPE-002: ancestors 长度=$alen bash层数=$nbash 最近祖先=bash(a0.pid=$a0pid==dig.ppid) 自近及远"
fi

# ══════════════════════════════════════════════════════════════
echo "=== BUS-002: 60s 内日志出现延迟统计行（queue/e2e avg/p95 非负）==="
# ══════════════════════════════════════════════════════════════
stats_found=""
for _ in {1..70}; do
    if grep -q "\[event_bus\] stats:" "$MON_LOG" 2>/dev/null; then stats_found=1; break; fi
    sleep 1
done
if [[ -n "$stats_found" ]]; then
    stats_line=$(grep "\[event_bus\] stats:" "$MON_LOG" | tail -1)
    # 解析 queue/e2e 的 avg 与 p95，校验非负数值
    qavg=$(echo "$stats_line"  | sed -nE 's/.*queue avg=([0-9.]+)us.*/\1/p')
    qp95=$(echo "$stats_line"  | sed -nE 's/.*queue avg=[0-9.]+us p95=([0-9]+)us.*/\1/p')
    eavg=$(echo "$stats_line"  | sed -nE 's/.*e2e avg=([0-9.]+)us.*/\1/p')
    ep95=$(echo "$stats_line"  | sed -nE 's/.*e2e avg=[0-9.]+us p95=([0-9]+)us.*/\1/p')
    if [[ -n "$qavg" && -n "$qp95" && -n "$eavg" && -n "$ep95" ]]; then
        pass "BUS-002: $stats_line"
    else
        fail "BUS-002: 统计行格式异常: $stats_line"
    fi
else
    fail "BUS-002: 60s 内未出现 [event_bus] stats 延迟统计行"
fi

# 停 monitor，避免干扰后续压测（CPU / 写库竞争）
stop_monitor

# ══════════════════════════════════════════════════════════════
echo "=== PIPE-003: 10,000 条/s × 60s → RSS<50% drop=0 对账闭合 查询P95<100ms ==="
# ══════════════════════════════════════════════════════════════
rm -f "$TMPDIR/flood3.db"
"$FLOOD" --rate 10000 --seconds 60 --category dns --db "$TMPDIR/flood3.db" --query > "$TMPDIR/flood3.log" 2>&1
f3_growth=$(grep "rss_kb:" "$TMPDIR/flood3.log" | sed -nE 's/.*growth=([0-9.]+)%.*/\1/p')
f3_drop=$(grep "drops:" "$TMPDIR/flood3.log" | sed -nE 's/.*total=([0-9]+).*/\1/p')
f3_recon=$(grep -c "reconcile: pushed==stored : YES" "$TMPDIR/flood3.log")
f3_qp95=$(grep "query_p95_ms" "$TMPDIR/flood3.log" | sed -nE 's/.*query_p95_ms=([0-9]+).*/\1/p')
f3_line=$(grep -E "attempted=|rss_kb:|reconcile:|query_p95_ms" "$TMPDIR/flood3.log" | tr '\n' ' ')
p3_ok=1
awk "BEGIN{exit !($f3_growth < 50)}"  || { fail "PIPE-003: RSS 增长 ${f3_growth}% >= 50%"; p3_ok=0; }
[[ "$f3_drop" == "0" ]]               || { fail "PIPE-003: drop=$f3_drop != 0"; p3_ok=0; }
[[ "$f3_recon" == "1" ]]              || { fail "PIPE-003: 对账未闭合"; p3_ok=0; }
[[ -n "$f3_qp95" && "$f3_qp95" -lt 100 ]] || { fail "PIPE-003: 查询 P95=${f3_qp95}ms >= 100ms"; p3_ok=0; }
[[ $p3_ok -eq 1 ]] && pass "PIPE-003: $f3_line"

# ══════════════════════════════════════════════════════════════
echo "=== PIPE-004: 50,000 条/s × 10s 突发 → lo drop>0 dns最高 hi drop=0 存活 ==="
# ══════════════════════════════════════════════════════════════
rm -f "$TMPDIR/flood4.db"
# --enrich：消费侧做真实富化（json 解析+祖先链），使消费吞吐低于突发速率，lo 队列才会溢出丢弃
"$FLOOD" --rate 50000 --seconds 10 --category mixed --enrich --db "$TMPDIR/flood4.db" > "$TMPDIR/flood4.log" 2>&1
f4_alive=$?
f4_line=$(grep "drops:" "$TMPDIR/flood4.log")
f4_hi_file=$(echo "$f4_line" | sed -nE 's/.*hi\(file=([0-9]+).*/\1/p')
f4_hi_ctrl=$(echo "$f4_line" | sed -nE 's/.*file=[0-9]+ ctrl=([0-9]+)\).*/\1/p')
f4_lo_net=$(echo "$f4_line"  | sed -nE 's/.*lo\(net=([0-9]+).*/\1/p')
f4_lo_dns=$(echo "$f4_line"  | sed -nE 's/.*net=[0-9]+ dns=([0-9]+)\).*/\1/p')
f4_stopped=$(grep -c "stopped=YES" "$TMPDIR/flood4.log")
p4_ok=1
[[ "$f4_alive" -eq 0 ]] || { fail "PIPE-004: 压测进程异常退出 code=$f4_alive"; p4_ok=0; }
[[ $((f4_lo_net + f4_lo_dns)) -gt 0 ]] || { fail "PIPE-004: lo 队列 drop=0（未发生丢弃）"; p4_ok=0; }
[[ "$f4_lo_dns" -gt "$f4_lo_net" ]] || { fail "PIPE-004: dns 丢弃($f4_lo_dns) 非最高(>net=$f4_lo_net)"; p4_ok=0; }
[[ "$f4_hi_file" == "0" && "$f4_hi_ctrl" == "0" ]] || { fail "PIPE-004: hi 队列 drop 非 0(file=$f4_hi_file ctrl=$f4_hi_ctrl)"; p4_ok=0; }
[[ "$f4_stopped" == "1" ]] || { fail "PIPE-004: 突发后 drop 未停止增长"; p4_ok=0; }
[[ $p4_ok -eq 1 ]] && pass "PIPE-004: lo drop(net=$f4_lo_net dns=$f4_lo_dns)>0 dns最高 hi drop=0 存活 drop停止"

# ══════════════════════════════════════════════════════════════
echo "=== NEG-001: telemetry.store=false → events.db 零增长 + 回归全绿 ==="
# ══════════════════════════════════════════════════════════════
NEG_DB="$TMPDIR/events_neg.db"
rm -f "$NEG_DB"
start_monitor false "$NEG_DB" || { fail "NEG-001: monitor 启动失败"; }
sleep 1
trigger_traffic "$DNS_TOKEN"
sleep 2
# store=false 时 EventStore 不创建，events.db 不应存在；若存在则行数必须为 0
if [[ ! -f "$NEG_DB" ]]; then
    pass "NEG-001: store=false 时 events.db 未创建（零增长）"
else
    neg_cnt=$(q "$NEG_DB" "SELECT count(*) FROM events;" 2>/dev/null); neg_cnt=${neg_cnt:-0}
    if [[ "$neg_cnt" == "0" ]]; then
        pass "NEG-001: store=false 时 events 行数=0（零增长）"
    else
        fail "NEG-001: store=false 时 events 行数=$neg_cnt（应零增长）"
    fi
fi
stop_monitor
# 回归全绿（test_monitor.sh 在默认 store=false 下跑文件路径）
bash "$TEST_MONITOR" > "$TMPDIR/test_monitor_neg.log" 2>&1; rc_neg=$?
[[ $rc_neg -eq 0 ]] && pass "NEG-001: 回归 test_monitor.sh 全绿(store=false)" || fail "NEG-001: 回归 test_monitor.sh 失败 code=$rc_neg"

echo ""
echo "############################################################"
if [[ $FAIL_COUNT -eq 0 ]]; then
    echo "# 全部通过：$PASS_COUNT 项 PASS / $FAIL_COUNT 项 FAIL"
    echo "############################################################"
    exit 0
else
    echo "# 存在失败：$PASS_COUNT 项 PASS / $FAIL_COUNT 项 FAIL"
    echo "############################################################"
    exit 1
fi
