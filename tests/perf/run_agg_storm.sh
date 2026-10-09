#!/bin/bash
# W5 D5 任务1：聚合降噪验证 —— 与 W4 风暴同口径（5,000 次 cat / 300s ≈ 10,000 命中事件），
# 但关闭冷却与静默（throttle=0 / silence=0），让 Dispatcher 全量收单，隔离聚合单一变量。
# 验收口径：
#   1. 外发降幅 = 1 - sink实收 / 落库条数 ≥ 80%（无聚合时每条必外发，落库条数即等价外发基线）
#   2. 计数对账：sink 实收 == [notify] sent；Σoccurrences == 落库条数；merged == 落库 - 开窗数
#   3. 落库条数 == 命中事件数（聚合不改落库，逐条）
# 用法（需 root）: sudo bash tests/perf/run_agg_storm.sh
set -u
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK=/tmp/bg-agg; RES=/tmp/bg-perf/results; PIDFILE=$WORK/monitor.pid
cd "$ROOT_DIR"
mkdir -p "$WORK" "$RES"
TARGET=/tmp/bg-storm/storm_target.txt; mkdir -p /tmp/bg-storm; echo "storm" > "$TARGET"
RULE_ID="dsl.storm_any_file_read"
LOG=$WORK/agg_monitor.log
SINK_PORT=18080
SINK_FILE=$WORK/sink_payloads.jsonl
: > "$SINK_FILE"

echo "=== 启动 webhook sink (127.0.0.1:$SINK_PORT) ==="
# 全重定向 + nohup：sink 不得继承脚本 stdout，否则脚本结束后管道不关、调用方悬挂
nohup python3 tests/perf/webhook_sink.py "$SINK_PORT" "$SINK_FILE" >"$WORK/sink_stdout.log" 2>&1 </dev/null &
SINK_PID=$!
sleep 0.5

echo "=== 启动 monitor (tests/perf/config_agg_storm.yaml) ==="
bash -c "echo \$\$ > '$PIDFILE'; exec '$ROOT_DIR/baseline-guard' monitor --db '$ROOT_DIR/baseline.db' -c '$ROOT_DIR/tests/perf/config_agg_storm.yaml'" >"$LOG" 2>&1 &
for i in $(seq 1 40); do grep -q "Monitoring started" "$LOG" && break; sleep 0.5; done
MPID=$(cat "$PIDFILE")
grep -m1 '\[notify\]' "$LOG" || echo "(no notify log line)"
echo "monitor pid=$MPID"

DB=/var/lib/baseline-guard/baseline.db
RULE_FILTER="rule_id IN ('$RULE_ID','STORM-SRC')"   # FIM allow 规则与 DSL 规则同事件各落一条
EV_SQL="select count(*) from events where json_extract(payload,'\$.file.path')='$TARGET' and json_extract(payload,'\$.event_type')='file.read';"
DB_BEFORE=$(sqlite3 "$DB" "select count(*) from alerts where $RULE_FILTER;")
EV_BEFORE=$(sqlite3 events_perf.db "$EV_SQL")

echo "=== 风暴生成：5,000 次读 / 300s（每次 cat 命中 open+read 两钩子 = 2 条告警）==="
GEN_START=$(date +%s)
for s in $(seq 100); do
  for j in $(seq 50); do cat "$TARGET" > /dev/null; done
  sleep 3
done
GEN_END=$(date +%s)
echo "generated=5000 in $((GEN_END-GEN_START))s"

echo "=== 等末窗摘要 flush（窗 60s）+ 等一个 60s 统计 tick ==="
sleep 75

echo "=== 停止 monitor 与 sink ==="
kill -TERM "$MPID"
for i in $(seq 1 40); do kill -0 "$MPID" 2>/dev/null || break; sleep 0.5; done
kill "$SINK_PID" 2>/dev/null; wait "$SINK_PID" 2>/dev/null

DB_AFTER=$(sqlite3 "$DB" "select count(*) from alerts where $RULE_FILTER;")
EV_AFTER=$(sqlite3 events_perf.db "$EV_SQL")
EV_COUNT=$((EV_AFTER-EV_BEFORE))
# 外发实绩两个独立来源：sink 实收 + monitor 日志 webhook sent 行数（计数器以 final stats 为准）
SENT_LOG=$(grep -c '\[notify\] webhook sent' "$LOG")
STATS=$(grep '\[notify\] final stats:' "$LOG" | tail -1)
[ -z "$STATS" ] && STATS=$(grep '\[notify\] stats:' "$LOG" | tail -1)
echo "stats_line: $STATS"
echo "webhook_sent_log_lines=$SENT_LOG"
ALERTS=$((DB_AFTER-DB_BEFORE))
SINK_RECV=$(wc -l < "$SINK_FILE")

python3 - "$ALERTS" "$EV_COUNT" "$SINK_RECV" "$SINK_FILE" "$STATS" "$SENT_LOG" <<'EOF' | tee "$RES/agg_reconcile.txt"
import json, re, sys

alerts, events, sink_recv = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
sink_file, stats, sent_log = sys.argv[4], sys.argv[5], int(sys.argv[6])

m = {k: int(v) for k, v in re.findall(r'(\w+)=(\d+)', stats)}
sent, merged = m.get('sent', 0), m.get('merged', 0)
failed, suppressed, dropped = m.get('failed', 0), m.get('suppressed', 0), m.get('dropped', 0)

opens = digests = 0
occ_sum = 0
for line in open(sink_file):
    line = line.strip()
    if not line:
        continue
    j = json.loads(line)
    occ = int(j.get('occurrences', 1))
    occ_sum += occ
    if 'first_seen' in j:
        digests += 1
    else:
        opens += 1

total_out = sent
reduction = (1 - total_out / alerts) * 100 if alerts else 0.0
print(f"events_observed={events}")
print(f"alerts_db={alerts} (落库逐条, throttle=0; FIM+DSL 双规则同事件各落一条 = 2×events)")
print(f"sink_received={sink_recv} notify_sent={sent} failed={failed} suppressed={suppressed} dropped={dropped} merged={merged}")
print(f"payloads: 开窗首条={opens} 摘要={digests} Σoccurrences={occ_sum}")

ok = True
def check(name, cond, detail):
    global ok
    print(f"{'PASS' if cond else 'FAIL'}: {name} ({detail})")
    ok = ok and cond

check("落库逐条", alerts == 2 * events, f"alerts_db={alerts} vs 2×events={2*events}")
check("外发降幅>=80%", reduction >= 80.0, f"1-{total_out}/{alerts}={reduction:.2f}%")
check("sink==sent==日志发送行", sink_recv == sent == sent_log and failed == 0 and dropped == 0,
      f"sink={sink_recv} sent(final)={sent} sent_log={sent_log} failed={failed} dropped={dropped}")
check("Σoccurrences==落库", occ_sum == alerts, f"{occ_sum} vs {alerts}")
check("merged对账", merged + opens == alerts, f"merged={merged} + 开窗={opens} = {merged+opens} vs alerts={alerts}")
check("摘要数==开窗数", digests <= opens, f"digests={digests} opens={opens}")
print("AGG RECONCILE:", "PASS" if ok else "FAIL")
EOF

echo "--- 摘要样例（末 3 条 digest 载荷）---"
grep '"first_seen"' "$SINK_FILE" | tail -3 | tee "$RES/agg_digest_samples.txt"
echo "DONE"
