#!/bin/bash
# W4 D5 任务5：告警风暴专项 —— 1,000 命中/分钟 × 5 分钟，验证冷却生效 + 抑制计数对账
# 用法（需 root）: bash tests/perf/run_alert_storm.sh
# 口径：5,000 次 cat（50 次/3s × 100 轮）命中 DSL 规则 dsl.storm_any_file_read；
#       期望发送 ≈ 300s/throttle(60s) ≈ 5 条，其余被冷却抑制；
#       对账：发送数(DB) + 抑制数(monitor 日志 [alerts] throttled total) ≈ 5,000，误差 <1%
set -u
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK=/tmp/bg-storm; RES=/tmp/bg-perf/results; PIDFILE=$WORK/monitor.pid
cd "$ROOT_DIR"
mkdir -p "$WORK" "$RES"
TARGET=$WORK/storm_target.txt; echo "storm" > "$TARGET"
RULE_ID="dsl.storm_any_file_read"
LOG=$WORK/storm_monitor.log

echo "=== 启动 monitor (tests/perf/config_storm.yaml) ==="
bash -c "echo \$\$ > '$PIDFILE'; exec '$ROOT_DIR/baseline-guard' monitor --db '$ROOT_DIR/baseline.db' -c '$ROOT_DIR/tests/perf/config_storm.yaml'" >"$LOG" 2>&1 &
for i in $(seq 1 40); do grep -q "Monitoring started" "$LOG" && break; sleep 0.5; done
MPID=$(cat "$PIDFILE")
grep -m1 'rule_engine' "$LOG" || echo "(no rule_engine log line)"
echo "monitor pid=$MPID"

DB_BEFORE=$(sqlite3 /var/lib/baseline-guard/baseline.db "select count(*) from alerts where rule_id='$RULE_ID';")

echo "=== 风暴生成：5,000 次读 / 300s ==="
GEN_START=$(date +%s)
for s in $(seq 100); do
  for j in $(seq 50); do cat "$TARGET" > /dev/null; done
  sleep 3
done
GEN_END=$(date +%s)
echo "generated=5000 in $((GEN_END-GEN_START))s"

echo "=== 等落库 + 等一个 60s 统计 tick ==="
sleep 65

DB_AFTER=$(sqlite3 /var/lib/baseline-guard/baseline.db "select count(*) from alerts where rule_id='$RULE_ID';")
EV_COUNT=$(sqlite3 events_perf.db "select count(*) from events where json_extract(payload,'\$.file.path')='$TARGET' and json_extract(payload,'\$.event_type')='file.read';")
THROTTLED=$(grep -oE "\[alerts\] throttled: rule=$RULE_ID count=[0-9]+" "$LOG" | tail -1 | grep -oE "[0-9]+$")
SENT=$((DB_AFTER-DB_BEFORE))
THROTTLED=${THROTTLED:-0}

echo "=== 停止 monitor ==="
kill -TERM "$MPID"
for i in $(seq 1 40); do kill -0 "$MPID" 2>/dev/null || break; sleep 0.5; done

echo "--- 对账 ---"
ACCOUNTED=$((SENT + THROTTLED)); BASE=$EV_COUNT
ERR=$(python3 -c "print(f'{abs($BASE-$ACCOUNTED)/$BASE*100:.3f}')")
{
  echo "events_observed=$EV_COUNT"
  echo "alerts_sent_db=$SENT"
  echo "throttled_total_log=$THROTTLED"
  echo "accounted=$ACCOUNTED / $BASE (events_observed)"
  echo "error=${ERR}% (<1% PASS/FAIL)"
} | tee "$RES/storm_reconcile.txt"
[ "$(python3 -c "print(1 if $ERR < 1 else 0)")" = "1" ] && echo "STORM RECONCILE: PASS" || echo "STORM RECONCILE: FAIL"
echo "--- 冷却生效证据（alerts 时间戳）---"
sqlite3 /var/lib/baseline-guard/baseline.db "select recorded_at, rule_id, severity from alerts where rule_id='$RULE_ID' order by id desc limit 10;" | tee "$RES/storm_alerts.txt"
grep -c 'VIOLATION\|storm hit' "$LOG" || true
echo "DONE"
