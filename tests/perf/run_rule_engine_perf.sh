#!/bin/bash
# W4 D4 任务4：规则引擎性能压测驱动
# 用法（需 root）: bash tests/perf/run_rule_engine_perf.sh <config> <label> [ops] [seconds] [rate]
# 例：bash tests/perf/run_rule_engine_perf.sh tests/perf/config_rules100.yaml on 3000000 300 10000
# 输出：原始数据落 /tmp/bg-perf/results/re_<label>_*.txt，stdout 只报聚合值
set -u
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CFG=${1:?usage: config label [ops] [seconds] [rate]}
LABEL=${2:?label}
OPS=${3:-3000000}; SECS=${4:-300}; RATE=${5:-10000}
WORK=/tmp/bg-perf; RES=$WORK/results; PIDFILE=$WORK/monitor.pid
cd "$ROOT_DIR"
mkdir -p "$RES" "$WORK"
TARGET="$WORK/tput_target.txt"; touch "$TARGET" "$WORK/lat_target.txt"

echo "=== [$LABEL] 启动 monitor ($CFG) ==="
bash -c "echo \$\$ > '$PIDFILE'; exec '$ROOT_DIR/baseline-guard' monitor --db '$ROOT_DIR/baseline.db' -c '$ROOT_DIR/$CFG'" >"$WORK/re_${LABEL}.log" 2>&1 &
for i in $(seq 1 40); do grep -q "Monitoring started" "$WORK/re_${LABEL}.log" && break; sleep 0.5; done
MPID=$(cat "$PIDFILE")
grep -m1 'rule_engine' "$WORK/re_${LABEL}.log" || echo "(no rule_engine log line)"
echo "monitor pid=$MPID"

echo "=== [$LABEL] 空闲 30s（稳态 CPU 采样）==="
sleep 24
pidstat -p "$MPID" 3 2 > "$RES/re_${LABEL}_idle_cpu.txt" 2>&1

echo "=== [$LABEL] 压测 $OPS ops / ${SECS}s / $RATE ops/s + 线程级 CPU 采样 ==="
./baseline-guard stats --drop > "$RES/re_${LABEL}_drop_before.txt"
EV_BEFORE=$(sqlite3 events_perf.db "select count(*) from events where json_extract(payload,'\$.file.path')='$TARGET';")
tests/perf/gen_load "$TARGET" "$OPS" "$SECS" "$RATE" > "$RES/re_${LABEL}_genload.txt" 2>&1 &
GL=$!
pidstat -t -p "$MPID" 10 $((SECS/10)) > "$RES/re_${LABEL}_load_cpu.txt" 2>&1
wait $GL
sleep 3
EV_AFTER=$(sqlite3 events_perf.db "select count(*) from events where json_extract(payload,'\$.file.path')='$TARGET';")
./baseline-guard stats --drop > "$RES/re_${LABEL}_drop_after.txt"
echo "RSS@end: $(grep VmRSS /proc/$MPID/status)"

echo "=== [$LABEL] 停止 monitor ==="
kill -TERM "$MPID"
for i in $(seq 1 40); do kill -0 "$MPID" 2>/dev/null || break; sleep 0.5; done

echo "--- [$LABEL] 聚合 ---"
echo "received=$((EV_AFTER-EV_BEFORE)) / $OPS"
echo "idle_cpu: $(grep -A3 'Average' "$RES/re_${LABEL}_idle_cpu.txt" | tail -1 | awk '{print $8"%"}')"
echo "load_cpu_threads:"
grep -aE '平均时间|Average' "$RES/re_${LABEL}_load_cpu.txt" | grep -v '%guest' | awk '{printf "  tid=%s usr=%s sys=%s total=%s cmd=%s\n", $4, $5, $6, $9, $11}' | sort -t= -k4 -rn | head -5
echo "drop_delta(hi): $(grep -oE 'bus.queue_full.hi.[a-z0-9_]+ = [0-9]+' "$RES/re_${LABEL}_drop_after.txt" | head -4)"
grep -iE 'drop|overflow' "$WORK/re_${LABEL}.log" | tail -3
echo "DONE $LABEL"
