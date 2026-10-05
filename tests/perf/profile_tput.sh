#!/bin/bash
# W4 D1 任务2 瓶颈测量：monitor 运行期间压测 + pidstat 按线程 + perf 采样。
# 用法: sudo bash tests/perf/profile_tput.sh [seconds] [rate]
set -u
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK=/tmp/bg-perf
RES=$WORK/results
PIDFILE=$WORK/profile.pid
SECS=${1:-30}
RATE=${2:-10000}
OPS=$((SECS * RATE))
cd "$ROOT_DIR"
mkdir -p "$RES"

echo "=== 启动 monitor ==="
bash -c "echo \$\$ > '$PIDFILE'; exec '$ROOT_DIR/baseline-guard' monitor --db '$ROOT_DIR/baseline.db' -c '$ROOT_DIR/tests/perf/config.yaml'" >"$WORK/profile_monitor.log" 2>&1 &
for i in $(seq 1 40); do
    grep -q "Monitoring started" "$WORK/profile_monitor.log" && break
    sleep 0.5
done
MPID=$(cat "$PIDFILE")
echo "monitor pid=$MPID"
sleep 2

echo "=== pidstat 按线程（5s 间隔）+ perf record 后台 ==="
pidstat -t -p "$MPID" 5 $((SECS / 5)) > "$RES/profile_pidstat.txt" 2>&1 &
PIDSTAT_PID=$!
perf record -F 99 -g -p "$MPID" -o "$RES/perf.data" -- sleep "$SECS" > /dev/null 2>&1 &
PERF_PID=$!

tests/perf/gen_load "$WORK/tput_target.txt" "$OPS" "$SECS" "$RATE" | tee "$RES/profile_load.txt"
wait "$PIDSTAT_PID" "$PERF_PID" 2>/dev/null

perf report -i "$RES/perf.data" --stdio --no-children 2>/dev/null | head -60 > "$RES/perf_report.txt"

echo "=== 停止 monitor ==="
./baseline-guard stats --drop > "$RES/profile_stats.txt" 2>/dev/null
kill -TERM "$MPID"
for i in $(seq 1 40); do kill -0 "$MPID" 2>/dev/null || break; sleep 0.5; done
echo "DONE"
