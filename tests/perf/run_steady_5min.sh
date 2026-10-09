#!/bin/bash
# W5 D5 任务2：常态 RSS / CPU 5 分钟空转测量。
# 全功能开：eBPF 探针 + DSL 规则引擎 + FIM 规则 + webhook 外发（本地 sink 待命）；
# 资产采集周期任务以每 60s 一次 asset collect 模拟（含 GPU 采集）。
# 采样：每 15s 取 VmRSS 与 /proc stat CPU 增量，输出 RSS 峰值与 CPU 均值（单核%）。
# 用法: sudo bash tests/perf/run_steady_5min.sh
set -u
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK=/tmp/bg-steady; RES=/tmp/bg-perf/results
mkdir -p "$WORK" "$RES"
cd "$ROOT_DIR"
LOG=$WORK/monitor.log
CFG=tests/perf/config_w5_smoke.yaml

echo "=== 启动 webhook sink 待命 ==="
nohup python3 tests/perf/webhook_sink.py 18080 "$WORK/sink.jsonl" >"$WORK/sink_stdout.log" 2>&1 </dev/null &
SINK_PID=$!
sleep 0.5

echo "=== 启动 monitor ($CFG) ==="
./baseline-guard monitor --db baseline.db -c "$CFG" >"$LOG" 2>&1 &
MPID=$!
for i in $(seq 1 40); do grep -q "Monitoring started" "$LOG" && break; sleep 0.5; done
grep -q "Monitoring started" "$LOG" || { echo "monitor 启动失败"; tail -5 "$LOG"; kill "$SINK_PID" 2>/dev/null; exit 1; }
echo "monitor pid=$MPID"

echo "=== 资产采集周期任务（每 60s，共 5 次）==="
( for i in $(seq 1 5); do ./baseline-guard asset collect -c "$CFG" >/dev/null 2>&1; sleep 60; done ) &
APID=$!

echo "=== 采样 5 分钟（15s × 20 点）==="
CLK=$(getconf CLK_TCK)
read_stat() { sed 's/.*) //' "/proc/$1/stat" | awk '{print $12+$13}'; }   # utime+stime（剔 comm）
PREV_J=$(read_stat "$MPID"); PREV_T=$(date +%s%N)
RSS_PEAK=0; CPU_SUM=0; N=0
for i in $(seq 1 20); do
  sleep 15
  RSS=$(awk '/VmRSS/{print $2}' "/proc/$MPID/status")
  J=$(read_stat "$MPID"); T=$(date +%s%N)
  CPU=$(awk -v dj=$((J-PREV_J)) -v dt=$((T-PREV_T)) -v clk="$CLK" 'BEGIN{printf "%.2f", dj/clk/(dt/1e9)*100}')
  [ "$RSS" -gt "$RSS_PEAK" ] && RSS_PEAK=$RSS
  CPU_SUM=$(awk -v s="$CPU_SUM" -v c="$CPU" 'BEGIN{printf "%.2f", s+c}')
  N=$((N+1)); PREV_J=$J; PREV_T=$T
  echo "  t+$((i*15))s RSS=${RSS}kB CPU=${CPU}%"
done
CPU_AVG=$(awk -v s="$CPU_SUM" -v n="$N" 'BEGIN{printf "%.2f", s/n}')

echo "=== 停止 ==="
kill -TERM "$MPID"; for i in $(seq 1 40); do kill -0 "$MPID" 2>/dev/null || break; sleep 0.5; done
kill "$APID" "$SINK_PID" 2>/dev/null; wait 2>/dev/null

{
  echo "rss_peak_mb=$(awk -v k="$RSS_PEAK" 'BEGIN{printf "%.1f", k/1024}')"
  echo "cpu_avg_pct=$CPU_AVG"
  echo "samples=$N"
} | tee "$RES/steady_5min.txt"
grep '\[notify\] stats' "$LOG" | tail -1 || true
echo "DONE"
