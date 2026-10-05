#!/bin/bash
# W3 性能基线编排：在 monitor 运行期间完成全部 4 项指标测量。
# 用法: sudo -n bash tests/perf/run_perf.sh
# 产出: /tmp/bg-perf/results/{lat_off,lat_on,tput,cpu,rss}.txt + monitor_perf.log
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK=/tmp/bg-perf
RES=$WORK/results
PIDFILE=$WORK/monitor.pid
cd "$ROOT_DIR"
mkdir -p "$RES"

echo "=== [0] Agent OFF 基线延迟 ==="
tests/perf/bench_lat "$WORK/lat_target.txt" 10000 | tee "$RES/lat_off.txt"

echo "=== [1] 启动 monitor ==="
if [ "$(id -u)" -eq 0 ]; then
    bash -c "echo \$\$ > '$PIDFILE'; exec '$ROOT_DIR/baseline-guard' monitor --db '$ROOT_DIR/baseline.db' -c '$ROOT_DIR/tests/perf/config.yaml'" >"$WORK/monitor_perf.log" 2>&1 &
else
    sudo -n bash -c "echo \$\$ > '$PIDFILE'; exec '$ROOT_DIR/baseline-guard' monitor --db '$ROOT_DIR/baseline.db' -c '$ROOT_DIR/tests/perf/config.yaml'" >"$WORK/monitor_perf.log" 2>&1 &
fi
for i in $(seq 1 40); do
    grep -q "Monitoring started" "$WORK/monitor_perf.log" && break
    sleep 0.5
done
MPID=$(cat "$PIDFILE")
grep -o 'LSM (ring buffer)\|LSM (perf buffer)\|kprobe mode' "$WORK/monitor_perf.log" | head -1 | tee "$RES/probe_mode.txt"
echo "monitor pid=$MPID"

echo "=== [2] Agent ON 延迟（受监控文件）=="
sleep 1
tests/perf/bench_lat "$WORK/lat_target.txt" 10000 | tee "$RES/lat_on.txt"

echo "=== [3] 吞吐压测 ==="
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo -n"; fi
$SUDO ./baseline-guard stats --drop > "$RES/drop_before.txt"
EV_BEFORE=$(sqlite3 events.db "select count(*) from events where category='file' and json_extract(payload,'\$.file.path')='/tmp/bg-perf/tput_target.txt';")
tests/perf/gen_load "$WORK/tput_target.txt" 300000 30 | tee "$RES/tput.txt"
sleep 3   # 等批量 flush
EV_AFTER=$(sqlite3 events.db "select count(*) from events where category='file' and json_extract(payload,'\$.file.path')='/tmp/bg-perf/tput_target.txt';")
$SUDO ./baseline-guard stats --drop > "$RES/drop_after.txt"
echo "events_before=$EV_BEFORE events_after=$EV_AFTER received=$((EV_AFTER-EV_BEFORE))" | tee "$RES/tput_events.txt"

echo "=== [4] 常态 CPU（pidstat 5s × 60 = 5 分钟）==="
pidstat -p "$MPID" 5 60 | tee "$RES/cpu.txt" | tail -5

echo "=== [5] RSS（monitor 就绪满 30 分钟时取值）==="
START_TS=$(date +%s)
echo "monitor 就绪时刻: $START_TS ($(date))" | tee "$RES/rss.txt"
while [ "$(date +%s)" -lt "$(( START_TS + 1800 ))" ]; do sleep 15; done
grep -E "VmRSS|VmHWM" /proc/"$MPID"/status | tee -a "$RES/rss.txt"

echo "=== [6] 停止 monitor ==="
kill -TERM "$MPID"
for i in $(seq 1 40); do kill -0 "$MPID" 2>/dev/null || break; sleep 0.5; done
grep -i "drop\|warn" "$WORK/monitor_perf.log" | tail -10 | tee "$RES/monitor_warn.txt"
echo "DONE"
