#!/bin/bash
# W3 性能补充测量：稳态延迟 + 10,000 事件/s 不丢验证。
# 背景：主测量（run_perf.sh）中吞吐压测为全速 348k ops/s，远超管道能力，
# 观测到 ringbuf reserve 失败导致的事件静默丢失且 drop 计数器不计（详见 perf-baseline-w3.md）。
# 本脚本按验收口径补测：稳态（monitor 空闲 30s 后）延迟 + 精确 10k/s 速率下的零丢失验证。
# 用法: sudo bash tests/perf/run_tput_10k.sh
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK=/tmp/bg-perf
RES=$WORK/results
PIDFILE=$WORK/monitor.pid
cd "$ROOT_DIR"

echo "=== 启动 monitor ==="
if [ "$(id -u)" -eq 0 ]; then
    bash -c "echo \$\$ > '$PIDFILE'; exec '$ROOT_DIR/baseline-guard' monitor --db '$ROOT_DIR/baseline.db' -c '$ROOT_DIR/tests/perf/config.yaml'" >"$WORK/monitor_10k.log" 2>&1 &
else
    sudo -n bash -c "echo \$\$ > '$PIDFILE'; exec '$ROOT_DIR/baseline-guard' monitor --db '$ROOT_DIR/baseline.db' -c '$ROOT_DIR/tests/perf/config.yaml'" >"$WORK/monitor_10k.log" 2>&1 &
fi
for i in $(seq 1 40); do
    grep -q "Monitoring started" "$WORK/monitor_10k.log" && break
    sleep 0.5
done
MPID=$(cat "$PIDFILE")
echo "monitor pid=$MPID"

echo "=== 稳态延迟（monitor 空闲 30s 后，受监控文件）=="
sleep 30
tests/perf/bench_lat "$WORK/lat_target.txt" 10000 | tee "$RES/lat_on_steady.txt"
echo "RSS@steady: $(grep VmRSS /proc/$MPID/status)"

echo "=== 10,000 事件/s 零丢失验证（30s 窗口）=="
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo -n"; fi
$SUDO ./baseline-guard stats --drop > "$RES/drop10k_before.txt"
EV_BEFORE=$(sqlite3 events_perf.db "select count(*) from events where json_extract(payload,'\$.file.path')='/tmp/bg-perf/tput_target.txt';")
echo "events_before=$EV_BEFORE"
tests/perf/gen_load "$WORK/tput_target.txt" 300000 30 10000 | tee "$RES/tput10k.txt"
sleep 3
EV_AFTER=$(sqlite3 events_perf.db "select count(*) from events where json_extract(payload,'\$.file.path')='/tmp/bg-perf/tput_target.txt';")
$SUDO ./baseline-guard stats --drop > "$RES/drop10k_after.txt"
echo "events_before=$EV_BEFORE events_after=$EV_AFTER received=$((EV_AFTER-EV_BEFORE))" | tee "$RES/tput10k_events.txt"

echo "=== 停止 monitor ==="
kill -TERM "$MPID"
for i in $(seq 1 40); do kill -0 "$MPID" 2>/dev/null || break; sleep 0.5; done
grep -i "drop\|overflow\|watermark" "$WORK/monitor_10k.log" | tail -8 | tee "$RES/monitor_10k_warn.txt"
echo "DONE"
