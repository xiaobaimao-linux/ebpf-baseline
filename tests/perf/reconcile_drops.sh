#!/bin/bash
# W4 D1 丢弃对账：应发数 = 内核drop + 总线drop + 批溢出drop + 落库成功，误差 <1% 通过。
#
# 口径（file 事件域，探针级计数器取自 stats --drop）：
#   应发数   = kernel.file.emitted + kernel.file.reserve_failed + kernel.file.backpressure_drop
#    accounted = kernel.file.reserve_failed + kernel.file.backpressure_drop        # 内核 drop
#             + bus.queue_full.hi.p0_file                                          # 总线 drop
#             + batch_overflow                                                     # 批溢出 drop
#             + store_failed                                                       # 落库失败 drop
#             + events 表落库成功数（target 文件，before/after 差值）
# 两侧同含内核 drop，约去后等价于 emitted = bus_drop + batch + store_failed + stored。
#
# 用法: sudo bash tests/perf/reconcile_drops.sh [ops] [seconds] [rate_per_s]
# 默认与 run_tput_10k.sh 同口径：300000 ops / 30s / 10000 ops/s。
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK=/tmp/bg-perf
RES=$WORK/results
PIDFILE=$WORK/reconcile.pid
TARGET="$WORK/tput_target.txt"
OPS=${1:-300000}
SECS=${2:-30}
RATE=${3:-10000}
cd "$ROOT_DIR"
mkdir -p "$RES"

if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo -n"; fi

get_stat() {  # get_stat <file> <key> → value（取最后一次出现，无则 0）
    awk -v k="$2" '$1==k {v=$NF} END {print v+0}' "$1"
}

echo "=== 启动 monitor ==="
if [ "$(id -u)" -eq 0 ]; then
    bash -c "echo \$\$ > '$PIDFILE'; exec '$ROOT_DIR/baseline-guard' monitor --db '$ROOT_DIR/baseline.db' -c '$ROOT_DIR/tests/perf/config.yaml'" >"$WORK/reconcile_monitor.log" 2>&1 &
else
    $SUDO bash -c "echo \$\$ > '$PIDFILE'; exec '$ROOT_DIR/baseline-guard' monitor --db '$ROOT_DIR/baseline.db' -c '$ROOT_DIR/tests/perf/config.yaml'" >"$WORK/reconcile_monitor.log" 2>&1 &
fi
for i in $(seq 1 40); do
    grep -q "Monitoring started" "$WORK/reconcile_monitor.log" && break
    sleep 0.5
done
MPID=$(cat "$PIDFILE")
echo "monitor pid=$MPID"
sleep 2   # 等 boot baseline check 产生的读事件落定（其不计入 before 快照之后的对账）

echo "=== before 快照 ==="
$SUDO ./baseline-guard stats --drop > "$RES/reconcile_before.txt"
EV_BEFORE=$(sqlite3 events_perf.db "select count(*) from events where json_extract(payload,'\$.file.path')='$TARGET';")

echo "=== 压测: ops=$OPS secs=$SECS rate=$RATE ==="
# PIN_CORE 环境变量：把 gen_load 钉到指定核（消除与消费线程的同核竞争，用于验收口径）
if [ -n "${PIN_CORE:-}" ]; then
    taskset -c "$PIN_CORE" tests/perf/gen_load "$TARGET" "$OPS" "$SECS" "$RATE" | tee "$RES/reconcile_load.txt"
else
    tests/perf/gen_load "$TARGET" "$OPS" "$SECS" "$RATE" | tee "$RES/reconcile_load.txt"
fi
OPS_DONE=$(awk -F'[= ]' '{for(i=1;i<NF;i++) if($i=="ops"){print $(i+1); exit}}' "$RES/reconcile_load.txt")

echo "=== 等待管道排干（目标文件落库数与总线丢弃数双双稳定，最长 120s）==="
# 注：不能用 store.stored / bus.depth 判定——后台系统活动的 proc exec 事件
# 会持续改变它们；file 对账域用目标文件落库数 + hi.p0 丢弃数即可。
PREV_EV=-1
PREV_DROP=-1
STABLE=0
for i in $(seq 1 40); do
    sleep 2
    EV_NOW=$(sqlite3 events_perf.db "select count(*) from events where json_extract(payload,'\$.file.path')='$TARGET';")
    $SUDO ./baseline-guard stats --drop > "$RES/reconcile_drain.txt"
    DROP_NOW=$(get_stat "$RES/reconcile_drain.txt" "bus.queue_full.hi.p0_file")
    if [ "$EV_NOW" -eq "$PREV_EV" ] && [ "$DROP_NOW" -eq "$PREV_DROP" ]; then
        STABLE=1
        echo "drained after ~$((i*2))s (stored_target=$EV_NOW bus_drop_file=$DROP_NOW)"
        break
    fi
    PREV_EV=$EV_NOW
    PREV_DROP=$DROP_NOW
done
[ "$STABLE" -eq 1 ] || echo "WARN: 排干等待超时，快照可能含在途事件"

echo "=== after 快照 ==="
$SUDO ./baseline-guard stats --drop > "$RES/reconcile_after.txt"
EV_AFTER=$(sqlite3 events_perf.db "select count(*) from events where json_extract(payload,'\$.file.path')='$TARGET';")

echo "=== 停止 monitor ==="
kill -TERM "$MPID" 2>/dev/null || $SUDO kill -TERM "$MPID"
for i in $(seq 1 40); do kill -0 "$MPID" 2>/dev/null || break; sleep 0.5; done

# ── 对账计算 ──────────────────────────────────────────────
B="$RES/reconcile_before.txt"; A="$RES/reconcile_after.txt"
delta() { echo $(( $(get_stat "$A" "$1") - $(get_stat "$B" "$1") )); }

EMITTED=$(delta kernel.file.emitted)
RESERVE=$(delta kernel.file.reserve_failed)
BPDROP=$(delta kernel.file.backpressure_drop)
BUS_DROP_FILE=$(delta bus.queue_full.hi.p0_file)
BUS_DROP_CTRL=$(delta bus.queue_full.hi.p1_ctrl)
BUS_DROP_LO=$(delta bus.queue_full.lo.p2_net)
BATCH=$(delta batch_overflow)
STORE_FAIL=$(delta store_failed)
STORED=$(( EV_AFTER - EV_BEFORE ))

EXPECTED=$(( EMITTED + RESERVE + BPDROP ))
ACCOUNTED=$(( RESERVE + BPDROP + BUS_DROP_FILE + BATCH + STORE_FAIL + STORED ))
if [ "$EXPECTED" -gt 0 ]; then
    DIFF=$(( EXPECTED > ACCOUNTED ? EXPECTED - ACCOUNTED : ACCOUNTED - EXPECTED ))
    ERR_PCT=$(awk -v d="$DIFF" -v e="$EXPECTED" 'BEGIN{printf "%.3f", d*100.0/e}')
else
    ERR_PCT="NaN(应发数为0)"
fi

{
echo "──────────────── 对账结果 ────────────────"
echo "gen_load ops              = $OPS_DONE"
echo "kernel.file.emitted       = $EMITTED  (每 op 事件数: $(awk -v e="$EMITTED" -v o="$OPS_DONE" 'BEGIN{printf "%.3f", (o>0)?e/o:0}'))"
echo "kernel.file.reserve_failed= $RESERVE"
echo "kernel.file.backpressure  = $BPDROP"
echo "bus.queue_full.hi.p0_file = $BUS_DROP_FILE   (高优丢弃)"
echo "bus.queue_full.hi.p1_ctrl = $BUS_DROP_CTRL   (参考: 非对账域)"
echo "bus.queue_full.lo.p2_net  = $BUS_DROP_LO     (参考: 非对账域)"
echo "batch_overflow            = $BATCH"
echo "store_failed              = $STORE_FAIL"
echo "stored (events 表差值)    = $STORED"
echo "──────────────────────────────────────────"
echo "应发数   = emitted+reserve+bp = $EXPECTED"
echo " accounted = drops+stored     = $ACCOUNTED"
echo "对账误差 = ${ERR_PCT}%"
} | tee "$RES/reconcile_report.txt"

awk -v e="$ERR_PCT" 'BEGIN{exit !(e+0 < 1.0)}' && echo "RECONCILE: PASS (<1%)" || echo "RECONCILE: FAIL (>=1%)"
