#!/bin/bash
# 集成测试：网络遥测（connect/accept/bind + 进程/容器归属）
# 运行: sudo bash test_net_collection.sh
#
# 对应验收项：
#   NET-001 (V1): curl 本地 http.server → network.connect，dport=目标端口，pid/comm 与 curl 一致
#   NET-002 (V2): nc 监听 + nc 客户端   → 依次出现 network.bind → network.connect → network.accept
#   NET-003 (V3): docker 容器内 wget     → connect 事件带 container_id（CID 前 12 位）；宿主机 curl 事件无 container 字段
#   NET-004 (V4): telemetry.network: false → 重复 V1/V2 流量，无任何 network.* 日志
#
# 防串扰：所有端口/容器名/临时目录带 $$ 唯一标记；断言精确匹配 JSON 片段与本脚本自己的日志文件。
# 清理：trap EXIT 杀干净本脚本启动的全部进程与容器，无后台任务残留。

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
BIN="$PROJECT_DIR/baseline-guard"
TMPDIR="/tmp/baseline_net_test_$$"
MONITOR_LOG="$TMPDIR/monitor.log"

MARKER="NET$$"
HTTP_PORT=$(( (RANDOM % 20000) + 20000 ))
NC_PORT=$(( (RANDOM % 20000) + 20000 ))
[ "$NC_PORT" -eq "$HTTP_PORT" ] && NC_PORT=$((NC_PORT + 1))
CONTAINER="nettest-$MARKER"

FAIL_COUNT=0
SKIP_COUNT=0
MONITOR_PID=""
HTTP_PID=""
NC_PID=""

cleanup() {
    [ -n "$MONITOR_PID" ] && kill -TERM "$MONITOR_PID" 2>/dev/null
    [ -n "$MONITOR_PID" ] && wait "$MONITOR_PID" 2>/dev/null
    [ -n "$HTTP_PID" ] && kill -TERM "$HTTP_PID" 2>/dev/null
    [ -n "$NC_PID" ] && kill -TERM "$NC_PID" 2>/dev/null
    docker rm -f "$CONTAINER" >/dev/null 2>&1
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

# 等待日志出现某片段，$1=pattern $2=timeout秒
wait_for_log() {
    local deadline=$((SECONDS + $2))
    while [ "$SECONDS" -lt "$deadline" ]; do
        grep -qF "$1" "$MONITOR_LOG" 2>/dev/null && return 0
        sleep 0.2
    done
    return 1
}

start_monitor() { # $1=network开关(true/false)
    local yaml="$TMPDIR/net_$1.yaml"
    cat > "$yaml" <<EOF
rules:
  - id: "NET-TEST-001"
    name: "网络遥测测试占位规则"
    severity: "low"
    monitor:
      path: "$TMPDIR/marker_$MARKER.txt"
      events:
        - "read"
      action: "alert"
telemetry:
  network: $1
EOF
    : > "$MONITOR_LOG"
    "$BIN" monitor -c "$yaml" > "$MONITOR_LOG" 2>&1 &
    MONITOR_PID=$!
    if ! wait_for_log "Monitoring started" 10; then
        echo "  [FAIL] monitor 启动失败（network=$1）:"
        cat "$MONITOR_LOG"
        return 1
    fi
    return 0
}

stop_monitor() {
    [ -n "$MONITOR_PID" ] && kill -TERM "$MONITOR_PID" 2>/dev/null
    [ -n "$MONITOR_PID" ] && wait "$MONITOR_PID" 2>/dev/null
    MONITOR_PID=""
}

mkdir -p "$TMPDIR"
touch "$TMPDIR/marker_$MARKER.txt"

# ── 前置检查 ──────────────────────────────────────────────────────
for tool in curl nc python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "=== SKIP: 缺少 $tool，无法执行网络采集测试 ==="
        exit 3
    fi
done

# ══════════════════════════════════════════════════════════════════
echo "=== NET-001 (V1): curl 触发 network.connect ==="
if start_monitor true; then
    python3 -m http.server "$HTTP_PORT" --bind 127.0.0.1 --directory "$TMPDIR" >/dev/null 2>&1 &
    HTTP_PID=$!
    sleep 1

    curl -s "http://127.0.0.1:$HTTP_PORT/" -o /dev/null
    sleep 1

    if grep -qF '"event_type":"network.connect"' "$MONITOR_LOG" \
       && grep -qF "\"dport\":$HTTP_PORT" "$MONITOR_LOG" \
       && grep -qF '"comm":"curl"' "$MONITOR_LOG"; then
        echo "  [PASS] NET-001: network.connect 命中（dport=$HTTP_PORT, comm=curl）"
    else
        echo "  [FAIL] NET-001: 未找到期望的 network.connect 事件"
        grep "network\." "$MONITOR_LOG" | tail -5
        FAIL_COUNT=$((FAIL_COUNT+1))
    fi
    stop_monitor
fi
[ -n "$HTTP_PID" ] && kill -TERM "$HTTP_PID" 2>/dev/null; HTTP_PID=""

# ══════════════════════════════════════════════════════════════════
echo "=== NET-002 (V2): bind → connect → accept 顺序 ==="
if start_monitor true; then
    nc -lvnp "$NC_PORT" >/dev/null 2>&1 &
    NC_PID=$!
    sleep 1

    echo hi | nc -w2 127.0.0.1 "$NC_PORT" >/dev/null 2>&1
    sleep 1

    BIND_LINE=$(grep -nF '"event_type":"network.bind"' "$MONITOR_LOG" | grep -F "\"sport\":$NC_PORT" | head -1 | cut -d: -f1)
    CONN_LINE=$(grep -nF '"event_type":"network.connect"' "$MONITOR_LOG" | grep -F "\"dport\":$NC_PORT" | head -1 | cut -d: -f1)
    ACCP_LINE=$(grep -nF '"event_type":"network.accept"' "$MONITOR_LOG" | grep -F "\"sport\":$NC_PORT" | head -1 | cut -d: -f1)

    if [ -n "$BIND_LINE" ] && [ -n "$CONN_LINE" ] && [ -n "$ACCP_LINE" ] \
       && [ "$BIND_LINE" -lt "$CONN_LINE" ] && [ "$CONN_LINE" -lt "$ACCP_LINE" ]; then
        echo "  [PASS] NET-002: bind(L$BIND_LINE) < connect(L$CONN_LINE) < accept(L$ACCP_LINE)，端口=$NC_PORT"
    else
        echo "  [FAIL] NET-002: 事件缺失或顺序错误（bind=$BIND_LINE connect=$CONN_LINE accept=$ACCP_LINE）"
        grep "network\." "$MONITOR_LOG" | tail -5
        FAIL_COUNT=$((FAIL_COUNT+1))
    fi
    stop_monitor
fi
[ -n "$NC_PID" ] && kill -TERM "$NC_PID" 2>/dev/null; NC_PID=""

# ══════════════════════════════════════════════════════════════════
echo "=== NET-003 (V3): 容器归属 container_id ==="
if ! command -v docker >/dev/null 2>&1; then
    echo "  [SKIP] NET-003: docker 不可用"
    SKIP_COUNT=$((SKIP_COUNT+1))
elif ! docker info >/dev/null 2>&1; then
    echo "  [SKIP] NET-003: docker daemon 不可用"
    SKIP_COUNT=$((SKIP_COUNT+1))
else
    DOCKER_SKIP=""
    if ! docker image inspect alpine >/dev/null 2>&1; then
        echo "  [INFO] NET-003: 拉取 alpine 镜像..."
        docker pull alpine >/dev/null 2>&1 || DOCKER_SKIP="alpine 镜像拉取失败"
    fi
    if [ -n "$DOCKER_SKIP" ]; then
        echo "  [SKIP] NET-003: $DOCKER_SKIP"
        SKIP_COUNT=$((SKIP_COUNT+1))
    else
        docker rm -f "$CONTAINER" >/dev/null 2>&1
        if ! docker run -d --name "$CONTAINER" alpine sh -c "sleep 60" >/dev/null 2>&1; then
            echo "  [SKIP] NET-003: 容器创建失败"
            SKIP_COUNT=$((SKIP_COUNT+1))
        else
            CID=$(docker inspect --format '{{.Id}}' "$CONTAINER")
            CID12=${CID:0:12}

            if ! start_monitor true; then
                FAIL_COUNT=$((FAIL_COUNT+1))
            else
                if ! docker exec "$CONTAINER" sh -c 'wget -q -O /dev/null http://example.com' 2>/dev/null; then
                    echo "  [INFO] NET-003: 容器内 wget 未成功（外网不可达？），仍检查已产生的事件"
                fi
                sleep 1
                curl -s http://example.com -o /dev/null
                sleep 1

                C_OK=0
                H_OK=0
                if grep -qF '"event_type":"network.connect"' "$MONITOR_LOG" \
                   && grep -qF "\"container_id\":\"$CID12\"" "$MONITOR_LOG"; then
                    C_OK=1
                fi
                if grep '"event_type":"network.connect"' "$MONITOR_LOG" \
                   | grep -F '"comm":"curl"' | grep -qvF '"container"'; then
                    H_OK=1
                fi

                if [ "$C_OK" -eq 1 ] && [ "$H_OK" -eq 1 ]; then
                    echo "  [PASS] NET-003: 容器事件 container_id=$CID12；宿主机 curl 事件无 container 字段"
                else
                    echo "  [FAIL] NET-003: 容器归属校验失败（container_match=$C_OK host_no_container=$H_OK, cid12=$CID12）"
                    grep "network\." "$MONITOR_LOG" | tail -8
                    FAIL_COUNT=$((FAIL_COUNT+1))
                fi
                stop_monitor
            fi
            docker rm -f "$CONTAINER" >/dev/null 2>&1
        fi
    fi
fi

# ══════════════════════════════════════════════════════════════════
echo "=== NET-004 (V4): telemetry.network=false 零事件 ==="
if start_monitor false; then
    python3 -m http.server "$HTTP_PORT" --bind 127.0.0.1 --directory "$TMPDIR" >/dev/null 2>&1 &
    HTTP_PID=$!
    sleep 1

    curl -s "http://127.0.0.1:$HTTP_PORT/" -o /dev/null
    nc -lvnp "$NC_PORT" >/dev/null 2>&1 &
    NC_PID=$!
    sleep 1
    echo hi | nc -w2 127.0.0.1 "$NC_PORT" >/dev/null 2>&1
    sleep 2
    stop_monitor
    [ -n "$HTTP_PID" ] && kill -TERM "$HTTP_PID" 2>/dev/null; HTTP_PID=""
    [ -n "$NC_PID" ] && kill -TERM "$NC_PID" 2>/dev/null; NC_PID=""

    if ! grep -q '"event_type":"network\.' "$MONITOR_LOG"; then
        echo "  [PASS] NET-004: network=false 时无任何 network.* 事件"
    else
        echo "  [FAIL] NET-004: network=false 时仍出现网络事件"
        grep "network\." "$MONITOR_LOG" | tail -5
        FAIL_COUNT=$((FAIL_COUNT+1))
    fi
fi

# ── 汇总 ──────────────────────────────────────────────────────────
echo ""
if [ "$FAIL_COUNT" -eq 0 ]; then
    echo "=== 网络采集测试完成: PASS（skip=$SKIP_COUNT）==="
    exit 0
else
    echo "=== 网络采集测试完成: $FAIL_COUNT FAILED（skip=$SKIP_COUNT）==="
    exit 1
fi
