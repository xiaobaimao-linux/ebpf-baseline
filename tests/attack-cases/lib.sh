#!/bin/bash
# 攻击用例库公共函数库。被各 case 的 run/verify 脚本 source。
# 约定：monitor 已由 run_all.sh 启动；本库只负责打标机、查询和等待落库。

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EVENTS_DB="${ROOT_DIR}/events.db"
# 注意：monitor 的实时告警固定落系统库 /var/lib/baseline-guard/baseline.db
# （main.cpp 里 alert_db 用默认路径，与 monitor --db 无关），别查仓库里的 baseline.db。
ALERTS_DB="/var/lib/baseline-guard/baseline.db"
WORK_DIR="/tmp/bg-attack-cases"
MARK_DIR="${WORK_DIR}/marks"

mkdir -p "$MARK_DIR"

# 告警库是 root 拥有的系统路径；非 root 调用时依赖 sudo 缓存凭据
sqlite_run() {
    local db="$1"; shift
    if [ "$(id -u)" -eq 0 ]; then
        sqlite3 "$db" "$@"
    else
        sudo -n sqlite3 "$db" "$@" 2>/dev/null || {
            echo "ERR: 查询 $db 需要 root（sudo 凭据未缓存？）" >&2; return 1; }
    fi
}

# 每个 case、每一轮用独立 mark 文件：round_case_{events,alerts}.before
mark_begin() {
    local tag="$1"
    sqlite_run "$EVENTS_DB" "select coalesce(max(id),0) from events;" > "${MARK_DIR}/${tag}.events.before"
    sqlite_run "$ALERTS_DB" "select coalesce(max(id),0) from alerts;" > "${MARK_DIR}/${tag}.alerts.before"
}

# 事件落库是批量的（batch_ms 200），等 2s 足够 flush
wait_flush() { sleep 2; }

count_events_since() { # $1=tag $2=where 条件(payload/category 等)
    local tag="$1" cond="$2" min_id
    min_id=$(cat "${MARK_DIR}/${tag}.events.before")
    sqlite3 "$EVENTS_DB" "select count(*) from events where id > ${min_id} and ${cond};"
}

count_alerts_since() { # $1=tag $2=where 条件
    local tag="$1" cond="$2" min_id
    min_id=$(cat "${MARK_DIR}/${tag}.alerts.before")
    sqlite_run "$ALERTS_DB" "select count(*) from alerts where id > ${min_id} and ${cond};"
}

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; }
