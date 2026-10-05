#!/bin/bash
# 攻击用例库批量执行：启动 monitor，6 个用例连跑 2 遍，输出 PASS/FAIL 汇总。
# 用法: sudo -n bash tests/attack-cases/run_all.sh        （需要 root：加载 eBPF + 部分攻击动作用 root）
# 退出码: 0 = 全部用例 × 2 轮 PASS；1 = 有失败项。
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK_DIR="/tmp/bg-attack-cases"
LOG="${WORK_DIR}/monitor.log"
PIDFILE="${WORK_DIR}/monitor.pid"
ROUNDS=2

CASES="case-01-reverse-shell case-02-read-etc-shadow case-03-chmod-777 \
       case-04-docker-sock-container case-05-batch-sensitive-read case-06-container-mount-tamper"

cd "$ROOT_DIR"
mkdir -p "$WORK_DIR"
: > "$WORK_DIR/results.txt"

echo "=== 前置检查 ==="
if [ "$(id -u)" -ne 0 ]; then
    sudo -n true || { echo "FAIL: 无 sudo 凭据，请先 sudo -v 或用 sudo -S 喂密码"; exit 1; }
fi
[ -x "$ROOT_DIR/baseline-guard" ] || { echo "FAIL: baseline-guard 不存在"; exit 1; }
docker info >/dev/null 2>&1 || echo "WARN: docker 不可用，case-04/06 将失败"

echo "=== 准备用例文件 ==="
cat > "$WORK_DIR/chmod-target.conf" <<'EOF'
# 攻击用例库 chmod 测试目标
sensitive_option=true
EOF
cat > "$WORK_DIR/protected-baseline.conf" <<'EOF'
# baseline-guard 受保护基线文件（攻击用例库测试对象）
config_value=original
EOF
# /root/.ssh/id_rsa 不存在时生成临时假密钥，cleanup 会删除
if [ ! -f /root/.ssh/id_rsa ]; then
    mkdir -p /root/.ssh && chmod 700 /root/.ssh
    ssh-keygen -t rsa -b 2048 -N '' -f /root/.ssh/id_rsa -q <<< y >/dev/null 2>&1
    touch /root/.ssh/.bg_attack_dummy_id_rsa
fi

echo "=== 启动 monitor ==="
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "已有 monitor 在跑（pid $(cat "$PIDFILE")），先停掉"
    kill -TERM "$(cat "$PIDFILE")" 2>/dev/null; sleep 2
fi
if [ "$(id -u)" -eq 0 ]; then
    bash -c "echo \$\$ > '$PIDFILE'; exec '$ROOT_DIR/baseline-guard' monitor --db '$ROOT_DIR/baseline.db' -c '$ROOT_DIR/tests/attack-cases/config.yaml'" >"$LOG" 2>&1 &
else
    sudo -n bash -c "echo \$\$ > '$PIDFILE'; exec '$ROOT_DIR/baseline-guard' monitor --db '$ROOT_DIR/baseline.db' -c '$ROOT_DIR/tests/attack-cases/config.yaml'" >"$LOG" 2>&1 &
fi

ready=0
for i in $(seq 1 40); do
    grep -q "Monitoring started" "$LOG" && { ready=1; break; }
    grep -q "bpf_program_error\|service_stop" "$LOG" && break
    sleep 0.5
done
[ "$ready" -eq 1 ] || { echo "FAIL: monitor 未就绪，日志:"; tail -20 "$LOG"; exit 1; }
echo "monitor 就绪 (pid $(cat "$PIDFILE"))，探针模式: $(grep -o 'LSM (ring buffer)\|LSM (perf buffer)\|kprobe mode' "$LOG" | head -1)"

overall=0
for round in $(seq 1 "$ROUNDS"); do
    echo ""
    echo "=== 第 $round 轮 ==="
    for c in $CASES; do
        name=$(basename "$c")
        tag="case-$(echo "$name" | cut -d- -f2)-r${round}"
        bash "tests/attack-cases/$c/run.sh" "$tag"
        out=$(bash "tests/attack-cases/$c/verify.sh" "$tag")
        echo "$out" | sed "s/^/[$name r$round] /"
        echo "[$name r$round] $out" | grep -o "PASS.*\|FAIL.*" >> "$WORK_DIR/results.txt"
        echo "[$name r$round] $out" | grep -q "^FAIL" && overall=1
        bash "tests/attack-cases/$c/cleanup.sh" >/dev/null 2>&1
    done
    # throttle=10s，等它过期再跑下一轮，保证每轮告警都能落库
    [ "$round" -lt "$ROUNDS" ] && { echo "(等待 12s 让告警节流过期)"; sleep 12; }
done

echo ""
echo "=== 停止 monitor ==="
kill -TERM "$(cat "$PIDFILE")" 2>/dev/null
for i in $(seq 1 20); do
    kill -0 "$(cat "$PIDFILE")" 2>/dev/null || break
    sleep 0.5
done
kill -0 "$(cat "$PIDFILE")" 2>/dev/null && { kill -KILL "$(cat "$PIDFILE")"; echo "WARN: monitor 未能优雅退出"; }
rm -f "$PIDFILE"

echo ""
echo "=== 清理临时假密钥 ==="
if [ -f /root/.ssh/.bg_attack_dummy_id_rsa ]; then
    rm -f /root/.ssh/id_rsa /root/.ssh/.bg_attack_dummy_id_rsa
    rmdir /root/.ssh 2>/dev/null
    echo "已删除 setup 生成的临时 /root/.ssh/id_rsa"
fi

echo ""
echo "=== 汇总 ==="
cat "$WORK_DIR/results.txt"
echo "monitor 日志: $LOG"
exit $overall
