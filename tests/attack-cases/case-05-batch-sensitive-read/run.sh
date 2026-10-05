#!/bin/bash
# 用例 05 敏感路径批量读取：攻击动作（root）
# /root/.ssh/id_rsa 不存在时由 run_all 的 setup 生成临时假密钥
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-05-r1}"
# 防御性重建（正常轮次 key 由 run_all setup 建好且轮间不删）：
# 必须放在 mark_begin 之前，让 ssh-keygen 触发的 AC-05B write 告警不计入本轮
if [ ! -f /root/.ssh/id_rsa ]; then
    mkdir -p /root/.ssh && chmod 700 /root/.ssh
    ssh-keygen -t rsa -b 2048 -N '' -f /root/.ssh/id_rsa -q <<< y >/dev/null 2>&1
    touch /root/.ssh/.bg_attack_dummy_id_rsa
fi
mark_begin "$tag"
for f in /etc/shadow /etc/gshadow /root/.ssh/id_rsa; do
    cat "$f" 2>/dev/null
done
exit 0
