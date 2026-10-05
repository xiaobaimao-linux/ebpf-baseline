#!/bin/bash
# 用例 05 验证：批量读取 3 个敏感文件，每个都有读取事件且进程链完整
# 预期事件：file.read × 3（/etc/shadow、/etc/gshadow、/root/.ssh/id_rsa 各 >=1），
#          每条 process.exe 非空且 ancestors 非空；AC-05A/AC-05B alerts × >=2
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-05-r1}"
wait_flush

ok=1
for f in /etc/shadow /etc/gshadow /root/.ssh/id_rsa; do
    n=$(count_events_since "$tag" "category='file' and json_extract(payload,'\$.event_type')='file.read' and json_extract(payload,'\$.file.path')='${f}' and json_extract(payload,'\$.process.exe') != '' and json_array_length(json_extract(payload,'\$.process.ancestors')) >= 1")
    [ "$n" -ge 1 ] || { fail "file.read($f) 进程链完整事件=$n，预期 >=1"; ok=0; }
done
# /etc/shadow 的告警走 AC-02 规则，与 case-02 共用节流窗口（同文件只允许一条规则，
# 见 README 实测发现 5），case-02 在前会占窗，故 shadow 告警不计入硬性预期；
# /etc/gshadow、/root/.ssh/id_rsa 由 AC-05A/AC-05B 独占，每轮稳定各 1 条。
alert_n=$(count_alerts_since "$tag" "rule_id in ('AC-05A','AC-05B') and event_type in ('read','file.read','file_read')")
[ "$alert_n" -ge 2 ] || { fail "AC-05A/AC-05B 读取 alerts=$alert_n，预期 >=2"; ok=0; }
shadow_alert_n=$(count_alerts_since "$tag" "rule_id='AC-02' and file_path='/etc/shadow' and event_type in ('read','file.read','file_read')")
[ "$shadow_alert_n" -eq 0 ] && echo "INFO: AC-02 shadow 告警被 case-02 节流窗口覆盖（0 条），事件维度已验证 3/3"
[ "$ok" -eq 1 ] && pass "批量敏感读取 3/3 文件事件+进程链完整，alerts×$alert_n"
exit $((1-ok))
