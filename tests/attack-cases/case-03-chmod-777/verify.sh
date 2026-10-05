#!/bin/bash
# 用例 03 验证：chmod 777 触发 perm/chmod 告警 + file.chmod 事件（带操作者进程）
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-03-r1}"
wait_flush

# 规则类告警的 event_type 是归一化后的 'read'/'write'（chmod 也记 'write'），
# 离线基线核查类才是 'perm_changed'/'hash_changed'/'missing'。
alert_n=$(count_alerts_since "$tag" "file_path='/tmp/bg-attack-cases/chmod-target.conf' and event_type in ('write','chmod','perm_changed')")
ev_n=$(count_events_since "$tag" "category='file' and json_extract(payload,'\$.event_type')='file.chmod' and json_extract(payload,'\$.file.path')='/tmp/bg-attack-cases/chmod-target.conf'")

ok=1
[ "$alert_n" -ge 1 ] || { fail "alerts(chmod)=$alert_n，预期 >=1"; ok=0; }
[ "$ev_n" -ge 1 ] || { fail "events file.chmod=$ev_n，预期 >=1"; ok=0; }
[ "$ok" -eq 1 ] && pass "chmod 777 告警+事件（alerts×$alert_n, events×$ev_n）"
exit $((1-ok))
