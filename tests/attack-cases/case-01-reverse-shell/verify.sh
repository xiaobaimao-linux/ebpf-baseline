#!/bin/bash
# 用例 01 验证：反弹 shell 全链路
# 预期事件：
#   1) process.exec × ≥2（外层 bash -c + 内层 bash -i）
#   2) network.connect 目的 127.0.0.1:4444 × ≥1
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-01-r1}"
wait_flush

exec_n=$(count_events_since "$tag" "category='process' and json_extract(payload,'\$.event_type')='process.exec' and json_extract(payload,'\$.process.exe') like '%/bash'")
conn_n=$(count_events_since "$tag" "category='network' and json_extract(payload,'\$.event_type')='network.connect' and json_extract(payload,'\$.network.dip')='127.0.0.1' and json_extract(payload,'\$.network.dport')=4444")

ok=1
[ "$exec_n" -ge 2 ] || { fail "process.exec(bash) 只有 $exec_n 次，预期 >=2"; ok=0; }
[ "$conn_n" -ge 1 ] || { fail "network.connect 127.0.0.1:4444 只有 $conn_n 次，预期 >=1"; ok=0; }
[ "$ok" -eq 1 ] && pass "反弹 shell 全链路（exec×$exec_n, connect×$conn_n）"
exit $((1-ok))
