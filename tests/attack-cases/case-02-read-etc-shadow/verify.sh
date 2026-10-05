#!/bin/bash
# 用例 02 验证：读取 /etc/shadow 触发告警 + 文件读取事件（含进程上下文）
# 预期事件：
#   1) alerts 表新增 file_path=/etc/shadow 的告警（read 类）
#   2) events 表新增 file.read，process.exe 非空、祖先链非空（M0-1 进程上下文）
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-02-r1}"
wait_flush

alert_n=$(count_alerts_since "$tag" "rule_id='AC-02' and file_path='/etc/shadow' and event_type in ('read','file.read','file_read')")
ev_n=$(count_events_since "$tag" "category='file' and json_extract(payload,'\$.event_type')='file.read' and json_extract(payload,'\$.file.path')='/etc/shadow'")
chain_n=$(count_events_since "$tag" "category='file' and json_extract(payload,'\$.event_type')='file.read' and json_extract(payload,'\$.file.path')='/etc/shadow' and json_extract(payload,'\$.process.exe') != '' and json_array_length(json_extract(payload,'\$.process.ancestors')) >= 1")

ok=1
[ "$alert_n" -ge 1 ] || { fail "alerts(/etc/shadow read)=$alert_n，预期 >=1"; ok=0; }
[ "$ev_n" -ge 1 ] || { fail "events file.read(/etc/shadow)=$ev_n，预期 >=1"; ok=0; }
[ "$chain_n" -ge 1 ] || { fail "进程链完整的 file.read 事件=$chain_n，预期 >=1"; ok=0; }
[ "$ok" -eq 1 ] && pass "读 /etc/shadow 告警+事件+进程链（alerts×$alert_n, events×$ev_n, chain×$chain_n）"
exit $((1-ok))
