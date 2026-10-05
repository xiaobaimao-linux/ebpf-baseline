#!/bin/bash
# 用例 06 验证：告警含容器短 ID（M0-1 验收标准）
# 预期事件：
#   1) alerts 新增受保护文件告警，container_id 非空（12 位短 ID）
#   2) events 表 file.write 事件带同样的 container_id
# 路径说明：容器场景下 LSM 钩子记录的是宿主机路径
# （/tmp/bg-attack-cases/protected-baseline.conf），container_id 列带 12 位短 ID。
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-06-r1}"
wait_flush

alert_n=$(count_alerts_since "$tag" "file_path like '%protected-baseline.conf' and container_id != ''")
ev_n=$(count_events_since "$tag" "category='file' and json_extract(payload,'\$.event_type')='file.write' and json_extract(payload,'\$.file.path') like '%protected-baseline.conf' and container_id != ''")

ok=1
[ "$alert_n" -ge 1 ] || { fail "带容器 ID 的告警=$alert_n，预期 >=1"; ok=0; }
[ "$ev_n" -ge 1 ] || { fail "带容器 ID 的 file.write=$ev_n，预期 >=1"; ok=0; }
[ "$ok" -eq 1 ] && pass "容器内篡改告警含容器短 ID（alerts×$alert_n, events×$ev_n）"
exit $((1-ok))
