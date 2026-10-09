#!/bin/bash
# 用例 13 验证：authorized_keys 篡改规则
# 预期：dsl.cred_tamper_authorized_keys 告警 ≥1
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-13-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.cred_tamper_authorized_keys'")
[ "$n" -ge 1 ] && pass "authorized_keys 篡改告警 ×$n" || fail "dsl.cred_tamper_authorized_keys 告警只有 $n 次，预期 >=1"
exit $((n < 1))
