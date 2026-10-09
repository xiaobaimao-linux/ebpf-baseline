#!/bin/bash
# 用例 11 验证：凭据类 shadow 读取规则
# 预期：dsl.cred_read_shadow_whitelist 告警 ≥1
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-11-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.cred_read_shadow_whitelist'")
[ "$n" -ge 1 ] && pass "shadow 读取告警 ×$n" || fail "dsl.cred_read_shadow_whitelist 告警只有 $n 次，预期 >=1"
exit $((n < 1))
