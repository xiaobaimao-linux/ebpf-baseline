#!/bin/bash
# 用例 10 验证：web 服务派生 shell
# 预期：dsl.exec_webspawner_shell 告警 ≥1
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-10-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.exec_webspawner_shell'")
[ "$n" -ge 1 ] && pass "web 服务派生 shell 告警 ×$n" || fail "dsl.exec_webspawner_shell 告警只有 $n 次，预期 >=1"
exit $((n < 1))
