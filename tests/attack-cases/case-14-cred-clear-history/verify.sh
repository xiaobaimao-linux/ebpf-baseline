#!/bin/bash
# 用例 14 验证：shell 历史清空规则
# 预期：dsl.cred_clear_shell_history 告警 ≥1
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-14-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.cred_clear_shell_history'")
[ "$n" -ge 1 ] && pass "shell 历史清空告警 ×$n" || fail "dsl.cred_clear_shell_history 告警只有 $n 次，预期 >=1"
exit $((n < 1))
