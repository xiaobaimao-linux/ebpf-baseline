#!/bin/bash
# 用例 07 验证：反弹 shell（解释器派生）
# 预期：dsl.exec_reverse_shell_under_interpreter 告警 ≥1（规则 Exec Reverse Shell Under Interpreter）
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-07-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.exec_reverse_shell_under_interpreter'")
[ "$n" -ge 1 ] && pass "解释器派生 shell 告警 ×$n" || fail "dsl.exec_reverse_shell_under_interpreter 告警只有 $n 次，预期 >=1"
exit $((n < 1))
