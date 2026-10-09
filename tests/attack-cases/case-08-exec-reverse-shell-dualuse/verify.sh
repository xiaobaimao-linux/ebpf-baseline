#!/bin/bash
# 用例 08 验证：双用途网络工具执行
# 预期：dsl.exec_reverse_shell_dual_use_tool 告警 ≥1（监听端与连接端 nc 均命中）
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-08-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.exec_reverse_shell_dual_use_tool'")
[ "$n" -ge 1 ] && pass "双用途工具执行告警 ×$n" || fail "dsl.exec_reverse_shell_dual_use_tool 告警只有 $n 次，预期 >=1"
exit $((n < 1))
