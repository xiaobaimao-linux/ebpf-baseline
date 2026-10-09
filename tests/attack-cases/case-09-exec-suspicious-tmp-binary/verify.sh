#!/bin/bash
# 用例 09 验证：临时目录无扩展名二进制执行
# 预期：dsl.exec_suspicious_tmp_binary 告警 ≥1
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-09-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.exec_suspicious_tmp_binary'")
[ "$n" -ge 1 ] && pass "临时目录执行告警 ×$n" || fail "dsl.exec_suspicious_tmp_binary 告警只有 $n 次，预期 >=1"
exit $((n < 1))
