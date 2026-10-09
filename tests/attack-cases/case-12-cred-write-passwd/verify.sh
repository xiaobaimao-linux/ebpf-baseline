#!/bin/bash
# 用例 12 验证：passwd 写入规则
# 预期：dsl.cred_write_etc_passwd 告警 ≥1，且告警 file_path 为替身路径
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-12-r1}"
wait_flush

n=$(count_alerts_since "$tag" "rule_id='dsl.cred_write_etc_passwd' and file_path='/tmp/bg-attack-cases/passwd-copy'")
[ "$n" -ge 1 ] && pass "passwd 写入告警 ×$n（替身路径）" || fail "dsl.cred_write_etc_passwd 告警只有 $n 次，预期 >=1"
exit $((n < 1))
