#!/bin/bash
# 用例 11 读 /etc/shadow（凭据类扩充规则）：cat 触发
# 预期：alerts 出现 dsl.cred_read_shadow_whitelist（cat 不在白名单）
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-11-r1}"
mark_begin "$tag"

cat /etc/shadow >/dev/null 2>&1
exit 0
