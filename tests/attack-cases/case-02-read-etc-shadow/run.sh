#!/bin/bash
# 用例 02 读 /etc/shadow：攻击动作（需 root，run_all 以 sudo 运行）
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-02-r1}"
mark_begin "$tag"
cat /etc/shadow >/dev/null
exit 0
