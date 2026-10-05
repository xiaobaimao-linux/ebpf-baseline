#!/bin/bash
# 用例 03 chmod 777 敏感文件：攻击动作（run_all 的 setup 已建好目标文件）
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-03-r1}"
mark_begin "$tag"
chmod 777 /tmp/bg-attack-cases/chmod-target.conf
exit 0
