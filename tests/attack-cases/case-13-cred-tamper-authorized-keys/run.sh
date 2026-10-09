#!/bin/bash
# 用例 13 篡改 authorized_keys：向测试家目录的 authorized_keys 追加攻击者公钥
# 预期：alerts 出现 dsl.cred_tamper_authorized_keys
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-13-r1}"
mark_begin "$tag"

echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAttackerBackdoorKey attacker@evil" >> "$WORK_DIR/fakehome/.ssh/authorized_keys"
exit 0
