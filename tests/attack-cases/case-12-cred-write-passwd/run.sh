#!/bin/bash
# 用例 12 写 /etc/passwd（测试替身）：安全约束下不写真实 /etc/passwd，
# 改写 /tmp/bg-attack-cases/passwd-copy（替身路径在规则 condition 列表内，选型理由见 README）
# 预期：alerts 出现 dsl.cred_write_etc_passwd
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-12-r1}"
mark_begin "$tag"

echo "bgattacker:x:10099:10099::/home/bgattacker:/bin/bash" >> "$WORK_DIR/passwd-copy"
exit 0
