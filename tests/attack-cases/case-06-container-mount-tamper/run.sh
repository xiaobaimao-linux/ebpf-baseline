#!/bin/bash
# 用例 06 容器内篡改挂载的基线文件：攻击动作（M0-1 验收用例）
# 受保护文件 /tmp/bg-attack-cases/protected-baseline.conf 由 run_all 的 setup 创建
# 且必须在 monitor 启动前存在（规则按 inode 匹配）
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-06-r1}"
mark_begin "$tag"
docker run --rm \
    -v /tmp/bg-attack-cases/protected-baseline.conf:/etc/app/protected.conf \
    alpine sh -c 'echo "tampered from container" >> /etc/app/protected.conf' >/dev/null
exit 0
