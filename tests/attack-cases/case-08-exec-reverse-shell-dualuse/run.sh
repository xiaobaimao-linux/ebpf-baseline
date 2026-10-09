#!/bin/bash
# 用例 08 双用途工具：nc 连接本地监听（反弹 shell 常见载体）
# 预期：alerts 出现 dsl.exec_reverse_shell_dual_use_tool（nc 实际 exe 为 nc.openbsd，已在规则名单）
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-08-r1}"
mark_begin "$tag"

PORT=4408
nc -l 127.0.0.1 $PORT >/dev/null 2>&1 &
NC_PID=$!
sleep 0.5
echo hello | timeout 3 nc 127.0.0.1 $PORT >/dev/null 2>&1
kill $NC_PID 2>/dev/null
exit 0
