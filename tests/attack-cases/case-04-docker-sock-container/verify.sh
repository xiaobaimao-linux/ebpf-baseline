#!/bin/bash
# 用例 04 验证：容器内进程执行 docker 命令（挂载 docker.sock）
# 预期事件：
#   1) docker 客户端 exec ×≥1（exe like %/docker，含宿主机路径 /usr/bin/docker 与
#      容器内 /usr/local/bin/docker 两种形态）
#   2) 进程归属为容器：祖先链含容器运行时（runc / containerd-shim）
# 已知边界（如实记录，本次验证实测确认）：
#   a) net_watch 只覆盖 TCPv4+DNS，AF_UNIX 连接 docker.sock 无网络事件；
#   b) process.exec 事件暂无 container_id 富化（M0-1 只覆盖 file/priv/ns 类），
#      容器归属以祖先链中的 runc/containerd-shim 判定。
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-04-r1}"
wait_flush

exec_n=$(count_events_since "$tag" "category='process' and json_extract(payload,'\$.event_type')='process.exec' and json_extract(payload,'\$.process.comm')='docker'")
rt_n=$(count_events_since "$tag" "category='process' and json_extract(payload,'\$.event_type')='process.exec' and json_extract(payload,'\$.process.comm')='docker' and json_extract(payload,'\$.process.ancestors') like '%containerd-shim%'")
cid_n=$(count_events_since "$tag" "category='process' and json_extract(payload,'\$.event_type')='process.exec' and container_id != ''")
unix_n=$(count_events_since "$tag" "category='network' and json_extract(payload,'\$.network.family')=1")

ok=1
[ "$exec_n" -ge 1 ] || { fail "docker 客户端 exec=$exec_n，预期 >=1"; ok=0; }
[ "$rt_n" -ge 1 ] || { fail "祖先链含 containerd-shim 的容器 exec=$rt_n，预期 >=1"; ok=0; }
[ "$cid_n" -eq 0 ] && echo "INFO: process.exec 无 container_id 富化（0 条），容器归属以祖先链判定（已知边界 b）"
echo "INFO: AF_UNIX(docker.sock) 网络事件 $unix_n 个（net_watch 未覆盖 unix 连接，已知边界 a）"
[ "$ok" -eq 1 ] && pass "容器内 docker 命令 exec×$exec_n，容器归属（containerd-shim 链）×$rt_n"
exit $((1-ok))
