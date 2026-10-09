#!/bin/bash
# 用例 10 webshell：伪造 nginx 进程（bash 副本改 comm）派生 shell
# 预期：alerts 出现 dsl.exec_webspawner_shell（bash 祖先链含 nginx）
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-10-r1}"
mark_begin "$tag"

# comm 取 exec 文件 basename：把 bash 复制成 nginx 即得到 comm=nginx 的父进程。
# 注意 -c 必须给命令列表：bash 对最后一条简单命令有 exec 优化（不 fork 直接 exec），
# 单命令写法下子 bash 会替换 nginx 进程，祖先链里没有 nginx（实测踩过）。
cp /bin/bash "$WORK_DIR/nginx"
"$WORK_DIR/nginx" -c '/bin/bash -c id; true' >/dev/null 2>&1
exit 0
