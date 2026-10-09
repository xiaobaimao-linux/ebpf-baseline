#!/bin/bash
# 用例 09 临时目录执行无扩展名二进制：复制 /bin/echo 到 /tmp 下执行
# 预期：alerts 出现 dsl.exec_suspicious_tmp_binary
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-09-r1}"
mark_begin "$tag"

cp /bin/echo "$WORK_DIR/tmpexe"
chmod +x "$WORK_DIR/tmpexe"
"$WORK_DIR/tmpexe" attack-sim >/dev/null 2>&1
exit 0
