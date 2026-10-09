#!/bin/bash
# 用例 14 清空 shell 历史：dd 覆写测试家目录的 .bash_history（conv=notrunc 保 inode）
# 注意：本探针只对有实际 write(2) 字节的写产生 file.write 事件——
# cp /dev/null、truncate -s 0、空输入 tee 都只 open 不写数据，实测零事件（W6 D1 实测发现 7）；
# 也不能用 rm/unlink：删除重建换 inode，monitor 启动时的 inode 注册失效，第 2 轮无事件。
# 预期：alerts 出现 dsl.cred_clear_shell_history（dd 非 shell 白名单进程）
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-14-r1}"
mark_begin "$tag"

dd if=/dev/zero of="$WORK_DIR/fakehome/.bash_history" bs=16 count=1 conv=notrunc 2>/dev/null
exit 0
