#!/bin/bash
# 用例 14 清理：恢复 history 内容（追加写保持 inode）
cat >> /tmp/bg-attack-cases/fakehome/.bash_history <<'EOF'
ls -la
cat /etc/passwd
EOF
exit 0
