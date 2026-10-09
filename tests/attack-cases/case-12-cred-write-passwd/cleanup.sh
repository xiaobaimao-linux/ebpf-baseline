#!/bin/bash
# 用例 12 清理：从 /etc/passwd 重建替身文件（保持同一 inode：先清空再写回，避免热加载问题）
# 注意：直接 cp 会换 inode，第 2 轮用例将无事件（inode 注册在 monitor 启动时完成）
cp /etc/passwd /tmp/bg-attack-cases/passwd-copy.new 2>/dev/null
cat /tmp/bg-attack-cases/passwd-copy.new > /tmp/bg-attack-cases/passwd-copy
rm -f /tmp/bg-attack-cases/passwd-copy.new
exit 0
