#!/bin/bash
# 用例 13 清理：去掉追加的攻击者公钥。
# 注意不能用 sed -i（临时文件 + rename 会换 inode，monitor 的 inode 注册失效，第 2 轮无事件），
# 用 cat 重定向原地覆盖保持 inode。
F=/tmp/bg-attack-cases/fakehome/.ssh/authorized_keys
grep -v 'attacker@evil' "$F" > "$F.keep" && cat "$F.keep" > "$F" && rm -f "$F.keep"
exit 0
