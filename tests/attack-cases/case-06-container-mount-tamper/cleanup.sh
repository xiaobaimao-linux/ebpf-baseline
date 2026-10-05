#!/bin/bash
# 用例 06 清理：恢复受保护文件原始内容
cat > /tmp/bg-attack-cases/protected-baseline.conf <<'EOF'
# baseline-guard 受保护基线文件（攻击用例库测试对象）
config_value=original
EOF
exit 0
