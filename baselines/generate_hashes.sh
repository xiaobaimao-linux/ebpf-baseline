#!/bin/bash
# 生成系统关键文件的真实哈希值
# 用法: bash generate_hashes.sh
# 输出: 直接打印可用于替换占位符的哈希值

echo "=== 系统关键文件哈希值 ==="
echo ""
echo "执行以下命令获取真实哈希值，然后替换 system_critical.yaml 中的占位符:"
echo ""

for file in /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config /etc/hosts; do
    if [[ -f "$file" ]]; then
        hash=$(sha256sum "$file" | awk '{print $1}')
        perm=$(stat -c '%a' "$file")
        echo "文件: $file"
        echo "  当前权限: $perm"
        echo "  SHA256:   $hash"
        echo ""
    else
        echo "文件不存在: $file"
        echo ""
    fi
done

echo "=== 自动替换占位符 ==="
echo ""
echo "方式1: 手动替换"
echo "  打开 baselines/system_critical.yaml"
echo "  将 PLACEHOLDER_PASSWD_HASH 替换为 /etc/passwd 的哈希值"
echo "  将 PLACEHOLDER_SHADOW_HASH 替换为 /etc/shadow 的哈希值"
echo "  ..."
echo ""
echo "方式2: 使用 sed 自动替换 (在当前目录执行):"
echo ""

# 生成 sed 命令
for file in /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config /etc/hosts; do
    if [[ -f "$file" ]]; then
        hash=$(sha256sum "$file" | awk '{print $1}')
        basename=$(basename "$file" | tr '.' '_')
        placeholder="PLACEHOLDER_$(echo $basename | tr '[:lower:]' '[:upper:]')_HASH"
        echo "  sed -i 's|$placeholder|$hash|' system_critical.yaml"
    fi
done

echo ""

# 如果 system_critical.yaml 存在，执行自动替换
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
YAML_FILE="$SCRIPT_DIR/system_critical.yaml"

if [[ -f "$YAML_FILE" ]]; then
    echo "检测到 system_critical.yaml，是否自动替换哈希值? [y/N]"
    read -r answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        for file in /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config /etc/hosts; do
            if [[ -f "$file" ]]; then
                hash=$(sha256sum "$file" | awk '{print $1}')
                basename=$(basename "$file" | tr '.' '_')
                placeholder="PLACEHOLDER_$(echo $basename | tr '[:lower:]' '[:upper:]')_HASH"
                sed -i "s|$placeholder|$hash|" "$YAML_FILE"
                echo "已替换: $file -> $hash"
            fi
        done
        echo ""
        echo "替换完成! 文件: $YAML_FILE"
    else
        echo "跳过自动替换"
    fi
else
    echo "未找到 system_critical.yaml，跳过自动替换"
fi
