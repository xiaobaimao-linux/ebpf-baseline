#!/usr/bin/env python3
"""
自动更新 default.yaml 中的哈希值
用法: python3 update_hashes.py
"""

import hashlib
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
YAML_FILE = os.path.join(SCRIPT_DIR, "default.yaml")

FILES = {
    "PLACEHOLDER_PASSWD_HASH": "/etc/passwd",
    "PLACEHOLDER_SHADOW_HASH": "/etc/shadow",
    "PLACEHOLDER_SUDOERS_HASH": "/etc/sudoers",
    "PLACEHOLDER_SSHD_CONFIG_HASH": "/etc/ssh/sshd_config",
    "PLACEHOLDER_HOSTS_HASH": "/etc/hosts",
}


def sha256_file(path):
    """计算文件的 SHA256 哈希值"""
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except FileNotFoundError:
        return None
    except PermissionError:
        return None


def main():
    print("=== 系统关键文件基线哈希更新 ===\n")

    # 读取 YAML 文件
    try:
        with open(YAML_FILE, "r") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"错误: 找不到文件 {YAML_FILE}")
        sys.exit(1)

    # 计算并替换每个文件的哈希值
    replaced_count = 0
    for placeholder, path in FILES.items():
        hash_value = sha256_file(path)
        if hash_value:
            if placeholder in content:
                content = content.replace(placeholder, hash_value)
                print(f"[OK] {path}")
                print(f"     SHA256: {hash_value}")
                replaced_count += 1
            else:
                print(f"[WARN] {path} - 占位符 {placeholder} 未找到")
        else:
            print(f"[SKIP] {path} - 无法读取文件（不存在或无权限）")

    print()

    # 写回文件
    with open(YAML_FILE, "w") as f:
        f.write(content)

    if replaced_count > 0:
        print(f"成功更新 {replaced_count} 个哈希值到 {YAML_FILE}")
    else:
        print("没有哈希值被更新")

    # 验证文件权限
    print("\n=== 文件当前权限 ===")
    for placeholder, path in FILES.items():
        if os.path.exists(path):
            mode = oct(os.stat(path).st_mode)[-4:]
            print(f"  {path}: {mode}")


if __name__ == "__main__":
    main()
