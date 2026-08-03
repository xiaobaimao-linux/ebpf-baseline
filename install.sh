#!/bin/bash
# install.sh

set -e

echo "=== baseline-guard installer ==="

# 1. 检测内核版本
KERNEL_MAJOR=$(uname -r | cut -d. -f1)
KERNEL_MINOR=$(uname -r | cut -d. -f2)

if [ "$KERNEL_MAJOR" -lt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 7 ]); then
    echo "ERROR: Linux kernel 5.7+ required, current: $(uname -r)"
    echo "Your kernel does not support BPF_LSM. Exiting."
    exit 1
fi

# 2. 检测 CONFIG_BPF_LSM
if ! grep -q "CONFIG_BPF_LSM=y" /boot/config-$(uname -r) 2>/dev/null; then
    echo "WARNING: CONFIG_BPF_LSM may not be enabled. Checking /sys/kernel/security/lsm..."
    if ! cat /sys/kernel/security/lsm | grep -q bpf; then
        echo "ERROR: BPF_LSM not enabled. Please enable it in kernel config."
        exit 1
    fi
fi

# 3. 编译
echo "[1/4] Compiling eBPF program..."
make clean >/dev/null 2>&1 || true
make

# 4. 安装二进制
echo "[2/4] Installing binary..."
sudo cp baseline-guard /usr/local/bin/
sudo chmod +x /usr/local/bin/baseline-guard

# 5. 创建配置目录
echo "[3/4] Setting up config..."
sudo mkdir -p /etc/baseline-guard
sudo mkdir -p /var/log/baseline-guard
sudo mkdir -p /var/lib/baseline-guard

# 6. 复制默认规则
if [ ! -f /etc/baseline-guard/rules.yaml ]; then
    sudo cp baselines/default.yaml /etc/baseline-guard/rules.yaml
fi

# 7. 创建 systemd 服务
echo "[4/4] Creating systemd service..."
cat << 'EOF' | sudo tee /etc/systemd/system/baseline-guard.service
[Unit]
Description=baseline-guard File Integrity Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/baseline-guard monitor -c /etc/baseline-guard/rules.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload

echo ""
echo "=== Installation Complete ==="
echo "Start monitoring: sudo systemctl start baseline-guard"
echo "Enable on boot:   sudo systemctl enable baseline-guard"
echo "Check status:     sudo systemctl status baseline-guard"
echo "Run audit:        sudo baseline-guard check"
echo ""
echo "Edit rules:       sudo vim /etc/baseline-guard/rules.yaml"