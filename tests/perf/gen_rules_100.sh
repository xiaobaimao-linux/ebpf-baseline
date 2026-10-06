#!/bin/bash
# 生成 100 条压测填充规则到 rules/perf-100/（不入库，.gitignore 排除）
# 用法: bash tests/perf/gen_rules_100.sh
# 构成: 80 条简单条件（file.read 敏感路径）+ 20 条复杂条件（and/or/not + 祖先链 + in 列表）
set -eu
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"
mkdir -p rules/perf-100
python3 - <<'EOF'
shells = "(/bin/bash, /bin/sh, /usr/bin/bash, /usr/bin/sh, /bin/dash)"
webs = "(nginx, apache2, httpd, php-fpm, node)"
sensitive = ["/etc/shadow","/etc/passwd","/etc/sudoers","/root/.ssh/id_rsa","/etc/ssh/sshd_config",
             "/var/log/auth.log","/etc/crontab","/root/.bash_history","/etc/hosts","/proc/kcore"]
for i in range(80):
    p = sensitive[i % len(sensitive)]
    open(f"rules/perf-100/pad_{i:03d}.yaml","w").write(f"""- rule: Perf Sensitive Read {i:03d}
  desc: perf padding rule {i}
  condition: event_type = file.read and file.path = {p} and not process.exe in (/usr/bin/passwd, /usr/bin/sudo)
  output: "perf rule {i} (exe=%process.exe file=%file.path)"
  priority: low
  attack: [T1003]
  fpr_note: perf padding
  response: perf padding
""")
for i in range(20):
    open(f"rules/perf-100/complex_{i:03d}.yaml","w").write(f"""- rule: Perf Complex {i:03d}
  desc: perf complex rule {i}
  condition: event_type = process.exec and process.exe in {shells} and process.ancestors[].comm in {webs} and not process.uid = 0 or (event_type = file.write and file.path startswith /etc/ and not process.exe in (/usr/bin/vim, /usr/bin/nano))
  output: "perf complex {i} (exe=%process.exe)"
  priority: medium
  attack: [T1059]
  fpr_note: perf padding
  response: perf padding
""")
print("generated 100 rules -> rules/perf-100/")
EOF
