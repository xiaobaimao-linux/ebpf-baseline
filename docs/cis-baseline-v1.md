# 系统配置基线检查项清单 v1（CIS 裁剪版）

本清单裁剪自 CIS Ubuntu Linux Benchmark v22.04/24.04，共 40 项，适用于 Ubuntu 24.04 LTS（x86_64）。每项检查方法均为可直接执行的 shell 命令，输出 `PASS`/`FAIL` 即判定结论；等保 2.0 条款号依据 GB/T 22239-2019 的 8.1.4 子条款标注。

## 判定方式约定

1. **执行身份**：全部命令可在普通用户下执行（只依赖 /etc、/proc/sys 的世界可读权限与 systemctl/stat/sysctl 查询）。无 sudo 需求。
2. **SSHD 取值语义**：`sshd -T` 是 sshd 生效配置的唯一权威来源，但本机实测普通用户执行报 `no hostkeys available`（无 hostkey 读取权限）。故 SSH 各项采用文件解析兜底：按 OpenSSH `Include` 语义近似——先读 `/etc/ssh/sshd_config.d/*.conf`（字典序），再读 `/etc/ssh/sshd_config`，**最后一个匹配行生效**。若运行环境为 root 且有可读 hostkey，优先改用 `sshd -T | awk '$1=="<keyword>"{print $2}'` 取值。Match 块内的指令会被本近似方法混入，属已知误差，首版可接受。
3. **sysctl 语义**：网络参数与 MISC 各sysctl 项读运行时值（`sysctl -n`），与 CIS 判定口径一致；持久化配置（/etc/sysctl.d/）差异不在首版判定范围。
4. **stat 权限比较**：`stat -c %a` 取到的 mode 按十进制数值比较（如 `[ "$m" -le 640 ]`），对常见三位权限等价于"不宽松于"语义。
5. **缺包/缺文件语义**：检查对象（文件、systemd unit、目录）不存在时，对应命令自然输出 `FAIL`，表示该控制未落实；个别项在"预期值"列另有说明（如 UEFI 下 grub.cfg 路径不同）。

## 等保 2.0 条款号结构说明

GB/T 22239-2019 的 8.1.4（安全计算环境）实际子条款结构为：**8.1.4.1 身份鉴别、8.1.4.2 访问控制、8.1.4.3 安全审计、8.1.4.4 入侵防范、8.1.4.5 恶意代码防范、8.1.4.6 数据完整性、8.1.4.7 数据备份恢复、8.1.4.8 剩余信息保护、8.1.4.9 个人信息保护**。注意数据完整性是 **8.1.4.6**（非 8.1.4.7）。本清单中配置类检查主要映射至 8.1.4.1/8.1.4.2/8.1.4.3/8.1.4.4/8.1.4.8；8.1.4.5（恶意代码防范）与 8.1.4.7（数据备份恢复）属产品能力与流程域，配置基线无法直接判定，本版未映射。映射不上的项标"无直接对应"。

## 检查项清单（40 项）

| 编号 | 检查项 | 检查方法（具体命令或文件路径） | 预期值 | 严重等级 | 等保 2.0 条款号 |
| --- | --- | --- | --- | --- | --- |
| AUTH-01 | 口令最长使用期限 ≤90 天 | `v=$(awk '$1=="PASS_MAX_DAYS"{print $2; exit}' /etc/login.defs); [ -n "$v" ] && [ "$v" -le 90 ] && echo PASS \|\| echo FAIL` | 输出 PASS（PASS_MAX_DAYS ≤90；未设置或默认值 99999 判 FAIL） | high | 8.1.4.1 |
| AUTH-02 | 口令最短使用期限 ≥1 天 | `v=$(awk '$1=="PASS_MIN_DAYS"{print $2; exit}' /etc/login.defs); [ -n "$v" ] && [ "$v" -ge 1 ] && echo PASS \|\| echo FAIL` | 输出 PASS（PASS_MIN_DAYS ≥1；未设置或 0 判 FAIL） | low | 8.1.4.1 |
| AUTH-03 | 口令过期提醒提前 ≥7 天 | `v=$(awk '$1=="PASS_WARN_AGE"{print $2; exit}' /etc/login.defs); [ -n "$v" ] && [ "$v" -ge 7 ] && echo PASS \|\| echo FAIL` | 输出 PASS（PASS_WARN_AGE ≥7；未设置判 FAIL） | low | 8.1.4.1 |
| AUTH-04 | 口令最小长度 ≥14（pwquality） | `v=$(awk -F= '/^\s*minlen\s*=/{gsub(/[[:space:]]/,"",$2);print $2;exit}' /etc/security/pwquality.conf); [ -z "$v" ] && v=$(grep -h 'pam_pwquality\.so' /etc/pam.d/common-password \| sed -n 's/.*minlen=\([0-9]*\).*/\1/p'); [ -n "$v" ] && [ "$v" -ge 14 ] && echo PASS \|\| echo FAIL` | 输出 PASS（minlen ≥14，pwquality.conf 优先，其次 common-password 中 pam_pwquality.so 行参数；两处均未设置判 FAIL） | high | 8.1.4.1 |
| AUTH-05 | 登录失败锁定（pam_faillock）已启用 | `[ "$(grep -c 'pam_faillock\.so' /etc/pam.d/common-auth)" -ge 2 ] && echo PASS \|\| echo FAIL` | 输出 PASS（common-auth 中 pam_faillock.so 出现 ≥2 次，即 preauth+authfail 均配置；0 次表示未启用锁定，判 FAIL。建议在 /etc/security/faillock.conf 中显式设 deny≤10） | high | 8.1.4.1 |
| AUTH-06 | 空口令禁用 | `awk -F: '$2==""{bad=1} END{exit bad}' /etc/passwd && ! grep -qE '^\s*[^#]*\bnullok\b' /etc/pam.d/common-auth /etc/pam.d/common-password && echo PASS \|\| echo FAIL` | 输出 PASS（/etc/passwd 第 2 列无空字段，且 common-auth/common-password 未启用 nullok；任一项不满足判 FAIL） | high | 8.1.4.1 |
| AUTH-07 | UID 0 账户唯一且为 root | `u=$(awk -F: '$3==0{print $1}' /etc/passwd); [ "$u" = "root" ] && echo PASS \|\| echo FAIL` | 输出 PASS（UID=0 仅 root 一个账户；存在其他 UID 0 账户判 FAIL） | medium | 8.1.4.2 |
| AUTH-08 | 默认 UMASK ≥027 | `v=$(awk '$1=="UMASK"{print $2; exit}' /etc/login.defs); [ -n "$v" ] && [ $((8#$v)) -ge $((8#027)) ] && echo PASS \|\| echo FAIL` | 输出 PASS（/etc/login.defs 中 UMASK 为 027/077 等不宽松于 027 的值；022 或未设置判 FAIL） | low | 8.1.4.8 |
| SSH-01 | 禁止 root 直接 SSH 登录（PermitRootLogin no） | `v=$(grep -hiE '^\s*PermitRootLogin\s+\S' /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null \| awk '{print tolower($2)}' \| tail -1); [ "$v" = no ] && echo PASS \|\| echo FAIL` | 输出 PASS（生效值为 no；缺省 prohibit-password 亦判 FAIL，因不满足"显式禁止"） | high | 8.1.4.1 |
| SSH-02 | 禁用口令认证（PasswordAuthentication no） | `v=$(grep -hiE '^\s*PasswordAuthentication\s+\S' /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null \| awk '{print tolower($2)}' \| tail -1); [ "$v" = no ] && echo PASS \|\| echo FAIL` | 输出 PASS（生效值为 no；未设置时缺省为 yes，判 FAIL。仅密钥环境适用） | medium | 8.1.4.1 |
| SSH-03 | 最大认证尝试次数 ≤4（MaxAuthTries） | `v=$(grep -hiE '^\s*MaxAuthTries\s+\S' /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null \| awk '{print tolower($2)}' \| tail -1); [ -n "$v" ] && [ "$v" -le 4 ] && echo PASS \|\| echo FAIL` | 输出 PASS（1≤MaxAuthTries≤4；未设置时缺省 6，判 FAIL） | medium | 8.1.4.1 |
| SSH-04 | 禁止空口令登录（PermitEmptyPasswords no） | `v=$(grep -hiE '^\s*PermitEmptyPasswords\s+\S' /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null \| awk '{print tolower($2)}' \| tail -1); { [ -z "$v" ] \|\| [ "$v" = no ]; } && echo PASS \|\| echo FAIL` | 输出 PASS（生效值为 no；未设置时缺省即为 no，判 PASS；显式 yes 判 FAIL） | high | 8.1.4.1 |
| SSH-05 | 关闭 X11 转发（X11Forwarding no） | `v=$(grep -hiE '^\s*X11Forwarding\s+\S' /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null \| awk '{print tolower($2)}' \| tail -1); { [ -z "$v" ] \|\| [ "$v" = no ]; } && echo PASS \|\| echo FAIL` | 输出 PASS（生效值为 no；未设置缺省为 no 判 PASS；显式 yes 判 FAIL） | low | 8.1.4.4 |
| SSH-06 | SSH 空闲会话超时（1≤ClientAliveInterval≤300） | `v=$(grep -hiE '^\s*ClientAliveInterval\s+\S' /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null \| awk '{print tolower($2)}' \| tail -1); [ -n "$v" ] && [ "$v" -ge 1 ] && [ "$v" -le 300 ] && echo PASS \|\| echo FAIL` | 输出 PASS（ClientAliveInterval 在 1~300 秒；未设置时缺省 0（永不超时），判 FAIL） | low | 8.1.4.1 |
| SSH-07 | 单连接最大会话数 ≤10（MaxSessions） | `v=$(grep -hiE '^\s*MaxSessions\s+\S' /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null \| awk '{print tolower($2)}' \| tail -1); { [ -z "$v" ] \|\| { [ "$v" -ge 1 ] && [ "$v" -le 10 ]; }; } && echo PASS \|\| echo FAIL` | 输出 PASS（未设置时缺省 10，判 PASS；显式设置须 ≤10） | low | 8.1.4.4 |
| SSH-08 | SSH 审计日志详细级别 ≥VERBOSE | `v=$(grep -hiE '^\s*LogLevel\s+\S' /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null \| awk '{print tolower($2)}' \| tail -1); [ -n "$v" ] && { [ "$v" = verbose ] \|\| [ "$v" = debug ] \|\| [ "$v" = debug1 ] \|\| [ "$v" = debug2 ] \|\| [ "$v" = debug3 ]; } && echo PASS \|\| echo FAIL` | 输出 PASS（LogLevel 为 VERBOSE/DEBUGx；未设置时缺省 INFO，判 FAIL） | low | 8.1.4.3 |
| LOG-01 | rsyslog 服务已启用自启动 | `systemctl is-enabled rsyslog 2>/dev/null \| grep -qx enabled && echo PASS \|\| echo FAIL` | 输出 PASS（rsyslog 开机自启；unit 不存在或 disabled/masked 判 FAIL） | high | 8.1.4.3 |
| LOG-02 | journald 日志持久化存储 | `v=$(awk -F= '/^\s*Storage\s*=/{x=tolower($2); gsub(/[[:space:]]/,"",x)} END{print x}' /etc/systemd/journald.conf); [ -z "$v" ] && v=auto; { [ "$v" = persistent ] \|\| { [ "$v" = auto ] && [ -d /var/log/journal ]; }; } && echo PASS \|\| echo FAIL` | 输出 PASS（Storage=persistent，或未设置/为 auto 且 /var/log/journal 目录存在——未设置时 journald 缺省即 auto；Storage=volatile，或 auto 但无持久目录判 FAIL） | medium | 8.1.4.3 |
| LOG-03 | auditd 已安装并启用自启动 | `systemctl is-enabled auditd 2>/dev/null \| grep -qx enabled && echo PASS \|\| echo FAIL` | 输出 PASS（auditd 开机自启；未安装（unit not-found）或 disabled 判 FAIL——按等保审计要求视为未落实） | high | 8.1.4.3 |
| LOG-04 | audit 规则非空 | `n=$(grep -hcE '^\s*[^#[:space:]]' /etc/audit/rules.d/*.rules 2>/dev/null \| awk '{s+=$1} END{print s+0}'); [ "$n" -gt 0 ] && echo PASS \|\| echo FAIL` | 输出 PASS（/etc/audit/rules.d/*.rules 中有效（非注释非空）规则行数 >0；目录或文件不存在（行数 0）判 FAIL） | medium | 8.1.4.3 |
| LOG-05 | 认证日志文件权限与属主正确（/var/log/auth.log） | `f=/var/log/auth.log; [ -f "$f" ] && { o=$(stat -c %U "$f"); g=$(stat -c %G "$f"); m=$(stat -c %a "$f"); { [ "$o" = root ] \|\| [ "$o" = syslog ]; } && [ "$g" = adm ] && [ "$m" -le 640 ] && echo PASS \|\| echo FAIL; } \|\| echo FAIL` | 输出 PASS（文件存在，属主 root 或 syslog，组 adm，权限 ≤640；文件不存在判 FAIL） | low | 8.1.4.3 |
| LOG-06 | 系统日志 logrotate 轮转已配置 | `[ -f /etc/logrotate.conf ] && [ -f /etc/logrotate.d/rsyslog ] && echo PASS \|\| echo FAIL` | 输出 PASS（logrotate 主配置与 rsyslog 轮转配置均存在；任一缺失判 FAIL） | low | 8.1.4.3 |
| NET-01 | 禁用 IPv4 转发（ip_forward=0） | `[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" = 0 ] && echo PASS \|\| echo FAIL` | 输出 PASS（运行时值为 0；为 1 判 FAIL。容器/虚拟化宿主机按需加白名单） | medium | 8.1.4.4 |
| NET-02 | 禁用源路由（accept_source_route=0） | `[ "$(sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null)" = 0 ] && echo PASS \|\| echo FAIL` | 输出 PASS（net.ipv4.conf.all.accept_source_route=0） | medium | 8.1.4.4 |
| NET-03 | 禁用 ICMP 重定向接收（accept_redirects=0） | `[ "$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)" = 0 ] && echo PASS \|\| echo FAIL` | 输出 PASS（net.ipv4.conf.all.accept_redirects=0） | medium | 8.1.4.4 |
| NET-04 | 反向路径过滤已启用（rp_filter≥1） | `v=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null); [ -n "$v" ] && [ "$v" -ge 1 ] && echo PASS \|\| echo FAIL` | 输出 PASS（net.ipv4.conf.all.rp_filter 为 1（严格）或 2（松散）；0 判 FAIL） | low | 8.1.4.4 |
| NET-05 | 忽略 ICMP 广播请求 | `[ "$(sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null)" = 1 ] && echo PASS \|\| echo FAIL` | 输出 PASS（net.ipv4.icmp_echo_ignore_broadcasts=1） | low | 8.1.4.4 |
| NET-06 | SYN Cookie 防护已启用 | `[ "$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)" = 1 ] && echo PASS \|\| echo FAIL` | 输出 PASS（net.ipv4.tcp_syncookies=1） | medium | 8.1.4.4 |
| FILE-01 | /etc/shadow 权限与属主 | `{ [ "$(stat -c %a /etc/shadow)" -le 640 ] && [ "$(stat -c %U:%G /etc/shadow)" = root:shadow ]; } && echo PASS \|\| echo FAIL` | 输出 PASS（权限 ≤640 且属主 root:shadow；全局可读判 FAIL） | high | 8.1.4.2 |
| FILE-02 | /etc/gshadow 权限与属主 | `{ [ "$(stat -c %a /etc/gshadow)" -le 640 ] && [ "$(stat -c %U:%G /etc/gshadow)" = root:shadow ]; } && echo PASS \|\| echo FAIL` | 输出 PASS（权限 ≤640 且属主 root:shadow） | high | 8.1.4.2 |
| FILE-03 | /etc/passwd 权限与属主 | `[ "$(stat -c %a /etc/passwd)" -le 644 ] && [ "$(stat -c %U:%G /etc/passwd)" = root:root ] && echo PASS \|\| echo FAIL` | 输出 PASS（权限 ≤644 且属主 root:root） | medium | 8.1.4.2 |
| FILE-04 | GRUB 配置文件权限（grub.cfg） | `[ "$(stat -c %a /boot/grub/grub.cfg 2>/dev/null)" -le 600 ] && [ "$(stat -c %U /boot/grub/grub.cfg 2>/dev/null)" = root ] && echo PASS \|\| echo FAIL` | 输出 PASS（/boot/grub/grub.cfg 权限 ≤600 且属主 root；文件不存在判 FAIL——纯 UEFI 安装需改查 /boot/efi/EFI/*/grub.cfg） | medium | 8.1.4.2 |
| FILE-05 | /etc/crontab 权限与属主 | `[ "$(stat -c %a /etc/crontab)" -le 600 ] && [ "$(stat -c %U:%G /etc/crontab)" = root:root ] && echo PASS \|\| echo FAIL` | 输出 PASS（权限 ≤600 且属主 root:root；缺省 644 判 FAIL） | medium | 8.1.4.2 |
| FILE-06 | cron 目录权限与属主 | `ok=1; for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do [ "$(stat -c %a "$d" 2>/dev/null)" -le 700 ] && [ "$(stat -c %U "$d" 2>/dev/null)" = root ] \|\| ok=0; done; [ "$ok" = 1 ] && echo PASS \|\| echo FAIL` | 输出 PASS（五个 cron 目录权限均 ≤700 且属主 root；任一不满足判 FAIL） | medium | 8.1.4.2 |
| FILE-07 | TCP Wrappers 配置文件权限（hosts.allow/deny） | `ok=1; for f in /etc/hosts.allow /etc/hosts.deny; do [ "$(stat -c %a "$f" 2>/dev/null)" -le 644 ] && [ "$(stat -c %U "$f" 2>/dev/null)" = root ] \|\| ok=0; done; [ "$ok" = 1 ] && echo PASS \|\| echo FAIL` | 输出 PASS（两文件权限均 ≤644 且属主 root） | low | 8.1.4.2 |
| FILE-08 | sshd_config 权限与属主 | `[ "$(stat -c %a /etc/ssh/sshd_config)" -le 600 ] && [ "$(stat -c %U:%G /etc/ssh/sshd_config)" = root:root ] && echo PASS \|\| echo FAIL` | 输出 PASS（权限 ≤600 且属主 root:root；缺省 644 判 FAIL） | medium | 8.1.4.2 |
| MISC-01 | swap 倾向值 ≤10（vm.swappiness） | `v=$(sysctl -n vm.swappiness 2>/dev/null); [ -n "$v" ] && [ "$v" -le 10 ] && echo PASS \|\| echo FAIL` | 输出 PASS（vm.swappiness ≤10；缺省 60 判 FAIL。属性能调优项，按系统角色取舍） | low | 无直接对应 |
| MISC-02 | 地址空间随机化全开（ASLR=2） | `[ "$(sysctl -n kernel.randomize_va_space 2>/dev/null)" = 2 ] && echo PASS \|\| echo FAIL` | 输出 PASS（kernel.randomize_va_space=2；0/1 判 FAIL） | medium | 8.1.4.4 |
| MISC-03 | 禁用 setuid 程序 core dump（suid_dumpable=0） | `[ "$(sysctl -n fs.suid_dumpable 2>/dev/null)" = 0 ] && echo PASS \|\| echo FAIL` | 输出 PASS（fs.suid_dumpable=0；缺省 2（受保护调试，但仍产生转储）判 FAIL） | medium | 8.1.4.8 |
| MISC-04 | sudoers 及 sudoers.d 文件权限 | `ok=1; for f in /etc/sudoers $(find /etc/sudoers.d -type f 2>/dev/null); do [ "$(stat -c %a "$f" 2>/dev/null)" -le 440 ] && [ "$(stat -c %U "$f" 2>/dev/null)" = root ] \|\| ok=0; done; [ "$ok" = 1 ] && echo PASS \|\| echo FAIL` | 输出 PASS（/etc/sudoers 及 /etc/sudoers.d 下全部文件权限 ≤440 且属主 root；任一 644/640 判 FAIL） | medium | 8.1.4.2 |

## 抽查执行记录

执行环境：Ubuntu 24.04.3 LTS（noble），x86_64，普通用户 sf，无 sudo。执行日期：2026-10-03。从六个分类各抽 1 项（共 6 项，覆盖全部类别且方法互不重复），命令与正文一致，原样执行。

| 抽查项编号 | 执行命令 | 实际输出摘要 | 结论 | 执行日期 |
| --- | --- | --- | --- | --- |
| AUTH-01 | `v=$(awk '$1=="PASS_MAX_DAYS"{print $2; exit}' /etc/login.defs); [ -n "$v" ] && [ "$v" -le 90 ] && echo PASS \|\| echo FAIL` | `awk` 取值 `99999`（/etc/login.defs 缺省值），命令输出 `FAIL` | FAIL | 2026-10-03 |
| SSH-01 | `v=$(grep -hiE '^\s*PermitRootLogin\s+\S' /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null \| awk '{print tolower($2)}' \| tail -1); [ "$v" = no ] && echo PASS \|\| echo FAIL` | 生效值取自主配置文件 `PermitRootLogin yes`（/etc/ssh/sshd_config.d 不存在，glob 为空不影响判定），命令输出 `FAIL`。另实测本机 `sshd -T` 报 `no hostkeys available`，验证文件解析兜底路径必要 | FAIL | 2026-10-03 |
| LOG-01 | `systemctl is-enabled rsyslog 2>/dev/null \| grep -qx enabled && echo PASS \|\| echo FAIL` | `systemctl is-enabled rsyslog` 输出 `enabled`，命令输出 `PASS` | PASS | 2026-10-03 |
| NET-01 | `[ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" = 0 ] && echo PASS \|\| echo FAIL` | `sysctl -n net.ipv4.ip_forward` 输出 `1`（本机为虚拟机/容器实验环境，转发被显式开启），命令输出 `FAIL` | FAIL | 2026-10-03 |
| FILE-01 | `{ [ "$(stat -c %a /etc/shadow)" -le 640 ] && [ "$(stat -c %U:%G /etc/shadow)" = root:shadow ]; } && echo PASS \|\| echo FAIL` | `stat` 输出 `640 root:shadow`，命令输出 `PASS` | PASS | 2026-10-03 |
| MISC-02 | `[ "$(sysctl -n kernel.randomize_va_space 2>/dev/null)" = 2 ] && echo PASS \|\| echo FAIL` | `sysctl -n kernel.randomize_va_space` 输出 `2`，命令输出 `PASS` | PASS | 2026-10-03 |

抽查结果统计：6 项中 PASS 3 项（LOG-01、FILE-01、MISC-02），FAIL 3 项（AUTH-01、SSH-01、NET-01）。全部命令在目标机一次执行成功，无依赖缺失、无模糊结论。本机其他已探测但未列入抽查的事实（供引擎联调参考）：auditd 未安装（LOG-03/LOG-04 将 FAIL）；common-auth 未配置 pam_faillock（AUTH-05 将 FAIL）且含 `nullok`（AUTH-06 将 FAIL）；UMASK 为 022（AUTH-08 将 FAIL）；/etc/crontab 644、cron 目录 755（FILE-05/FILE-06 将 FAIL）；sshd_config 644（FILE-08 将 FAIL）；vm.swappiness=60（MISC-01 将 FAIL）；fs.suid_dumpable=2（MISC-03 将 FAIL）；/etc/sudoers.d 下存在 644 的 gdb-nopasswd（MISC-04 将 FAIL）。
