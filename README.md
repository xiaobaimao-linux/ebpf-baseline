# baseline-guard

**基于 eBPF LSM 的 Linux 内核级安全基线核查与运行时主动防御工具**

面向等保2.0 / 关基 / 工控 / 容器安全场景

------

## 一、项目简介（3句话）

baseline-guard 是一款基于 eBPF LSM 的 Linux 内核级安全工具，填补了 OpenSCAP（静态扫描）与 Falco（运行时监控）之间的空白。

它做的事情：

1. **静态核查**：一次性扫描系统，对照 YAML 定义的基线检查文件权限、文件哈希等
2. **运行时监控**：通过 eBPF LSM 持续监控敏感文件的读写操作
3. **实时拦截**：支持对违规操作进行阻断（block）
4. **合规报告**：生成可用于等保/关基/密评的合规报告和证据包

适合谁用：

- 过等保2.0三级/关基保护的企业
- 工控/嵌入式 Linux 系统的安全运维团队
- 需要持续合规证据的安全服务公司
- 容器/K8s 环境的安全基线管理

------

## 二、核心功能（4大模块）

### 模块1：安全基线定义（YAML 配置）

通过 YAML 文件定义系统的安全期望状态。支持三种规则类型：

| 规则类型                     | 说明                             | 适用模式        |
| ---------------------------- | -------------------------------- | --------------- |
| **check only**               | 仅静态检查（文件权限、文件哈希） | check           |
| **monitor only**             | 仅运行时监控（文件读写）         | monitor         |
| **combo（check + monitor）** | 静态检查 + 运行时监控            | check + monitor |

#### 支持的检查类型（check）

| 检查类型          | 说明                     | 示例                                 |
| ----------------- | ------------------------ | ------------------------------------ |
| `file_permission` | 检查文件权限是否为期望值 | `/etc/passwd` 应为 `0644`            |
| `file_hash`       | 检查文件哈希是否匹配     | `/usr/bin/sshd` 的 SHA256 应为指定值 |

#### 支持的监控事件（monitor）

| 事件类型 | 说明                | 挂钩点                                                  |
| -------- | ------------------- | ------------------------------------------------------- |
| `read`   | 监控文件被读取      | LSM `security_file_permission`                          |
| `write`  | 监控文件被写入/修改 | LSM `security_file_permission` + kprobe `chmod`/`chown` |

#### 动作（action）

| 动作    | 说明                                   |
| ------- | -------------------------------------- |
| `alert` | 仅告警，不拦截                         |
| `block` | 拦截操作（返回 EPERM），并杀死违规进程 |

#### 告警配置

支持钉钉机器人告警，可配置频率限制：

```
alert:
  dingtalk:
    webhook: "https://oapi.dingtalk.com/robot/send?access_token=xxx"
    secret: "xxx"  # 可选，加签密钥
  throttle: 300    # 同一规则5分钟内只告警一次（秒）
```

------

### 模块2：静态基线核查（check 模式）

一次性扫描系统，对照 YAML 基线输出合规状态。

```
$ ./baseline-guard check -c rules.yaml

[SYS-PERM-001] /etc/passwd
  ✓ PASS: mode 0644 (expected 0644)

[SYS-HASH-001] /usr/bin/sshd
  ✓ PASS: mode 0644 (expected 0644)
  ✓ PASS: sha256 matches

[SYS-COMBO-001] /home/sf/combo.txt
  ✗ FAIL: mode 0777 (expected 0644)
  ✓ PASS: sha256 matches

合规评分：75/100
```

------

### 模块2：静态基线核查（check 模式）

一次性扫描系统，对照 YAML 基线输出合规状态。

```
$ ./baseline-guard check -c rules.yaml

[SYS-PERM-001] /etc/passwd
  ✓ PASS: mode 0644 (expected 0644)

[SYS-HASH-001] /usr/bin/sshd
  ✓ PASS: mode 0644 (expected 0644)
  ✓ PASS: sha256 matches

[SYS-COMBO-001] /home/sf/combo.txt
  ✗ FAIL: mode 0777 (expected 0644)
  ✓ PASS: sha256 matches

合规评分：75/100
```

### 模块3：基线快照（baseline snapshot）

`baseline snapshot` 是不依赖 YAML 规则的底层基线采集命令，直接扫描一个或多个文件/目录，并将当前文件状态写入 SQLite。目录默认递归扫描；每个文件在 `baseline_entries` 中只保留一条当前生效记录，实际新增、修改和删除会记录到 `baseline_audit`。

```bash
./baseline-guard baseline snapshot /etc /usr/bin \
  --db /var/lib/baseline-guard/baseline.db \
  --label release-2026-08-12 \
  --exclude /etc/cache
```

支持的选项：

- `PATH...`：至少一个文件或目录，可指定多个。
- `--db PATH`：指定 SQLite 数据库，默认 `/var/lib/baseline-guard/baseline.db`。
- `--label NAME`：本次快照标签，默认 `default`。
- `--exclude PATH`：单次扫描临时排除路径，可重复使用，不会修改全局白名单。
- `--no-recurse`：目录只扫描直接子文件，不进入下级目录。

重复执行相同快照不会产生新的审计变更；文件内容、权限、属主或元数据发生变化时会产生 `modified` 记录。只扫描部分目录时，只会处理当前扫描作用域中的删除，不会影响其他目录的基线。

------

### 模块4：运行时 eBPF LSM 监控（monitor 模式）

持续监控系统运行时状态，检测基线偏离。

```
$ ./baseline-guard monitor -c rules.yaml

[2026-08-05 14:32:01] [CRITICAL] SYS-MONITOR-abc.txt
  Process: /usr/bin/vim (PID=1234, PPID=1)
  Event:   WRITE /home/sf/abc.txt.12345678901234567890
  Action:  BLOCKED (rule: SYS-MONITOR-abc.txt)

[2026-08-05 14:35:22] [MEDIUM] SYS-COMBO-001
  Process: /usr/bin/cat (PID=5678, PPID=1)
  Event:   READ /home/sf/combo.txt.12345678901234567890
  Action:  ALERTED (rule: SYS-COMBO-001, monitor action: block but event is read)
```

------

### 模块4：monitor 事件报告

```bash
./baseline-guard report --start 2026-08-01 --end 2026-08-10 -o ./monitor-events.html
```

`report` 从 SQLite 的 `alerts` 表读取 monitor 持久化的原始事件并输出 HTML。`-o` 指定输出文件，不能省略；无需传入规则配置文件。

- `--start`：包含式开始时间，可省略
- `--end`：包含式结束时间，可省略
- 时间支持 `YYYY-MM-DD`、`YYYY-MM-DD HH:MM:SS` 和 `YYYY-MM-DDTHH:MM:SS`
- 仅指定日期时，开始日期按 `00:00:00`、结束日期按 `23:59:59` 处理
- 两个时间参数都省略时输出全部 monitor 事件

报告包含事件时间、规则、严重级别、文件、事件类型、进程/PID、用户/UID、预期值、实际值和动作。原有 `alerts` 命令仍用于控制台查询；HTML 输出已从 `alerts --report_html` 迁移到 `report -o`。

------

## 三、快速开始（3步）

```
# 1. 编译
git clone https://github.com/yourname/baseline-guard.git
cd baseline-guard
make

# 2. 静态核查
./baseline-guard check -c examples/rules.yaml

# 3. 运行时监控
./baseline-guard monitor -c examples/rules.yaml
```

------

## 四、与现有工具的对比

| 工具           | 能力           | baseline-guard 差异      |
| -------------- | -------------- | ------------------------ |
| OpenSCAP/Lynis | 静态基线检查   | ✅ 静态 + 运行时验证      |
| Falco          | 运行时异常检测 | ✅ 有基线定义，不只是规则 |
| Tetragon       | 运行时拦截     | ✅ 有合规报告，不只是安全 |
| 等保测评工具   | 人工检查为主   | ✅ 自动化 + 持续监控      |



------

## 五、等保2.0 映射表

| 等保控制项       | baseline-guard 规则    | 检查/监控类型          |
| ---------------- | ---------------------- | ---------------------- |
| 7.1.3.1 身份鉴别 | 空口令用户检查         | check（用户态）        |
| 7.1.3.2 访问控制 | `/etc/passwd` 权限检查 | check: file_permission |
| 7.1.3.2 访问控制 | 敏感文件读取监控       | monitor: read          |
| 7.1.3.2 访问控制 | 敏感文件写入拦截       | monitor: write + block |
| 7.1.3.3 安全审计 | eBPF 监控事件输出      | monitor: 全部事件      |
| 7.1.3.4 入侵防范 | 关键文件哈希校验       | check: file_hash       |
| 7.1.3.4 入侵防范 | 异常文件修改拦截       | monitor: write + block |

------

## 六、项目结构

```
baseline-guard/
├── src/
│   ├── main.c           # CLI 入口
│   ├── config.c         # YAML 解析器
│   ├── checker.c        # 静态核查
│   ├── monitor.c        # eBPF 加载 + 事件处理
│   └── reporter.c       # 报告生成
├── bpf/
│   ├── lsm_file.bpf.c   # eBPF LSM 程序
│   └── kprobe_chmod.bpf.c  # kprobe 监控程序
├── include/
│   └── baseline_guard.h # 公共头文件
├── examples/
│   └── rules.yaml       # 示例配置文件
├── Makefile
└── README.md
```

------

## 七、技术栈

| 组件       | 选型                  |
| ---------- | --------------------- |
| 用户态语言 | C/C++                 |
| eBPF 框架  | libbpf + BPF skeleton |
| 配置格式   | YAML（libyaml）       |
| 报告输出   | HTML（可转 PDF）      |
| 日志       | 文件 + syslog         |
| 告警       | 钉钉机器人            |
| 历史存储   | SQLite                |

------

## 八、项目状态

**当前版本：v0.1（MVP）**

已实现：

- ✅ YAML 配置解析（check + monitor + combo）
- ✅ 文件权限静态核查（file_permission）
- ✅ 文件哈希校验（file_hash）
- ✅ eBPF LSM 文件读写监控（read / write）
- ✅ 运行时拦截（block action）
- ✅ 钉钉告警推送
- ✅ CLI 彩色输出

开发中：

- 🔄 内核参数基线
- 🔄 进程白名单基线
- 🔄 网络端口基线
- 🔄 合规报告生成
- 🔄 告警频率限制

------

## 九、商业合作

baseline-guard 采用 **开源核心 + 企业版授权** 模式。

**企业版提供：**

- 完整基线库（等保三级、CIS、工控等 50+ 条规则）
- 多节点集中管理
- 合规报告品牌化（可自定义 Logo 和公司信息）
- 钉钉/企微/飞书多通道告警
- 技术支持

**服务项目：**

- 等保自查服务（远程/现场）
- 内核安全咨询
- eBPF LSM 定制开发
- 企业版授权

**联系方式：**

- 邮箱：xiaobaimao-linux@proton.me
- 知乎：https://www.zhihu.com/people/q1w2e3r4t5y6-86

------

## 十、许可证

Apache License 2.0
