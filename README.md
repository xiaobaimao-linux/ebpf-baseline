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

## 二、核心功能（6大模块）

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

### 模块2：静态合规核查（check 模式）

基于 YAML 规则的一次性扫描，对照基线输出合规状态。

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

### 模块3：基线快照管理（baseline 子命令）

`baseline` 子命令族提供完整的基线生命周期管理，数据存储在 SQLite 中。所有子命令支持 `--db PATH` 指定数据库路径。

#### 3.1 baseline snapshot — 采集基线

扫描文件/目录，将当前状态写入 SQLite。目录默认递归扫描；每个文件在 `baseline_entries` 中只保留一条当前生效记录，变更会记录到 `baseline_audit`。

```bash
./baseline-guard baseline snapshot /etc /usr/bin \
  --db /var/lib/baseline-guard/baseline.db \
  --label release-2026-08-12 \
  --exclude /etc/cache
```

| 参数             | 说明                                                    |
| ---------------- | ------------------------------------------------------- |
| `PATH...`        | 至少一个文件或目录（必填）                              |
| `--db PATH`      | SQLite 数据库路径                                       |
| `--label NAME`   | 快照标签，默认 `default`                                |
| `--exclude PATH` | 排除路径，可重复                                        |
| `--no-recurse`   | 目录只扫描直接子文件                                    |

#### 3.2 baseline list — 查询基线

分页查询已采集的基线条目，支持路径模糊过滤和 JSON 输出。

```bash
# 按目录过滤，前50条
./baseline-guard baseline list --path-filter "/etc/ssh/%" --limit 50

# 分页：第2页
./baseline-guard baseline list --limit 50 --offset 50

# 全量 JSON 导出
./baseline-guard baseline list --json > baseline.json
```

| 参数                    | 说明                                            |
| ----------------------- | ----------------------------------------------- |
| `--db PATH`             | SQLite 数据库路径                               |
| `--path-filter PATTERN` | SQL LIKE 路径过滤（`%` 为通配符）               |
| `--limit N`             | 结果行数上限                                    |
| `--offset N`            | 分页偏移量                                      |
| `--json`                | 输出结构化 JSON                                 |

#### 3.3 baseline delete — 删除基线

手动删除指定路径的基线记录，支持多路径和递归删除。

```bash
# 精确删除单文件基线
./baseline-guard baseline delete /etc/passwd --db baseline.db

# 目录递归删除所有子文件基线
./baseline-guard baseline delete /etc --recurse --db baseline.db

# 多路径混合
./baseline-guard baseline delete /etc/passwd /root/.ssh --recurse
```

| 参数          | 说明                                                     |
| ------------- | -------------------------------------------------------- |
| `PATH...`     | 待删除的文件/目录路径（必填）                            |
| `--db PATH`   | SQLite 数据库路径                                        |
| `--recurse`   | 目录路径启用递归前缀匹配；文件路径始终精确匹配          |

每条删除自动生成 `baseline_audit` 审计记录（`op_type=delete`，保留旧基线值）。

#### 3.4 baseline check — 离线一致性核查

读取 `baseline_entries` 中的基线 → 逐个比对磁盘真实文件 → 识别篡改和文件消失。差异写入 `alerts` 表（`rule_id=baseline-check`），可选推送钉钉、输出 HTML 报告。

```bash
# 全量离线核查，控制台输出
./baseline-guard baseline check --db baseline.db

# 仅校验 /etc 下已快照基线
./baseline-guard baseline check --path-filter "/etc%"

# 检出差异推送钉钉（需指定 YAML 配置）
./baseline-guard baseline check --send-webhook -c config.yaml

# 核查并导出 HTML 审计报表
./baseline-guard baseline check --path-filter "/etc%" --report_html check.html

# JSON 结构化输出
./baseline-guard baseline check --json
```

| 参数                    | 说明                                                     |
| ----------------------- | -------------------------------------------------------- |
| `--db PATH`             | SQLite 数据库路径                                        |
| `--path-filter PATTERN` | SQL LIKE 过滤，只校验匹配路径的基线条目                  |
| `--report_html FILE`    | 输出差异告警到 HTML 文件（控制台不再输出告警详情）        |
| `--json`                | 输出结构化 JSON 数组                                     |
| `--send-webhook`        | 将检出差异推送钉钉（需配合 `-c` 指定 YAML 配置）         |
| `-c, --config PATH`     | YAML 配置文件路径（提供钉钉 webhook 等配置）             |

比对项与事件类型：

| 比对项                     | event_type       | severity | 说明                               |
| -------------------------- | ---------------- | -------- | ---------------------------------- |
| 磁盘文件缺失               | `missing`        | high     | 基线存在但磁盘文件已消失           |
| sha256 不一致              | `hash_changed`   | high     | 文件内容被篡改                     |
| hash 一致、权限/属主变动   | `perm_changed`   | medium   | 权限/uid/gid 变动但内容未变        |
| 文件读取权限不足           | `access_failed`  | medium   | 无法计算哈希（权限不足等）         |

> **注意**：只检查库内已有基线，不扫描磁盘新增文件。不跟随 symlink。差异始终写入 `alerts` 表；钉钉仅 `--send-webhook` 时推送，复用现有节流降噪逻辑。

#### 3.5 baseline clean — 清理孤儿基线

自动识别并清理磁盘上已不存在的孤儿基线记录。会删除 `baseline_entries` 并写入 `baseline_audit` 审计。

```bash
# 先预演，查看哪些孤儿基线会被清理
./baseline-guard baseline clean --dry-run --db baseline.db

# 确认无误，真实清理
./baseline-guard baseline clean --db baseline.db
```

| 参数          | 说明                                                   |
| ------------- | ------------------------------------------------------ |
| `--db PATH`   | SQLite 数据库路径                                      |
| `--dry-run`   | 预扫描模式：只打印待清理条目，不执行删除               |

> **与 `baseline delete` 的区别**：`delete` 是人工指定路径主动删除；`clean` 是自动识别磁盘已消失的僵尸基线批量清理。

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

### 模块5：告警查询（alerts）

查询 SQLite 中持久化的告警记录。

```bash
# 查看最新20条告警
./baseline-guard alerts

# 查看今日告警，按规则过滤
./baseline-guard alerts --today --rule SYS-MONITOR

# 限制数量
./baseline-guard alerts -n 50
```

------

### 模块6：monitor 事件报告（report）

```bash
./baseline-guard report --start 2026-08-01 --end 2026-08-10 -o ./monitor-events.html
```

`report` 从 SQLite 的 `alerts` 表读取 monitor 持久化的原始事件并输出 HTML。`-o` 指定输出文件，不能省略；无需传入规则配置文件。

- `--start`：包含式开始时间，可省略
- `--end`：包含式结束时间，可省略
- 时间支持 `YYYY-MM-DD`、`YYYY-MM-DD HH:MM:SS` 和 `YYYY-MM-DDTHH:MM:SS`
- 仅指定日期时，开始日期按 `00:00:00`、结束日期按 `23:59:59` 处理
- 两个时间参数都省略时输出全部 monitor 事件

报告包含事件时间、规则、严重级别、文件、事件类型、进程/PID、用户/UID、预期值、实际值和动作。

------

## 三、快速开始

```
# 1. 编译
make

# 2. 采集基线快照
./baseline-guard baseline snapshot /etc/ssh --db baseline.db --label initial

# 3. 查看已采集基线
./baseline-guard baseline list --db baseline.db

# 4. 离线一致性核查
./baseline-guard baseline check --db baseline.db -o check-report.html

# 5. 基于 YAML 规则的静态合规检查
./baseline-guard check -c baselines/default.yaml

# 6. 运行时监控（需要 root）
sudo ./baseline-guard monitor -c baselines/default.yaml
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
│   ├── main.cpp                          # CLI 入口 + 命令路由
│   ├── alerts/
│   │   ├── alert_manager.cpp/hpp         # 告警管理 + 钉钉推送
│   ├── baseline/
│   │   ├── baseline_snapshot.cpp/hpp     # baseline snapshot 子命令
│   │   ├── baseline_list.cpp/hpp         # baseline list 子命令
│   │   ├── baseline_delete.cpp/hpp       # baseline delete 子命令
│   │   ├── baseline_check.cpp/hpp        # baseline check 子命令
│   │   └── baseline_clean.cpp/hpp        # baseline clean 子命令
│   ├── check/
│   │   └── check.cpp/hpp                 # YAML 规则静态核查
│   ├── cli/
│   │   ├── config.cpp/hpp                # YAML 配置解析
│   │   └── baseline.hpp                  # 旧版 check 命令接口
│   ├── common/
│   │   ├── utils.cpp/hpp                 # SHA256 / 权限转换等工具函数
│   │   ├── commonfun.cpp/hpp             # 通用辅助函数
│   │   ├── nlohmann/json.hpp             # JSON 库
│   │   ├── spdlog/                       # 日志库
│   │   └── logger.h                      # 日志初始化
│   ├── monitor/
│   │   └── monitor.cpp/hpp               # eBPF LSM 加载 + 事件处理
│   ├── report/
│   │   └── report_generator.cpp/hpp      # HTML 报告生成
│   └── storage/
│       └── baseline_db.cpp/hpp           # SQLite 数据层
├── bpf/
│   ├── vmlinux.h                         # 内核类型定义
│   ├── event.h                           # BPF 事件结构
│   ├── lsm_file.bpf.c                    # eBPF LSM 程序
│   └── lsm_file.skel.h                   # BPF skeleton 头文件
├── baselines/
│   └── default.yaml                      # 默认基线规则
├── tests/                                # 测试用例
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

**当前版本：v0.3**

已实现：

- ✅ YAML 配置解析（check + monitor + combo）
- ✅ 文件权限静态核查（file_permission）
- ✅ 文件哈希校验（file_hash）
- ✅ eBPF LSM 文件读写监控（read / write）
- ✅ 运行时拦截（block action）
- ✅ 钉钉告警推送 + 频率限制
- ✅ 基线快照管理（snapshot / list / delete / check / clean）
- ✅ SQLite 审计日志（baseline_audit）
- ✅ HTML 合规报告 + 基线核查报告
- ✅ monitor 事件报告导出
- ✅ 告警历史查询（alerts）

开发中：

- 🔄 内核参数基线
- 🔄 进程白名单基线
- 🔄 网络端口基线

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
