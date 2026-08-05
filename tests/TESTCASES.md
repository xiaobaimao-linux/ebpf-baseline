# baseline-guard 测试用例设计

## 一、单元测试 (Unit Tests)

### 1. 配置解析测试 (test_config)

| 编号 | 用例名称 | 前置条件 | 操作步骤 | 预期结果 | 验证点 |
|------|---------|---------|---------|---------|--------|
| CFG-001 | INI正常解析 | 存在合法INI文件 | 调用 `parseIniFile("test.ini")` | 返回规则列表，size=2 | 规则name、path、mode、hash、action正确 |
| CFG-002 | INI文件不存在 | 文件路径无效 | 调用 `parseIniFile("/nonexist.ini")` | 返回空列表 | 日志输出错误 |
| CFG-003 | INI非法mode值 | mode="abc" | 调用 `parseIniFile` | 规则mode=0，输出warn | 不崩溃 |
| CFG-004 | INI缺失section内容 | `[empty]`后无键值 | 调用 `parseIniFile` | 规则有默认值 | 不崩溃 |
| CFG-005 | YAML正常解析 | 存在合法YAML文件 | 调用 `parseYamlFile("test.yaml")` | 返回规则列表，size=2 | id+name组合正确，type映射正确 |
| CFG-006 | YAML缺少rules根节点 | 文件内容 `{}` | 调用 `parseYamlFile` | 返回空列表 | 日志输出错误 |
| CFG-007 | YAML缺少check节点 | rules中无check | 调用 `parseYamlFile` | 跳过该规则 | 输出warn |
| CFG-008 | YAML未知check_type | type="unknown" | 调用 `parseYamlFile` | 规则path为空 | 输出warn |
| CFG-009 | 空文件解析 | 文件大小为0 | 调用 `parseIniFile` / `parseYamlFile` | 返回空列表 | 不崩溃 |
| CFG-010 | 混合注释和空行 | INI含#、;、空行 | 调用 `parseIniFile` | 正确解析 | 注释不影响 |

### 2. 基线检查测试 (test_check)

| 编号 | 用例名称 | 前置条件 | 操作步骤 | 预期结果 | 验证点 |
|------|---------|---------|---------|---------|--------|
| CHK-001 | 全部通过 | 文件存在，权限匹配，hash匹配 | `do_check(config, db)` | return 0 | `[PASS]`日志，db入库 |
| CHK-002 | 文件不存在 | path指向不存在的文件 | `do_check(config, db)` | return 1 | `[FAIL]`日志，db不入库 |
| CHK-003 | 权限不匹配 | mode预期644，实际600 | `do_check(config, db)` | return 1 | `[FAIL]`日志，db入库 |
| CHK-004 | hash不匹配 | hash预期≠实际 | `do_check(config, db)` | return 1 | `[FAIL]`日志，db入库 |
| CHK-005 | 权限+hash双失败 | 两者都不匹配 | `do_check(config, db)` | return 1 | 只计1次失败（按rule） |
| CHK-006 | 无hash配置 | has_hash=false | `do_check(config, db)` | return 0/1视权限 | 不计算hash |
| CHK-007 | 空规则列表 | config.rules为空 | `do_check(config, db)` | return 0 | "检查完成: 0 通过, 0 失败" |
| CHK-008 | 基线入库验证 | check完成后 | 查询db | 记录存在 | path/permission/hash/owner/group/at齐全 |

### 3. 工具函数测试 (test_utils)

| 编号 | 用例名称 | 前置条件 | 操作步骤 | 预期结果 |
|------|---------|---------|---------|--------|
| UTL-001 | SHA256计算 | 创建临时文件"hello" | `compute_sha256(path)` | 返回固定256位hex |
| UTL-002 | SHA256不存在的文件 | path无效 | `compute_sha256(path)` | 抛出runtime_error |
| UTL-003 | mode转字符串 | mode=0644 | `mode_to_string(0644)` | "rw-r--r--" |
| UTL-004 | mode转字符串-全权限 | mode=0777 | `mode_to_string(0777)` | "rwxrwxrwx" |
| UTL-005 | mode转字符串-无权限 | mode=0000 | `mode_to_string(0000)` | "---------" |

---

## 二、集成测试 (Integration Tests)

### 4. check命令集成测试

| 编号 | 用例名称 | 前置条件 | 操作步骤 | 预期结果 | 验证点 |
|------|---------|---------|---------|---------|--------|
| INT-001 | check INI全通过 | 准备test_pass.ini | `./baseline-guard check -c test_pass.ini` | exit=0 | `[service_start]`, `[rules_loaded]`, `[baseline_created]`, `[service_stop]` |
| INT-002 | check INI有失败 | 准备test_fail.ini | `./baseline-guard check -c test_fail.ini` | exit=1 | `[FAIL]`日志，统计失败=1 |
| INT-003 | check YAML格式 | 准备test_pass.yaml | `./baseline-guard check -c test_pass.yaml` | exit=0 | `[rules_loaded] format=yaml` |
| INT-004 | check 无配置文件 | 不指定-c | `./baseline-guard check` | exit=1 | stderr: "config file required" |
| INT-005 | check 配置文件不存在 | -c /nonexist | `./baseline-guard check -c /nonexist` | exit=0(空规则)或1 | 日志: 无法打开文件 |

### 5. monitor命令集成测试

| 编号 | 用例名称 | 前置条件 | 操作步骤 | 预期结果 | 验证点 |
|------|---------|---------|---------|---------|--------|
| INT-006 | monitor正常启动 | root权限，LSM可用 | `sudo ./baseline-guard monitor -c test.ini` | 输出Monitoring started | `[bpf_program_loaded]` |
| INT-007 | monitor文件写入告警 | monitor运行中 | `echo x >> /monitored/file` | 输出[ALERT] | pid/comm/path正确 |
| INT-008 | monitor hash不匹配 | monitor运行中，修改文件 | `echo changed >> /monitored/file` | 输出[ALERT] hash mismatch | expected(mode) vs current |
| INT-009 | monitor BLOCK模式 | action=block | `echo x >> /blocked/file` | 写入被拒绝(EPERM) | `[ALERT]`, 文件内容不变 |
| INT-010 | monitor非root启动 | 普通用户 | `./baseline-guard monitor` | 失败或权限错误 | `[bpf_program_error]` |
| INT-011 | monitor SIGTERM退出 | monitor运行中 | `kill -TERM <pid>` | 优雅退出 | `[service_stop]` |
| INT-012 | monitor SIGHUP重载 | monitor运行中 | `kill -HUP <pid>` | 重新加载配置 | `[rules_reload]` |

---

## 三、端到端测试 (E2E Tests)

### 6. 完整工作流测试

| 编号 | 用例名称 | 前置条件 | 操作步骤 | 预期结果 |
|------|---------|---------|---------|--------|
| E2E-001 | 初始化→check→monitor→篡改→告警 | 干净环境 | 1. 首次check建基线 2. 启动monitor 3. 修改文件 4. 观察告警 | 检测到篡改，输出[ALERT] |
| E2E-002 | 权限漂移检测 | 文件权限正确 | 1. check通过 2. chmod改变权限 3. 再次check | 检测到权限变化，[FAIL] |
| E2E-003 | 多规则混合场景 | 3个文件不同配置 | check/monitor覆盖全部 | 每个规则独立计成功/失败 |
| E2E-004 | 长时间稳定性 | monitor运行1小时 | 持续监控，期间正常/异常写入 | 无内存泄漏，无coredump |
| E2E-005 | 配置热重载 | monitor运行中 | 1. 修改YAML 2. SIGHUP 3. 新规则生效 | 新文件被监控，旧文件不再监控 |

---

## 四、性能/压力测试

| 编号 | 用例名称 | 前置条件 | 操作步骤 | 预期结果 |
|------|---------|---------|---------|--------|
| PERF-001 | 100规则check | 100个文件配置 | `./baseline-guard check` | 完成时间 < 5s |
| PERF-002 | 高频率文件写入 | monitor运行中 | 1000次/秒写入监控文件 | 无丢事件，内存稳定 |
| PERF-003 | 大文件hash计算 | 1GB文件 | `compute_sha256` | 完成，不OOM |

---

## 五、异常/边界测试

| 编号 | 用例名称 | 前置条件 | 操作步骤 | 预期结果 |
|------|---------|---------|---------|--------|
| EXC-001 | 路径含特殊字符 | path="/tmp/a b/c" | check/monitor | 正确处理空格 |
| EXC-002 | 符号链接 | path指向symlink | check | 跟随或不跟随，行为一致 |
| EXC-003 | 无权限访问文件 | 文件owner=root, mode=000 | check | `[FAIL]`, 不crash |
| EXC-004 | 磁盘满 | db目录满 | check | 优雅失败，日志记录 |
| EXC-005 | 内核不支持LSM | 老内核无BPF_LSM | monitor | `[bpf_program_error]`, exit=1 |
| EXC-006 | 重复加载BPF | 已有一个monitor运行 | 启动第二个 | 失败或资源冲突提示 |
