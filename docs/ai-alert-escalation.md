# AI 告警联动升级设计（W5 D3 设计，实现排 W6）

> 日期：2026-10-08。状态：**仅设计，未实现**。依赖 W5 D1/D2 已落地的资产侧数据
> （process 资产 `detail_json.ai_workload` / `ai_signals`，model_file 资产表）。
> 预估工作量：**≤0.5 天**（改动集中在规则命中后的告警构建单点 + 单测）。

## 1. 目标

AI 工作负载进程触发的告警、或告警目标涉及模型文件路径时，告警严重级别**自动升一级**
（low→medium→high→critical，critical 封顶不变）。依据：AI 训练/推理进程持有高价值资产
（模型权重、训练数据、GPU 资源），同一可疑行为发生在 AI 进程身上，业务损失与攻击价值
显著高于普通进程。

## 2. 判定时机与字段来源

### 2.1 判定时机：规则引擎求值命中后、AlertEvent 构建时

挂钩点在 `src/baseline/monitor.cpp` 规则命中后构建 `AlertEvent` 的单点
（现 `evt.severity = severityToString(rule.severity)` 处，monitor.cpp:283/373）。

**不在规则 DSL 条件内做**（不加 `asset.ai_workload = true` 之类的条件字段），理由：

- 升级是**告警侧横切策略**，对全部规则统一生效；写进 DSL 要求每条规则重复声明，漏配即失效；
- 规则求值是每事件热路径，资产查询（SQLite）不应进入匹配条件；命中后才查一次，成本可忽略
  （命中量 << 事件量，且多数命中还会被节流窗口挡在构建之前——`ThrottledNow` 预检在构建前，
  节流期内连资产查询都不发生）。

### 2.2 字段来源

| 判定输入 | 来源 | 说明 |
|---|---|---|
| 进程是否 AI 工作负载 | `assets` 表 `asset_type='process'`、`name = comm(pid)`，`json_extract(detail_json,'$.ai_workload')` | W5 D2 已落库；命中信号在 `$.ai_signals`（cmdline:torch_path / maps:libcuda / env:CUDA_VISIBLE_DEVICES 等） |
| 目标是否模型文件 | `assets` 表 `asset_type='model_file'`、`name = <绝对路径>` 精确匹配告警 `file_path` | W5 D1 已落库；精确匹配，不做前缀（避免 /models/ 下普通文件误升） |
| 标记新鲜度 | `assets.last_seen` | 见 §3 边界 |

告警侧新增字段（`AlertEvent` + `alerts` 表按需加列，或复用 detail 思路落 JSON）：

- `severity_origin`：规则原始级别（升级前），审计可追溯；
- `ai_boost`：升级原因，空串=未升级；取值 `process_ai_workload` / `model_file_target`，
  两者同时命中以逗号连接，级别仍只升一级（不叠加）。

钉钉模板在"严重级别"行后追加一行 `**AI 升级**: high → critical (process_ai_workload)`。

## 3. 边界与退化行为

| 边界 | 行为 |
|---|---|
| **标记过期** | 进程资产 `last_seen` 距当前超过 **2 个采集周期**（采集周期由外部调用 `asset collect` 的节奏决定，运行时读不到调度配置，故用相对阈值：默认 2×3600s 可配 `alert.ai_boost.stale_seconds`）→ 视为标记失效，不升级。防止"进程曾是 AI、早已退出，pid 复用后告警仍被升级" |
| **进程退出后** | 告警事件本身由 eBPF 实时产生，进程在事件发生时存活；资产标记只要新鲜（上周期采集到）即有效。进程退出不改变已发告警；pid 复用由 `comm(pid)` 组合键 + 新鲜度双重约束，残余误判窗口 ≤1 个采集周期，可接受 |
| **进程从未被采集到**（采集间隔内生灭、或 collect 未运行） | 查不到资产行 → 不升级，保持原级别（宁缺毋滥，升级是增强而非兜底） |
| **critical 封顶** | 原级别 critical 不再升，仅记录 `ai_boost` 原因 |
| **节流不受影响** | 节流 key 仍为 `rule_id`（AlertManager::IsThrottled），升级在节流预检之后发生，不改变风暴抑制口径 |
| **model_file 命中但进程非 AI** | 同样升一级（模型文件本身是高价值目标，如 `cat /data/model.pt` 的是运维脚本也升级） |

## 4. 场景示例

规则（rules/examples/read_etc_shadow.yaml，`priority: high`）：

```yaml
- rule: Read Etc Shadow By Unusual Process
  condition: event_type = file.read and file.path = /etc/shadow and not process.exe in (/usr/bin/passwd, ...)
  priority: high
```

### 场景 1：AI 训练进程读 /etc/shadow → high 升 critical

```
python3 /home/u/.local/lib/python3.10/site-packages/torch/distributed/run.py  (pid=4210)
  → open(/etc/shadow, O_RDONLY)
```

- 规则命中，原始级别 high；
- 资产查询：`process` 资产 `python3(4210)` 的 `ai_workload=true`
  （`ai_signals=["cmdline:torch_path","maps:libcuda"]`），`last_seen` 新鲜；
- 升级：**high → critical**，`ai_boost=process_ai_workload`，`severity_origin=high`；
- 钉钉按 critical 渠道/样式发出（红色 emoji 路径），落库同。

### 场景 2：普通进程读同文件 → 不变

```
cat /etc/shadow  (pid=4300, exe=/usr/bin/cat)
```

- 规则命中，原始级别 high；
- 资产查询：`process` 资产 `cat(4300)` 的 `ai_workload=false`（或无该行）；
  `file_path=/etc/shadow` 不在 `model_file` 资产中；
- 不升级：**保持 high**，`ai_boost` 空串，与原行为完全一致。

## 5. W6 实现清单（≤0.5 天）

1. `monitor.cpp` 告警构建点插入 `MaybeBoostSeverityForAi(evt)`：两次 SQLite 点查
   （process by `comm(pid)`、model_file by `file_path`），新鲜度判断，升级 + 填新字段（0.5h）；
2. `AlertEvent`/`alerts` 表加 `severity_origin`、`ai_boost` 两列（老库 ALTER 兼容，沿用
   baseline_db.cpp 既有加列套路）；钉钉模板加一行（1h）；
3. 单测：构造 BaselineDB 内存库写入 ai_workload=true/false + model_file 行，喂
   升级函数断言级别映射与 stale 行为（1.5h）；
4. 联调：rules/examples/read_etc_shadow.yaml 双场景各跑一遍，核 alerts 表与钉钉文案（0.5h）。

合计约 3.5h ≤ 0.5 天。风险：资产采集周期若过长（小时级），短生命周期 AI 进程可能漏标 →
不升级（退化安全，方向正确）；如需收紧可在 W6 顺带把 `asset collect` 挂进 cron 分钟级。
