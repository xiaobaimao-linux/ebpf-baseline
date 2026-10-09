# W5 校准纪要（W5 收官）

> 日期：2026-10-09。口径：W5 清单按 D1–D5 任务卡还原为 14 项可勾选交付物；
> 实测数据引自 tests/perf 结果文件（/tmp/bg-perf/results/）与当次 monitor 日志。

## 1. 完成率统计

| # | 计划项 | 状态 | 证据 |
|---|---|---|---|
| 1 | GPU 统一采集接口 IGpuCollector + nvidia-smi 解析落地 | ✓ | src/asset/gpu_collector.cpp，单测 GPU-001~005 |
| 2 | 昇腾/海光国产 GPU stub（未适配标记） | ✓ | 同上，GPU-005 |
| 3 | 模型文件发现（扩展名+魔数、深度≤4、不跟符号链接） | ✓ | src/asset/model_file_collector.cpp，MDL-001~004 |
| 4 | asset collect/list 接入 GPU 与模型文件 | ✓ | src/asset/README.md，asset list 可查 |
| 5 | AI 工作负载进程识别（cmdline/environ/maps 三特征） | ✓ | src/asset/asset_collector.cpp，test_ai_workload 4 例 |
| 6 | ai_workload/ai_signals 落库 + 进程采集幂等修复 | ✓ | commit 453963f |
| 7 | 告警四级 severity 体系（枚举 + DSL priority 可选） | ✓ | src/common/severity.hpp，RDSL-006/007 |
| 8 | AI 告警联动升级设计文档（实现排 W6） | ✓ | docs/ai-alert-escalation.md |
| 9 | webhook 异步外发（队列+工作线程+重试，不阻塞消费线程） | ✓ | src/alerts/notify_dispatcher.cpp / webhook_notifier.cpp |
| 10 | 级别路由 min_level（低级仅落库） | ✓ | notify_router.hpp，NRT-001/002 |
| 11 | 静默窗口（同 rule_id+对象 key） | ✓ | 同上，NRT-003/004 |
| 12 | 外发计数 sent/failed/suppressed/dropped | ✓ | 60s tick `[notify] stats` + 退出时 final stats |
| 13 | 聚合降噪（同规则同对象窗口合并，occurrences=N 摘要） | ✓ | tests/perf/run_agg_storm.sh，见下方实测 |
| 14 | 端到端回归 + 性能冒烟 | ✓ | 见下方实测 |

**完成率 14/14 = 100%**。两处口径说明（主动决策，非滑落）：

- 聚合降噪的实现口径相对 W4 差距清单 #1 做了收窄：只聚合外发侧，落库保持逐条。理由是审计留痕与降噪解耦——聚合摘要让接收者不被刷屏，逐条落库保证事后可溯。差距清单 #1 的"落库加 count 列"随之取消。
- AI 告警升级"只设计未实现"是 D3 设计文档的明确结论（挂钩点、字段、边界均已定，实现估 ≤0.5 天排 W6），属于有意排序，不计偏差。

测试设施两起自查事故（已修，不影响交付物）：聚合验证首跑 sink 继承脚本 stdout 致管道悬挂超时；retention 默认上限 1 万顶掉一半落库行致首轮对账失真（压测配置已显式 `retention_max_records: 0`）。run_tput_10k.sh 补了监控目标文件预创建（inode 注册要求文件先于 monitor 存在，/tmp 清空后曾空跑）。

### 任务 1 / 任务 2 实测

| 项 | 数值 | 判定 |
|---|---|---|
| 聚合外发降幅 | 20,000 条告警（throttle=0/silence=0 隔离变量）→ 外发 24 条（12 开窗首条 + 12 窗末摘要），**降幅 99.88%** | ✓ ≥80% |
| 计数对账 | merged=19,988 + 开窗 12 = 20,000 = 落库条数 = Σoccurrences；sink 实收 24 = sent 计数 24 = 日志发送行 24，**误差 0** | ✓ |
| 落库不受影响 | 落库 20,000 条 = 2 × 10,000 命中事件（FIM+DSL 双规则逐条） | ✓ |
| make unit | 11 个测试程序、90 项断言全绿 | ✓ |
| tput 30s | 300,000/300,000 事件入库，bus.queue_full.hi.* = 0 | ✓ |
| RSS / CPU 常态 5min | RSS 峰值 139.3MB（≤150）/ CPU 均值 0.57%（≤3%，含每 60s asset collect 空转） | ✓ |

> RSS 口径注：139.3MB 为全功能配置（network/dns/privilege 探针全开），W4 的 123.5MB 为三类探针关闭的压测配置，不同口径。同口径 A/B（75s 快照）：全开 137MB / 关三类探针 120MB / 再关落库+引擎+外发 120MB——17MB 增量全部来自 network/dns/privilege 探针及其事件链路；同口径对 W4 无增长。

## 2. v1.0 定义对焦

原计划 W18 出口：**遥测 + FIM + 规则引擎 + CIS 基线 + 15 攻击用例 ≥90% 检出**。

W5 末实际盘点：遥测 ✓、FIM ✓、规则引擎 ✓（DSL v1 + 解析器 + 3 示例规则）、CIS 仅完成 40 项裁剪清单（docs/cis-baseline-v1.md）、**引擎未动工（推后 W6）**、攻击用例 6/15（W3 口径）；**AI 线提前 5 周启动**：GPU/模型文件/AI 进程识别已落库，告警升级设计完成（PRD 把 AI 资产放在 v1.0 MVP 的 M1，docs/prd.md:403，提前并不违口径）。

三个方案供决策（不自行拍板）：

- **方案 A：范围不变、时点不变**。CIS 引擎 W6 动工，距 W18 尚有 12 周；按 W1–W4 周均 2.75 计划项的速率，容量充裕。AI 提前量转为纯缓冲。风险：CIS 引擎属"引擎类"工作，历史上这类工作持续被低估（W3 性能攻坚吃掉 W4 前两天），缓冲可能被侵蚀。
- **方案 B：范围调整、时点不变**。把已交付的 AI 资产发现（GPU/模型文件/AI 进程识别）正式写进 v1.0 出口定义——只是把 prd.md:403 的既成事实落到验收口径；CIS 承诺不动。实质收益：W18 评审时 AI 线有可演示的完整故事（资产→告警升级），而不是半成品。
- **方案 C：时点顺延 1–2 周（W18→W19/20），条件触发**。触发条件写死：W6 末 CIS 引擎未全量可跑、或规则包不足 20 条，即启动顺延。用顺延换 AI 告警升级与规则包做扎实，避免 W18 前突击。

观察（非结论）：A 与 B 可叠加；C 作为条件触发的保险丝成本最低。

## 3. W6 建议排期骨架

| 方向 | 内容 | 验收口径 |
|---|---|---|
| 规则包扩充 | DSL 规则从 3 条示例扩至 **20+ 条**，覆盖 ATT&CK 常见战术（凭据访问、防御规避、横向移动、容器逃逸苗头） | clean 主机 24h 零误报基线（沿用 W4 口径）；规则加载全部通过 RDSL 解析校验 |
| CIS 检查引擎 | docs/cis-baseline-v1.md 40 项接入 check 引擎，规则包版本化，报告含等保 2.0 映射 | 40 项全量可跑，pass/fail/warn 分级输出 |
| AI 告警升级实现 | 按 docs/ai-alert-escalation.md §5 清单：monitor.cpp 告警构建点挂 MaybeBoostSeverityForAi、alerts 表加 severity_origin/ai_boost 两列、单测 + 双场景联调 | 预估 ≤0.5 天；AI 进程读 /etc/shadow 场景 high→critical 端到端可见 |
| 顺带项 | `asset collect` 挂 cron 分钟级（缩短 AI 进程漏标窗口，ai-alert-escalation.md 末尾建议） | 资产标记新鲜度 ≤2 周期可依赖 |
