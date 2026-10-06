# 告警风暴专项（W4 D5 任务5）

> 日期：2026-10-06。口径：DSL 规则 `Storm Any File Read`（rules/storm/）故意高频命中，
> 5,000 次 `cat /tmp/bg-storm/storm_target.txt`（50 次/3s × 100 轮 = 1,000 命中/分钟 × 5 分钟）。
> 冷却窗口 throttle=60s（tests/perf/config_storm.yaml）。原始数据：/tmp/bg-perf/results/storm_*.txt。

## 1. 对账数据

口径说明：每次 `cat` 产生 2 个 file.read 事件（open + read 系统调用各触发一次 LSM file_permission），5,000 次 cat → 10,000 条命中事件；告警落 /var/lib/baseline-guard/baseline.db（AlertManager 默认路径，--db 不影响告警库）。

| 项 | 数值 |
|---|---|
| 命中事件（events 表实测） | 10,000 |
| 实际发送（alerts 表，rule_id=dsl.storm_any_file_read） | 6（≈350s / 60s 冷却窗） |
| 已抑制（monitor 日志 `[alerts] throttled: rule=... count=`） | 9,994 |
| 对账 | 6 + 9,994 = 10,000，**误差 0.000%（<1% PASS）** |
| 冷却生效证据 | 6 条告警落库时间戳精确间隔 ~60s（20:02:31 → 20:07:38，原始数据 /home/sf/bg-perf/results/storm_alerts.txt） |
| 风暴期间系统表现 | 100 条/秒的规则求值 + 抑制计数无额外丢失；抑制计数挂 60s tick 输出，无每事件日志放大 |

熔断（单位时间阈值）：本场景未触发（机制不存在，见差距清单 #2）。冷却窗口内首条发送、后续静默丢弃 + 计数，是本次验证的唯一防线；5 分钟风暴共产出 6 条告警（vs 无冷却时 10,000 条），降噪比 1,667:1。

## 2. 冷却/熔断机制现状（代码口径）

| 机制 | 状态 | 位置 |
|---|---|---|
| 冷却（per-rule 时间窗节流） | ✓ 已存在 | AlertManager::IsThrottled，key=rule_id，窗口 throttle_seconds（默认 300s，压测 60s）；窗口首条发钉钉+落库，窗口内后续跳过 |
| "已抑制 N 条"统计 | ✓ 本周补齐 | 预检路径（ThrottledNow）与 SendDingTalk 内部路径统一 NoteThrottled 入口，每条抑制恰好计一次；60s tick 打 `[alerts] throttled: total=N` |
| 熔断（单位时间阈值） | ✗ 不存在 | — |
| 同源聚合（进程+规则+目标去重） | ✗ 不存在 | — |

## 3. 对照 PRD M5-3 的差距清单

M5-3 原文："沿用并扩展现有冷却机制：同源告警聚合（按进程+规则+目标去重）、告警风暴抑制（单位时间阈值熔断）、统计'已抑制 N 条' | P0"。

| # | 差距 | 说明 | W5 工作量粗估 |
|---|---|---|---|
| 1 | 同源告警聚合 | 现冷却是时间窗丢弃，窗口内同源 N 条只留首条且无 count。聚合要求：窗口内按 (rule_id, exe, container_id, 目标路径) 合并，窗末产出一条带 count 的聚合告警（落库 + 钉钉模板加 count 行）。改动：AlertManager 加聚合窗 map、alerts 表加 count 列、聚合窗 flush 挂消费线程 tick | 2-3 天（含单测 + 风暴场景复测） |
| 2 | 单位时间阈值熔断 | 现无限流上限：N 条不同 rule_id 或冷却窗密集翻窗仍可刷屏。要求：per-rule 滑动窗计数超阈值进入熔断期（整窗静默），熔断开始/结束各落一条元事件。改动：AlertManager 加滑动窗计数器与熔断状态机 | 1-2 天 |
| 3 | 抑制统计持久化与查询 | 当前计数驻留内存、60s 打日志，重启清零；CLI `stats` 未暴露。要求：计数入 pinned map 或 stats 子命令展示 per-rule 抑制数 | 0.5-1 天 |
| 4 | 分级路由联动 | critical 不应被熔断/聚合埋没（M5-3 未直接要求，但与 W5"告警分级多渠道"强耦合：critical 多渠道直达、low 仅落库参与聚合）。依赖 #1/#2 落地后统一设计 | 含在 W5 多渠道任务内（1-2 天） |

已满足项：冷却机制沿用 ✓、"已抑制 N 条"统计 ✓（本次对账误差 <1% 验收）。
