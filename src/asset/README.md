# M1 资产清点（Asset Inventory）

对应 PRD 第 5、6.1 章（M1-1 ~ M1-7）。

已落地：

- **M1-2 主机资产采集**：`asset_collector.*` 五类采集器（软件包 / 监听端口 / 运行进程 / 自启项 / 定时任务），
  单类失败降级记 warn 不影响其他类；`asset_collect.*` / `asset_list.*` 提供
  `baseline-guard asset collect` 与 `baseline-guard asset list [--type T] [--json]` 子命令。
  存储走 `src/storage/baseline_db.*` 的 `assets` 表（`UNIQUE(asset_type, name)`，
  重复采集仅刷新 `detail_json`/`last_seen`，为资产变更 diff 保留 `first_seen`）。

预留（后续版本）：主机指纹、容器/K8s 资产、AI 资产（GPU/框架/模型文件）、账号资产、脆弱性初筛。
