# M1 资产清点（Asset Inventory）

对应 PRD 第 5、6.1 章（M1-1 ~ M1-7）。

已落地：

- **M1-2 主机资产采集**：`asset_collector.*` 五类采集器（软件包 / 监听端口 / 运行进程 / 自启项 / 定时任务），
  单类失败降级记 warn 不影响其他类；`asset_collect.*` / `asset_list.*` 提供
  `baseline-guard asset collect` 与 `baseline-guard asset list [--type T] [--json]` 子命令。
  存储走 `src/storage/baseline_db.*` 的 `assets` 表（`UNIQUE(asset_type, name)`，
  重复采集仅刷新 `detail_json`/`last_seen`，为资产变更 diff 保留 `first_seen`）。
- **W5 AI 资产采集**：
  - `gpu_collector.*`：统一接口 `IGpuCollector`（`vendor()/collect() → GpuInfo`）；
    NVIDIA 经 `nvidia-smi --query-gpu=... --format=csv,noheader` 解析实现（不链 NVML），
    昇腾 `AscendCollector` / 海光 `DcuCollector` 为未适配 stub；无 GPU 或无 `nvidia-smi`
    时 gpu 段为空数组、不影响其他采集。字段映射对照见 `docs/gpu-collector-mapping.md`。
  - `model_file_collector.*`：扫描 `asset.model_scan_dirs`（默认
    `~/.cache/huggingface`、`/data`、`/models`，`asset collect -c config.yaml` 指定），
    匹配 `.pt/.safetensors/.gguf/.onnx/.ckpt`，记录路径/大小/mtime；目录不存在跳过、
    递归深度 ≤4 层、不跟随符号链接。

预留（后续版本）：主机指纹、容器/K8s 资产、昇腾/海光 GPU 采集实现、账号资产、脆弱性初筛。
