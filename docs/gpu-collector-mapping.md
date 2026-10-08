# GPU 采集器字段映射（gpu-collector-mapping）

W5 统一接口 `IGpuCollector::collect() → GpuInfo{vendor, model, driver, mem_total_mb, mem_used_mb, util_pct}`
（见 `src/asset/gpu_collector.hpp`）。本文档给出三家厂商命令行工具公开输出字段到统一字段的对照。

> ⚠️ 昇腾、海光两行**未经真机验证**，仅依据公开官方文档整理；实现 AscendCollector /
> DcuCollector 前需在真实环境核对输出格式与单位。

## NVIDIA（已实现）

命令：

```bash
nvidia-smi --query-gpu=name,driver_version,memory.total,memory.used,utilization.gpu --format=csv,noheader
```

| 统一字段 | nvidia-smi 查询字段 | 说明 |
|---|---|---|
| model | name | 芯片型号 |
| driver | driver_version | 驱动版本 |
| mem_total_mb | memory.total | MiB → MB（同单位，直接取值） |
| mem_used_mb | memory.used | 同上 |
| util_pct | utilization.gpu | 整数百分比；`[N/A]` 解析为 -1 |

## 昇腾 Ascend（stub，未适配）

命令：`npu-smi info`（表格式输出，每设备一行芯片信息；驱动版本在表头 `Version` 行）。

| 统一字段 | npu-smi 输出字段 | 说明 |
|---|---|---|
| model | Name | 芯片名称（如 910B3 / 910B4） |
| driver | Version（表头 `npu-smi Version: x.y.z`） | 工具/驱动版本，需从表头行解析 |
| mem_total_mb | —（`npu-smi info` 默认输出无总量列） | 需配合 `npu-smi info -t memory -i <id>` 或按型号规格补齐 |
| mem_used_mb | Memory-Usage(MB) / HBM-Usage(MB) | DDR 内存 / 片上 HBM 占用（MB）；建议取 HBM-Usage |
| util_pct | AICore(%) | AI Core 占用率 |

参考：昇腾社区《npu-smi 命令参考》输出说明表（NPU/Name/Health/Power(W)/Temp(C)/Hugepages-Usage(page)/Chip/Device/Bus-Id/AICore(%)/Memory-Usage(MB)/HBM-Usage(MB)）。

## 海光 DCU（stub，未适配）

命令：`hy-smi`（rocm-smi 风格表格输出）。

| 统一字段 | hy-smi 输出字段 | 说明 |
|---|---|---|
| model | Card series / 设备名 | 卡型号（如 K100_AI） |
| driver | —（hy-smi 主表无驱动版本列） | 需从 `hy-smi --showdriverversion` 或 dkms 信息补齐（未验证） |
| mem_total_mb | — | `hy-smi --showmeminfo vram` 输出 Total Memory，注意单位（字节，需换算 MB） |
| mem_used_mb | VRAM 相关（`--showmemuse` / `--showmeminfo vram` 的 Used Memory） | 字节 → MB |
| util_pct | DCU%（`hy-smi -u`） | 计算核心利用率百分比；主表 VRAM% 为显存利用率，不要混淆 |

参考：海光 DCU 技术资料中 `hy-smi` 各字段（DCU/Temp/AvgPwr/Fan/Perf/PwrCap/VRAM%/DCU%）及 `--showmeminfo vram` / `--showmemuse` / `-u` 子命令说明。

## 解析注意事项

- 三家输出均为"给人看"的表格，列对齐宽度随字段长度变化，实现时应按表头定位列或用
  `--format=csv` 类选项（仅 nvidia-smi 确认支持）。
- 单位不统一：nvidia-smi 用 MiB、npu-smi 用 MB、hy-smi 显存信息为字节，入 `GpuInfo`
  前统一换算为 MB。
- 不可用值（`[N/A]`、`N/A`、空列）统一解析为 -1，不丢卡。
