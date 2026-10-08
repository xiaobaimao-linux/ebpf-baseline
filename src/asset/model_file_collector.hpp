// W5 AI 资产：模型文件发现。
//
// 扫描可配置目录（asset.model_scan_dirs），匹配常见模型扩展名，
// 记录路径/大小/mtime。防护：目录不存在跳过、递归深度 ≤4 层、不跟随符号链接。
#pragma once

#include <string>
#include <vector>

#include "asset_collector.hpp"

// 默认扫描目录（~ 展开为 HOME）：~/.cache/huggingface、/data、/models
std::vector<std::string> DefaultModelScanDirs();

// 扫描 dirs 下的模型文件（.pt/.safetensors/.gguf/.onnx/.ckpt，大小写不敏感），
// 单目录内递归深度 ≤4 层（目录本身为第 1 层），符号链接不跟随，
// 目录不存在/权限不足记 debug 跳过，不抛异常。
std::vector<AssetItem> CollectModelFiles(const std::vector<std::string>& dirs);
