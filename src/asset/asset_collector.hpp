// M1-2 主机资产清点：五类资产采集器（package / port / process / autostart / cron）
//
// 每个采集器独立函数，只读 /proc、/etc、dpkg 数据库等系统数据源；
// 调用方（asset collect）对单类失败 catch 降级记 warn，不影响其他四类。
#pragma once

#include <string>
#include <vector>

struct AssetItem {
    std::string asset_type;   // package / port / process / autostart / cron
    std::string name;         // 稳定键：包名 / proto://addr:port / comm(pid) / unit名 / 文件::条目
    std::string detail_json;  // 类型相关扩展字段（nlohmann 序列化）
};

// 软件包：dpkg 系解析 /var/lib/dpkg/status（dpkg-query 兜底），rpm 系探测 rpmdb，缺失记 debug
std::vector<AssetItem> CollectPackages();

// 监听端口：解析 /proc/net/tcp{,6}、udp{,6}，经 /proc/*/fd 反查进程归属（失败填空串）
std::vector<AssetItem> CollectPorts();

// 运行进程：扫 /proc/<pid>/，采集 pid/ppid/comm/exe/cmdline/uid/启动时间（瞬时值）
std::vector<AssetItem> CollectProcesses();

// 自启项：systemd enabled unit（非 systemd 主机降级）+ /etc/rc.local + /etc/init.d
std::vector<AssetItem> CollectAutostart();

// 定时任务：/etc/crontab、/etc/cron.d/*、/var/spool/cron/crontabs/*、/var/spool/cron/*
std::vector<AssetItem> CollectCron();

// W5 AI 工作负载进程识别（纯函数，不读 /proc，供单测直接喂字符串）。
// 命中任一特征即视为 AI 工作负载，返回命中的信号名列表（空 = 非 AI）：
//   cmdline 含 torch/tensorflow 关键路径（site-packages/ 或 dist-packages/ 下）
//   environ（NUL 分隔原始内容）按变量边界含 CUDA_VISIBLE_DEVICES
//   maps 加载了 /libcuda.so 或 /libnvidia-ml.so（含 .so.<ver> 后缀）
// 普通 "python script.py" 不命中任何特征，不会误判。
std::vector<std::string> AiWorkloadSignals(const std::string& cmdline,
                                           const std::string& environ,
                                           const std::string& maps);
bool IsAiWorkload(const std::string& cmdline, const std::string& environ,
                  const std::string& maps);
