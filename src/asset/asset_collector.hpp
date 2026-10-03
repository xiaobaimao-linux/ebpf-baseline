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
