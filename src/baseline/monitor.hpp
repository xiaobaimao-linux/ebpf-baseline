#pragma once
#include "baseline.hpp"
#include "config.hpp"
#include "alert_manager.hpp"

void on_violation_detected(const Rule& rule,
                            const std::string& file_path,
                            const std::string& actual_mode,
                            const std::string& proc_name,
                            int pid,
                            AlertManager& alert_mgr,
                            const FileActorContext* actor = nullptr);

// baseline_db_path 为空时走原有纯 YAML 监控；非空时额外开启 SQL 基线实时比对
// skip_boot_check 为 true 时跳过开机全基线核查，直接进入 eBPF 事件监控循环
// config_path 非空时启用 SIGHUP 热加载：主循环每轮检查标志，成功原子替换
// 规则表与白名单快照并清缓存，失败保留旧配置（monitor 进程不重启）
int do_monitor(const Config& config, AlertManager& alert_mgr,
               const std::string& config_path = "",
               const std::string& baseline_db_path = "",
               bool skip_boot_check = false);
