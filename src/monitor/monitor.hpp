#pragma once
#include "baseline.hpp"
#include "config.hpp"
#include "alert_manager.hpp"

void on_violation_detected(const Rule& rule,
                            const std::string& file_path,
                            const std::string& actual_mode,
                            const std::string& proc_name,
                            int pid,
                            AlertManager& alert_mgr);

// baseline_db_path 为空时走原有纯 YAML 监控；非空时额外开启 SQL 基线实时比对
int do_monitor(const Config& config, AlertManager& alert_mgr,
               const std::string& baseline_db_path = "");
