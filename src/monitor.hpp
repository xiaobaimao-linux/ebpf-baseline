#pragma once
#include "baseline.hpp"
#include "config.hpp"
#include "alert_manager.hpp"
#include "baseline_db.hpp"

void on_violation_detected(const Rule& rule,
                            const std::string& file_path,
                            const std::string& actual_mode,
                            const std::string& proc_name,
                            int pid,
                            AlertManager& alert_mgr,
                            BaselineDB& db);

int do_monitor(const Config& config, AlertManager &alert_mgr, BaselineDB& db);
