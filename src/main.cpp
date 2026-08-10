#include "baseline.hpp"
#include "check.hpp"
#include "config.hpp"
#include "monitor.hpp"
#include "utils.hpp"
#include "commonfun.hpp"
#include "logger.h"
#include "baseline_db.hpp"
#include "alert_manager.hpp"

#include "spdlog/spdlog.h"
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

// 长选项定义
static struct option long_options[] = { {"config", required_argument, 0, 'c'},
                                        {"help", no_argument, 0, 'h'},
                                        {"check", no_argument, 0, 'C'},
                                        {"monitor", no_argument, 0, 'm'},
                                        {0, 0, 0, 0} };

static volatile bool g_reload = false;

void sighup_handler(int) {
    g_reload = true;
}

int main(int argc, char* argv[]) {
    // 设置全局日志级别（默认是 info，低于它的 debug/trace 不会输出）
    spdlog::set_level(spdlog::level::debug);

// 1. 初始化日志
    Logger::init("/var/log/baseline-guard");

    spdlog::info("[service_start] baseline-guard starting, pid={}", getpid());

    // 2. 初始化数据库
    BaselineDB db;

    std::string config_path;
    std::string cmd;

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "c:hCm", long_options, &option_index)) != -1) {
        switch (opt) {
        case 'c':
            config_path = optarg;
            spdlog::debug("config file is : {}", config_path);
            break;

        case 'h':
            printf("Usage: %s [options] [command]\n", argv[0]);
            printf("Options:\n");
            printf("  -c, --config <path>   config file path\n");
            printf("  -h, --help            display this message\n");
            printf("Commands:\n");
            printf("  --check               check baseline\n");
            printf("  --monitor             monitor baseline\n");
            return 0;

        case 'C': // --check
            cmd = "check";
            spdlog::debug("command is : check");
            break;

        case 'm': // --monitor
            cmd = "monitor";
            spdlog::debug("command is : monitor");
            break;

        default:
            return 1;
        }
    }

    // 如果没有指定命令，检查是否有非选项参数
    if (cmd.empty() && optind < argc) {
        cmd = argv[optind];
    }

    // 验证
    if (config_path.empty()) {
        fprintf(stderr, "Error: config file required (-c <path>)\n");
        return 1;
    }

    if (cmd.empty()) {
        fprintf(stderr, "Error: command required (check or monitor)\n");
        return 1;
    }

    Config config;
    if (!ends_with(config_path, ".yaml") && !ends_with(config_path, ".yml")) {
        spdlog::error("[config_error] only yaml/yml config is supported now: {}", config_path);
        return 1;
    }

    config = parseYamlFile(config_path);

    spdlog::info("[rules_loaded] config={}, format=yaml, rules={}",
                 config_path,
                 config.rules.size());

    // 打印结果
    printRules(config.rules);

    AlertManager alert_mgr;
    alert_mgr.LoadConfig(config.alert, config.db);  // alert + db 分开配置
    alert_mgr.SetDB(&db);  // 绑定数据库，所有告警统一落库

    if (alert_mgr.IsEnabled()) {
        spdlog::info("DingTalk alert enabled, throttle={}s", config.alert.throttle_seconds);
    } else {
        spdlog::warn("DingTalk alert NOT configured (alerts will still be persisted to DB)");
    }
    spdlog::info("Alert retention: {} days, max {} records",
                 config.db.retention_days, config.db.retention_max_records);

    compute_inodes(config);

    if (cmd == "check") {
        spdlog::info("[service_start] check mode started");
        int ret = do_check(config, db);
        spdlog::info("[service_stop] check mode finished, exit_code={}", ret);
        return ret;
    } else if (cmd == "monitor") {
        // 注册 SIGHUP 用于配置重载
        signal(SIGHUP, sighup_handler);
        spdlog::info("[service_start] monitor mode started");

        int ret = 0;
        while (true) {
            ret = do_monitor(config, alert_mgr);
            if (!g_reload) {
                break;
            }
            g_reload = false;
            spdlog::info("[rules_reload] SIGHUP received, reloading config from {}", config_path);

            config = parseYamlFile(config_path);
            compute_inodes(config);

            spdlog::info("[rules_reload] config reloaded, rules={}", config.rules.size());
        }

        spdlog::info("[service_stop] monitor mode stopped, exit_code={}", ret);
        return ret;
    } else {
        spdlog::error("未知命令: {}", cmd);
        return 1;
    }
}