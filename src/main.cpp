#include "baseline.hpp"
#include "check.hpp"
#include "config.hpp"
#include "monitor.hpp"
#include "utils.hpp"

#include "spdlog/spdlog.h"
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>

// 长选项定义
static struct option long_options[] = {{"config", required_argument, 0, 'c'},
                                       {"help", no_argument, 0, 'h'},
                                       {"check", no_argument, 0, 'C'},   // 返回 'C'
                                       {"monitor", no_argument, 0, 'm'}, // 返回 'm'
                                       {0, 0, 0, 0}};



// 辅助函数：判断字符串是否以指定后缀结尾
static bool ends_with(const string& str, const string& suffix) {
    if (suffix.size() > str.size()) return false;
    return equal(suffix.rbegin(), suffix.rend(), str.rbegin());
}


int main(int argc, char *argv[]) {

    // 设置全局日志级别（默认是 info，低于它的 debug/trace 不会输出）
    spdlog::set_level(spdlog::level::debug);

    // // 不同级别日志
    // spdlog::trace("trace 信息");
    // spdlog::debug("调试信息: x={}", 42);
    // spdlog::info("欢迎使用 spdlog!");
    // spdlog::warn("警告信息");
    // spdlog::error("错误信息: {}", "文件不存在");
    // spdlog::critical("致命错误!");

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

    vector<Rule> rules;
    if (ends_with(config_path, ".yaml") || ends_with(config_path, ".yml")) {
        rules = parseYamlFile(config_path);
    } else {
        rules = parseIniFile(config_path);
    }

    // 打印结果
    printRules(rules);

    Config config;
    config.rules = rules;

    compute_inodes(config);

    if (cmd == "check") {
        return do_check(config);
    } else if (cmd == "monitor") {
        return do_monitor(config);
    } else {
        spdlog::error("未知命令: {}", cmd);
        return 1;
    }

    // 加载配置，执行check或monitor
}