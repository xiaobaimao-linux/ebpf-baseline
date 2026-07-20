#include "check.hpp"
#include "config.hpp"
#include "utils.hpp"
#include "spdlog/spdlog.h"



int main(int argc, char **argv) {

    // 设置全局日志级别（默认是 info，低于它的 debug/trace 不会输出）
    spdlog::set_level(spdlog::level::debug);

    // 不同级别日志
    spdlog::trace("trace 信息");
    spdlog::debug("调试信息: x={}", 42);
    spdlog::info("欢迎使用 spdlog!");
    spdlog::warn("警告信息");
    spdlog::error("错误信息: {}", "文件不存在");
    spdlog::critical("致命错误!");

    const char *config_path = NULL;
    int opt;
    
    while ((opt = getopt(argc, argv, "c:h")) != -1) {
        switch (opt) {
        case 'c':
            config_path = optarg;
            spdlog::debug("config file is : {}", config_path);
            break;
        case 'h':
            printf("Use tool like below:\n");
            printf("-c  config file path\n");
            printf("-h display this message\n");
            continue;
        default:
            // usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }
    
    if (!config_path) {
        // usage(argv[0]);
        return 1;
    }
    
    // 加载配置，执行check或monitor
}