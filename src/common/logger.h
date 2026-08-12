#pragma once
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <memory>
#include <string>

class Logger {
public:
    static void init(const std::string& log_dir = "/var/log/baseline-guard") {
        // 创建日志目录
        std::string cmd = "mkdir -p " + log_dir;
        system(cmd.c_str());

        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            log_dir + "/baseline-guard.log",
            1024 * 1024 * 100,  // 100MB
            30,                  // 30个备份
            true                 // 自动创建目录
        );

        std::vector<spdlog::sink_ptr> sinks{console_sink, file_sink};
        auto logger = std::make_shared<spdlog::logger>(
            "baseline-guard", sinks.begin(), sinks.end()
        );

        logger->set_level(spdlog::level::info);
        logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
        spdlog::set_default_logger(logger);
    }
};