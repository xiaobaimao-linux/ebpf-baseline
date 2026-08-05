#include "check.hpp"
#include "utils.hpp"
#include <sys/stat.h>
#include <spdlog/spdlog.h>
#include <algorithm>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip> 

int do_check(const Config& config, BaselineDB& db) {
    int fail_count = 0;
    int pass_count = 0;

    for (const auto& rule : config.rules) {
        if (!rule.has_check) {
            continue;
        }

        const std::string target_path = rule.check_path;
        struct stat st;
        bool rule_failed = false;
        std::string actual_hash;

        if (stat(target_path.c_str(), &st) < 0) {
            log_fail(rule.name, target_path + " 文件不存在");
            fail_count++;
            continue;
        }

        mode_t actual_mode = st.st_mode & 0777;
        const bool has_permission_check = std::find(rule.check_types.begin(), rule.check_types.end(), "file_permission") != rule.check_types.end();
        const bool has_hash_check = std::find(rule.check_types.begin(), rule.check_types.end(), "file_hash") != rule.check_types.end();

        if (has_permission_check) {
            if (actual_mode == rule.check_mode) {
                log_pass(rule.name, target_path + " mode " + mode_to_string(actual_mode));
            } else {
                log_fail(rule.name, target_path + " mode " + mode_to_string(actual_mode) +
                         ", mode " + mode_to_string(rule.check_mode));
                rule_failed = true;
            }
        }

        if (has_hash_check) {
            actual_hash = compute_sha256(const_cast<string&>(target_path));
            if (actual_hash == rule.check_hash) {
                log_pass(rule.name, "hash匹配");
            } else {
                log_fail(rule.name, "hash不匹配");
                rule_failed = true;
            }
        }

        BaselineRecord record;
        record.file_path = target_path;
        record.permission = mode_to_string(actual_mode);
        record.hash = actual_hash.empty() ? compute_sha256(const_cast<string&>(target_path)) : actual_hash;
        record.owner = std::to_string(st.st_uid);
        record.group = std::to_string(st.st_gid);

        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t_now), "%Y-%m-%dT%H:%M:%S");
        record.recorded_at = ss.str();

        db.SaveBaseline(record);
        spdlog::info("[baseline_created] path={}, permission={}, hash={}, recorded_at={}",
                     record.file_path, record.permission,
                     record.hash.empty() ? "(none)" : record.hash,
                     record.recorded_at);

        if (rule_failed) {
            fail_count++;
        } else {
            pass_count++;
        }
    }

    spdlog::info("检查完成: {} 通过, {} 失败", pass_count, fail_count);
    return fail_count > 0 ? 1 : 0;
}