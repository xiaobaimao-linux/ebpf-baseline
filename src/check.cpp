#include "check.hpp"
#include "utils.hpp"
#include <sys/stat.h>
#include <spdlog/spdlog.h>

int do_check(const Config& config) {
    int fail_count = 0;
    
    for (const auto& rule : config.rules) {
        struct stat st;
        
        // 1. 检查文件是否存在
        if (stat(rule.path.c_str(), &st) < 0) {
            log_fail(rule.name, rule.path + " 文件不存在");
            fail_count++;
            continue;
        }
        
        // 2. 检查权限
        mode_t actual_mode = st.st_mode & 0777;
        if (actual_mode == rule.mode) {
            log_pass(rule.name, rule.path + " mode " + mode_to_string(actual_mode));
        } else {
            log_fail(rule.name, rule.path + " mode " + mode_to_string(actual_mode) + 
                     ", expected " + mode_to_string(rule.mode));
            fail_count++;
        }
        
        // 3. 检查hash（如果有）
        if (rule.has_hash) {
            string actual_hash = compute_sha256(const_cast<string&>(rule.path));
            if (actual_hash == rule.hash) {
                log_pass(rule.name, "hash匹配");
            } else {
                log_fail(rule.name, "hash不匹配");
                fail_count++;
            }
        }
    }
    
    spdlog::info("检查完成: {} 通过, {} 失败", 
                 config.rules.size() - fail_count, fail_count);
    return fail_count > 0 ? 1 : 0;
}