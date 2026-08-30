#include "check.hpp"
#include "utils.hpp"
#include "report_generator.hpp"
#include "commonfun.hpp"

#include <sys/stat.h>
#include <spdlog/spdlog.h>
#include <algorithm>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip> 
#include <fstream>
#include <cstdlib>

// 读取 /proc/sys 下的内核参数值
static bool read_kernel_param(const std::string& param, long long& out_value) {
    std::string path = "/proc/sys/" + param;
    // 将点号替换为斜杠，如 kernel.randomize_va_space -> kernel/randomize_va_space
    for (auto& c : path) {
        if (c == '.') c = '/';
    }

    std::ifstream fs(path);
    if (!fs.is_open()) {
        return false;
    }
    fs >> out_value;
    return !fs.fail();
}

// 比较实际值和期望值
static bool compare_value(long long actual, long long expected, const std::string& op) {
    if (op == "=")  return actual == expected;
    if (op == "!=") return actual != expected;
    if (op == ">=") return actual >= expected;
    if (op == "<=") return actual <= expected;
    if (op == ">")  return actual > expected;
    if (op == "<")  return actual < expected;
    // 默认使用等于
    return actual == expected;
}

static void do_file_check(const Rule& rule, BaselineDB& db, std::vector<CheckResult>& results, int& pass_count, int& fail_count) {
    const std::string target_path = rule.check_path;
    struct stat st;
    bool rule_failed = false;
    std::string actual_hash;

    if (stat(target_path.c_str(), &st) < 0) {
        log_fail(rule.name, target_path + " 文件不存在");
        fail_count++;
        return;
    }

    mode_t actual_mode = st.st_mode & 0777;
    const bool has_permission_check = std::find(rule.check_types.begin(), rule.check_types.end(), "file_permission") != rule.check_types.end();
    const bool has_hash_check = std::find(rule.check_types.begin(), rule.check_types.end(), "file_hash") != rule.check_types.end();

    if (has_permission_check) {
        if (actual_mode == rule.check_expected) {
            log_pass(rule.name, target_path + " mode " + mode_to_string(actual_mode));
        } else {
            log_fail(rule.name, target_path + " mode " + mode_to_string(actual_mode) +
                     ", 期望 mode " + mode_to_string(rule.check_expected));
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

    // 保存结果到sqlite
    BaselineRecord record;
    record.file_path = target_path;
    record.permission = mode_to_string(actual_mode);
    record.hash = actual_hash.empty() ? compute_sha256(const_cast<string&>(target_path)) : actual_hash;
    record.owner = std::to_string(st.st_uid);
    record.grp = std::to_string(st.st_gid);

    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t_now), "%Y-%m-%dT%H:%M:%S");
    record.recorded_at = ss.str();

        db.SaveBaseline(record);

        // 生成HTML结果记录
    CheckResult r;
    r.rule_id = rule.id;
    r.rule_name = rule.name;
    r.file_path = rule.check_path;
    r.expected = mode_to_string(rule.check_expected);
    r.actual = mode_to_string(actual_mode);
    r.passed = !rule_failed;
    r.severity = severityToString(rule.severity);
    results.push_back(r);

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

static void do_kernel_param_check(const Rule& rule, BaselineDB& db, std::vector<CheckResult>& results, int& pass_count, int& fail_count) {
    long long actual_value = 0;
    bool rule_failed = false;

    if (!read_kernel_param(rule.check_param, actual_value)) {
        log_fail(rule.name, "无法读取内核参数: " + rule.check_param);
        fail_count++;
        return;
    }

    bool passed = compare_value(actual_value, rule.check_expected_value, rule.check_operator);
    std::string expected_str = std::to_string(rule.check_expected_value);
    std::string actual_str = std::to_string(actual_value);

    if (passed) {
        log_pass(rule.name, rule.check_param + " = " + actual_str + " (期望 " + rule.check_operator + " " + expected_str + ")");
    } else {
        log_fail(rule.name, rule.check_param + " = " + actual_str + ", 期望 " + rule.check_operator + " " + expected_str);
        rule_failed = true;
    }

    // 保存结果到sqlite
    BaselineRecord record;
    record.file_path = "[kernel_param] " + rule.check_param;
    record.permission = "-";
    record.hash = actual_str;
    record.owner = "-";
    record.grp = "-";

    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t_now), "%Y-%m-%dT%H:%M:%S");
    record.recorded_at = ss.str();

    db.SaveBaseline(record);

    // 生成HTML结果记录
    CheckResult r;
    r.rule_id = rule.id;
    r.rule_name = rule.name;
    r.file_path = record.file_path;
    r.expected = rule.check_operator + " " + expected_str;
    r.actual = actual_str;
    r.passed = !rule_failed;
    r.severity = severityToString(rule.severity);
    results.push_back(r);

    spdlog::info("[kernel_param_check] param={}, actual={}, expected_op={}, expected_val={}, passed={}",
                 rule.check_param, actual_str, rule.check_operator, expected_str, passed);

    if (rule_failed) {
        fail_count++;
    } else {
        pass_count++;
    }
}

int do_check(const Config& config, BaselineDB& db) {
    int fail_count = 0;
    int pass_count = 0;
    std::vector<CheckResult> results;

    for (const auto& rule : config.rules) {
        if (!rule.has_check) {
            continue;
        }

        const bool has_kernel_param = std::find(rule.check_types.begin(), rule.check_types.end(), "kernel_param") != rule.check_types.end();

        if (has_kernel_param) {
            do_kernel_param_check(rule, db, results, pass_count, fail_count);
        } else {
            do_file_check(rule, db, results, pass_count, fail_count);
        }
    }
    
    spdlog::info("检查完成: {} 通过, {} 失败", pass_count, fail_count);

     // 生成报告
    std::string report_path = "/var/log/baseline-guard/report-" + NowString() + ".html";
    ReportGenerator gen;
    if (gen.GenerateCheckHtml(results, report_path)) {
        spdlog::info("Report generated: {}", report_path);
    }

    return fail_count > 0 ? 1 : 0;
}