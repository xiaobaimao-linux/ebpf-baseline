#include "monitor_baseline.hpp"
#include "commonfun.hpp"
#include "utils.hpp"

#include <spdlog/spdlog.h>
#include <sys/stat.h>

#include <stdexcept>

// ── 比对逻辑（与 baseline_check.cpp::CheckOneEntry 严格一致）──────────────

std::vector<BaselineDeviation> CompareWithBaseline(const CheckEntry& baseline,
                                                    const std::string& file_path) {
    std::vector<BaselineDeviation> findings;

    // 1. 检测文件是否存在（lstat 不跟随 symlink）
    struct stat st = {};
    if (lstat(file_path.c_str(), &st) != 0) {
        BaselineDeviation dev;
        dev.event_type = "missing";
        dev.severity   = "high";
        dev.expected   = "file exists";
        dev.actual     = "file missing";
        findings.push_back(std::move(dev));
        return findings;
    }

    // 2. 计算 sha256
    std::string actual_hash;
    try {
        actual_hash = compute_sha256(file_path);
    } catch (const std::exception& ex) {
        BaselineDeviation dev;
        dev.event_type = "access_failed";
        dev.severity   = "medium";
        dev.expected   = "hash computable";
        dev.actual     = std::string("error: ") + ex.what();
        findings.push_back(std::move(dev));
        return findings;
    }

    // 3. 比对 hash
    if (actual_hash != baseline.hash) {
        BaselineDeviation dev;
        dev.event_type = "hash_changed";
        dev.severity   = "high";
        dev.expected   = "sha256:" + baseline.hash.substr(0, 16) + "...";
        dev.actual     = "sha256:" + actual_hash.substr(0, 16) + "...";
        findings.push_back(std::move(dev));
    }

    // 4. 无论 hash 是否变化，都比对 permission / uid / gid
    std::string actual_perm = mode_to_string(st.st_mode & 0777);
    bool perm_diff = (actual_perm != baseline.permission);
    bool uid_diff  = (static_cast<int64_t>(st.st_uid) != baseline.uid);
    bool gid_diff  = (static_cast<int64_t>(st.st_gid) != baseline.gid);

    if (perm_diff || uid_diff || gid_diff) {
        BaselineDeviation dev;
        dev.event_type = "perm_changed";
        dev.severity   = "medium";
        std::string exp_parts, act_parts;
        if (perm_diff) {
            exp_parts += "mode=" + baseline.permission;
            act_parts += "mode=" + actual_perm;
        }
        if (uid_diff) {
            if (!exp_parts.empty()) exp_parts += ", ";
            exp_parts += "uid=" + std::to_string(baseline.uid);
            if (!act_parts.empty()) act_parts += ", ";
            act_parts += "uid=" + std::to_string(st.st_uid);
        }
        if (gid_diff) {
            if (!exp_parts.empty()) exp_parts += ", ";
            exp_parts += "gid=" + std::to_string(baseline.gid);
            if (!act_parts.empty()) act_parts += ", ";
            act_parts += "gid=" + std::to_string(st.st_gid);
        }
        dev.expected = exp_parts;
        dev.actual   = act_parts;
        findings.push_back(std::move(dev));
    }

    // 全部一致 → findings 为空
    return findings;
}

// ── 告警处理 ──────────────────────────────────────────────────────────────

void HandleBaselineDeviation(const BaselineDeviation& dev,
                              const std::string& file_path,
                              const std::string& proc_name,
                              int pid,
                              AlertManager& alert_mgr) {
    // 1. 打印日志
    spdlog::warn("[基线监控告警] event_type={} file={} expected={} actual={} proc={} pid={}",
                 dev.event_type, file_path, dev.expected, dev.actual, proc_name, pid);

    // 2. 构造 AlertEvent 并通过 AlertManager 统一落库 + 钉钉推送
    AlertEvent evt;
    evt.rule_id      = kBaselineRuleId;
    evt.rule_name    = kBaselineRuleName;
    evt.severity     = dev.severity;
    evt.file_path    = file_path;
    evt.expected     = dev.expected;
    evt.actual       = dev.actual;
    evt.event_type   = dev.event_type;
    evt.process_name = proc_name;
    evt.pid          = pid;
    evt.action_taken = "alert";
    evt.timestamp    = NowString();

    alert_mgr.SendDingTalk(evt);
}
