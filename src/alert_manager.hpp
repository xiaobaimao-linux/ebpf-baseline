#pragma once
#include <string>
#include <unordered_map>
#include <chrono>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include "baseline_db.hpp"
#include "config.hpp"

using json = nlohmann::json;

struct AlertEvent {
    std::string rule_id;
    std::string rule_name;
    std::string severity;
    std::string file_path;
    std::string expected;   // 预期值（如 0644）
    std::string actual;     // 实际值（如 0777）
    std::string process_name;
    int pid = 0;
    std::string timestamp;
    std::string event_type;     // 事件类型: read / write / check_fail
    std::string action_taken;   // alert / block / report_only
};

class AlertManager {
public:
    AlertManager();
    ~AlertManager();

    // 加载配置：alert + db
    void LoadConfig(const AlertConfig& alert_cfg, const DbConfig& db_cfg);
    bool IsEnabled() const;

    // 绑定数据库（告警统一落库）
    void SetDB(BaselineDB* db);

    // 发送钉钉告警（内部自动落库到 alerts 表）
    // 返回值: 钉钉是否实际发送成功（被节流返回 false，但仍会落库）
    bool SendDingTalk(const AlertEvent& event);
    
    // 执行保留策略清理（可由外部定期调用，如每1小时一次）
    // 返回删除的记录数
    int RunRetention();

private:
    std::string dingtalk_url_;
    std::string dingtalk_secret_;
    int throttle_seconds_ = 300;
    int retention_days_ = 30;          // 0=永久保留
    int retention_max_records_ = 10000; // 0=不限制
    BaselineDB* db_ = nullptr;

    // 记录每条规则最近一次告警时间: rule_id -> 上次告警时间点
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_alert_time_;

    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);
    bool PostJson(const std::string& url, const json& payload);

    // 检查是否允许发送告警（节流逻辑）
    bool IsThrottled(const std::string& rule_id);

    // 统一落库（被节流也记录）
    void SaveAlertToDB(const AlertEvent& event, bool dingtalk_sent);
};