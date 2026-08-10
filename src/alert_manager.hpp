#pragma once
#include <string>
#include <unordered_map>
#include <chrono>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

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
};

class AlertManager {
public:
    AlertManager();
    ~AlertManager();

    void LoadConfig(const std::string& dingtalk_webhook,
                    const std::string& dingtalk_secret = "",
                    int throttle_seconds = 300);
    bool IsEnabled() const;

    // 发送钉钉告警（带节流控制）
    bool SendDingTalk(const AlertEvent& event);
    
private:
    std::string dingtalk_url_;
    std::string dingtalk_secret_;
    int throttle_seconds_ = 300;  // 默认5分钟节流

    // 记录每条规则最近一次告警时间: rule_id -> 上次告警时间点
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_alert_time_;

    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);
    bool PostJson(const std::string& url, const json& payload);

    // 检查是否允许发送告警（节流逻辑）
    bool IsThrottled(const std::string& rule_id);
};