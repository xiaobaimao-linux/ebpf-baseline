#pragma once
#include <string>
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
    
    void LoadConfig(const std::string& dingtalk_webhook, const std::string& dingtalk_secret = "");
    bool IsEnabled() const;
    
    // 发送钉钉告警
    bool SendDingTalk(const AlertEvent& event);
    
private:
    std::string dingtalk_url_;
    std::string dingtalk_secret_;
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);
    bool PostJson(const std::string& url, const json& payload);
};