#include "webhook_notifier.hpp"
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <unistd.h>

using json = nlohmann::json;

WebhookNotifier::WebhookNotifier(std::string url) : url_(std::move(url)) {
    char buf[256] = {};
    if (gethostname(buf, sizeof(buf) - 1) == 0) {
        host_ = buf;
    }
}

size_t WebhookNotifier::WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    (void)contents;
    (void)userp;
    return size * nmemb;
}

bool WebhookNotifier::Send(const AlertEvent& alert) {
    json payload;
    payload["source"]       = "baseline-guard";
    payload["host"]         = host_;
    payload["rule_id"]      = alert.rule_id;
    payload["rule_name"]    = alert.rule_name;
    payload["severity"]     = alert.severity;
    payload["file_path"]    = alert.file_path;
    payload["expected"]     = alert.expected;
    payload["actual"]       = alert.actual;
    payload["process_name"] = alert.process_name;
    payload["pid"]          = alert.pid;
    payload["user_name"]    = alert.user_name;
    payload["uid"]          = alert.uid;
    payload["timestamp"]    = alert.timestamp;
    payload["event_type"]   = alert.event_type;
    payload["action_taken"] = alert.action_taken;
    payload["exe"]          = alert.exe;
    payload["container_id"] = alert.container_id;
    payload["ancestors"]    = alert.ancestors;
    payload["attack"]       = alert.attack;
    // 聚合摘要字段（W5 D5）：普通告警恒 1；摘要告警为窗口内合并条数，附首末时间
    payload["occurrences"]  = alert.occurrences;
    if (!alert.first_seen.empty()) {
        payload["first_seen"] = alert.first_seen;
        payload["last_seen"]  = alert.last_seen;
    }

    CURL* curl = curl_easy_init();
    if (!curl) {
        spdlog::error("[notify] curl init failed");
        return false;
    }

    const std::string body = payload.dump();
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url_.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    // 硬约束：单次发送总超时 ≤3s（连接阶段 ≤1.5s）
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 3000L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 1500L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);   // 工作线程内禁用信号超时

    const CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        spdlog::warn("[notify] webhook POST failed: {}", curl_easy_strerror(res));
        return false;
    }
    if (http_code < 200 || http_code >= 300) {
        spdlog::warn("[notify] webhook HTTP {}", http_code);
        return false;
    }
    return true;
}
