#include "alert_manager.hpp"
#include "logger.h"       // 你的日志头文件在 include/ 下
#include <spdlog/spdlog.h>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cctype>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

namespace {

std::string UrlEncode(const std::string& value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::uppercase << std::hex;
    for (unsigned char c : value) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        } else {
            escaped << '%' << std::setw(2) << static_cast<int>(c);
        }
    }
    return escaped.str();
}

std::string Base64Encode(const unsigned char* data, size_t len) {
    BIO* bio = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    bio = BIO_push(bio, mem);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, static_cast<int>(len));
    BIO_flush(bio);

    BUF_MEM* mem_ptr = nullptr;
    BIO_get_mem_ptr(bio, &mem_ptr);
    std::string out(mem_ptr->data, mem_ptr->length);

    BIO_free_all(bio);
    return out;
}

std::string BuildSignedUrl(const std::string& url, const std::string& secret) {
    if (secret.empty()) {
        return url;
    }

    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const std::string timestamp = std::to_string(now_ms);
    const std::string to_sign = timestamp + "\n" + secret;

    unsigned char digest[EVP_MAX_MD_SIZE] = {};
    unsigned int digest_len = 0;
    const unsigned char* secret_bytes = reinterpret_cast<const unsigned char*>(secret.c_str());
    const unsigned char* text_bytes = reinterpret_cast<const unsigned char*>(to_sign.c_str());

    if (HMAC(EVP_sha256(), secret_bytes, static_cast<int>(secret.size()),
             text_bytes, to_sign.size(), digest, &digest_len) == nullptr) {
        return url;
    }

    const std::string base64 = Base64Encode(digest, digest_len);
    const std::string sign = UrlEncode(base64);
    return url + "&timestamp=" + timestamp + "&sign=" + sign;
}

}  // namespace

AlertManager::AlertManager() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

AlertManager::~AlertManager() {
    curl_global_cleanup();
}

void AlertManager::LoadConfig(const std::string& dingtalk_webhook,
                              const std::string& dingtalk_secret,
                              int throttle_seconds) {
    dingtalk_url_ = dingtalk_webhook;
    dingtalk_secret_ = dingtalk_secret;
    throttle_seconds_ = throttle_seconds;
}

bool AlertManager::IsEnabled() const {
    return !dingtalk_url_.empty();
}

// 检查是否被节流（同一规则在throttle_seconds内只允许一次告警）
bool AlertManager::IsThrottled(const std::string& rule_id) {
    if (throttle_seconds_ <= 0) {
        // 节流时间为0或负数表示不节流
        return false;
    }

    auto now = std::chrono::steady_clock::now();
    auto it = last_alert_time_.find(rule_id);

    if (it == last_alert_time_.end()) {
        // 该规则从未告警过，允许发送
        last_alert_time_[rule_id] = now;
        return false;
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count();
    if (elapsed >= throttle_seconds_) {
        // 已经超过节流时间，允许发送，更新时间戳
        it->second = now;
        return false;
    }

    // 在节流时间内，阻止发送
    int remaining = throttle_seconds_ - static_cast<int>(elapsed);
    spdlog::debug("Alert throttled for rule {}: {}s elapsed, {}s remaining",
                  rule_id, elapsed, remaining);
    return true;
}

size_t AlertManager::WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    (void)contents;
    (void)userp;
    return size * nmemb;
}

bool AlertManager::PostJson(const std::string& url, const json& payload) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        spdlog::error("curl init failed");
        return false;
    }

    std::string post_data = payload.dump();
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        spdlog::error("DingTalk request failed: {}", curl_easy_strerror(res));
        return false;
    }
    if (http_code != 200) {
        spdlog::error("DingTalk HTTP {}", http_code);
        return false;
    }

    spdlog::info("Alert sent to DingTalk OK");
    return true;
}

bool AlertManager::SendDingTalk(const AlertEvent& event) {
    if (!IsEnabled()) {
        spdlog::warn("DingTalk not configured, skip alert");
        return false;
    }

    // 节流检查：同一规则在 throttle_seconds_ 内只告警一次
    if (IsThrottled(event.rule_id)) {
        spdlog::warn("Alert suppressed for rule {} due to throttle ({}s)",
                     event.rule_id, throttle_seconds_);
        return false;
    }

    std::string emoji = "";
    if (event.severity == "critical") emoji = "";
    else if (event.severity == "high") emoji = "";
    else if (event.severity == "low") emoji = "";

    std::string md = emoji + " **基线违规告警**\n\n";
    md += "**规则ID**: " + event.rule_id + "\n\n";
    md += "**规则名称**: " + event.rule_name + "\n\n";
    md += "**严重级别**: " + event.severity + "\n\n";
    md += "**文件路径**: `" + event.file_path + "`\n\n";
    md += "**预期值**: `" + event.expected + "`\n\n";
    md += "**实际值**: `" + event.actual + "`\n\n";
    if (!event.process_name.empty()) {
        md += "**进程**: " + event.process_name + " (pid=" + std::to_string(event.pid) + ")\n\n";
    }
    md += "**时间**: " + event.timestamp + "\n\n";
    md += "> baseline-guard 自动检测";

    json payload;
    payload["msgtype"] = "markdown";
    payload["markdown"] = {
        {"title", "基线违规告警"},
        {"text", md}
    };

    const std::string signed_url = BuildSignedUrl(dingtalk_url_, dingtalk_secret_);
    return PostJson(signed_url, payload);
}