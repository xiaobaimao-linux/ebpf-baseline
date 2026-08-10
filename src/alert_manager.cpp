#include "alert_manager.hpp"
#include "commonfun.hpp"


#include "logger.h"
#include <spdlog/spdlog.h>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cctype>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
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

void AlertManager::LoadConfig(const AlertConfig& alert_cfg, const DbConfig& db_cfg) {
    dingtalk_url_      = alert_cfg.dingtalk_webhook;
    dingtalk_secret_   = alert_cfg.dingtalk_secret;
    throttle_seconds_  = alert_cfg.throttle_seconds;
    retention_days_    = db_cfg.retention_days;
    retention_max_records_ = db_cfg.retention_max_records;
}

void AlertManager::SetDB(BaselineDB* db) {
    db_ = db;
    if (db_) {
        spdlog::info("AlertManager DB bound, alerts will be persisted to SQLite");
    }
}

bool AlertManager::IsEnabled() const {
    return !dingtalk_url_.empty();
}

// 检查是否被节流（同一规则在throttle_seconds内只允许一次告警）
bool AlertManager::IsThrottled(const std::string& rule_id) {
    if (throttle_seconds_ <= 0) {
        return false;
    }

    auto now = std::chrono::steady_clock::now();
    auto it = last_alert_time_.find(rule_id);

    if (it == last_alert_time_.end()) {
        last_alert_time_[rule_id] = now;
        return false;
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count();
    if (elapsed >= throttle_seconds_) {
        it->second = now;
        return false;
    }

    int remaining = throttle_seconds_ - static_cast<int>(elapsed);
    spdlog::debug("Alert throttled for rule {}: {}s elapsed, {}s remaining",
                  rule_id, elapsed, remaining);
    return true;
}

// 执行保留策略：按天数 + 按数量双保险
int AlertManager::RunRetention() {
    if (!db_) {
        return 0;
    }

    int total_deleted = 0;
    int before_count = db_->GetAlertCount();

    // 策略1：按天数清理
    if (retention_days_ > 0) {
        int deleted = db_->PurgeAlertsByAge(retention_days_);
        if (deleted > 0) {
            spdlog::info("[retention] Purged {} alerts older than {} days", deleted, retention_days_);
            total_deleted += deleted;
        }
    }

    // 策略2：按数量上限清理（保留最新的N条）
    if (retention_max_records_ > 0) {
        int deleted = db_->PurgeAlertsByCount(retention_max_records_);
        if (deleted > 0) {
            spdlog::info("[retention] Purged {} alerts exceeding max {} records",
                         deleted, retention_max_records_);
            total_deleted += deleted;
        }
    }

    // 如果删除了记录，执行VACUUM回收空间
    if (total_deleted > 0) {
        int after_count = db_->GetAlertCount();
        spdlog::info("[retention] Before: {} records, After: {} records, Deleted: {} total",
                     before_count, after_count, total_deleted);

        spdlog::info("[retention] Running VACUUM to reclaim disk space...");
        db_->Vacuum();
        spdlog::info("[retention] VACUUM completed");
    }

    return total_deleted;
}

// 统一落库：无论钉钉是否发送成功/被节流，都写入 alerts 表
void AlertManager::SaveAlertToDB(const AlertEvent& event, bool dingtalk_sent) {
    if (!db_) {
        return;
    }

    AlertRecord record;
    record.rule_id      = event.rule_id;
    record.rule_name    = event.rule_name;
    record.severity     = event.severity;
    record.file_path    = event.file_path;
    record.event_type   = event.event_type.empty() ? "unknown" : event.event_type;
    record.process_name = event.process_name;
    record.pid          = event.pid;
    record.user_name    = event.user_name;
    record.uid          = event.uid;
    record.expected     = event.expected;
    record.actual       = event.actual;
    record.action_taken = event.action_taken.empty() ? "alert" : event.action_taken;
    record.dingtalk_sent = dingtalk_sent;
    record.recorded_at  = event.timestamp.empty() ? NowString() : event.timestamp;

    db_->SaveAlert(record);

    // 每插入1000条触发一次保留检查（简单策略）
    static int insert_count = 0;
    insert_count++;
    if (insert_count >= 1000) {
        insert_count = 0;
        int current = db_->GetAlertCount();
        if (retention_max_records_ > 0 && current > retention_max_records_ * 1.2) {
            spdlog::warn("[retention] Alert count {} exceeds threshold, triggering cleanup", current);
            RunRetention();
        }
    }
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
    // 1. 检查是否被节流
    bool throttled = IsThrottled(event.rule_id);

    // 2. 构造钉钉消息
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
    if (!event.event_type.empty()) {
        md += "**事件类型**: " + event.event_type + "\n\n";
    }
    md += "**时间**: " + event.timestamp + "\n\n";
    md += "> baseline-guard 自动检测";

    json payload;
    payload["msgtype"] = "markdown";
    payload["markdown"] = {
        {"title", "基线违规告警"},
        {"text", md}
    };

    // 3. 发送钉钉（如果被节流则跳过）
    bool dingtalk_sent = false;
    if (!throttled && IsEnabled()) {
        const std::string signed_url = BuildSignedUrl(dingtalk_url_, dingtalk_secret_);
        dingtalk_sent = PostJson(signed_url, payload);
    } else if (throttled) {
        spdlog::warn("Alert throttled for rule {} ({}s), skip DingTalk but persist to DB",
                     event.rule_id, throttle_seconds_);
    } else if (!IsEnabled()) {
        spdlog::debug("DingTalk not enabled, skip webhook but persist to DB");
    }

    // 4. 统一落库（无论钉钉是否发送成功/被节流，都记录到 SQLite）
    SaveAlertToDB(event, dingtalk_sent);

    return dingtalk_sent;
}