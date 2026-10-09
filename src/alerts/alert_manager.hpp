#pragma once
#include <string>
#include <unordered_map>
#include <chrono>
#include <cstdint>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include "alert_event.hpp"
#include "baseline_db.hpp"
#include "config.hpp"
#include "notify_dispatcher.hpp"

using json = nlohmann::json;

// ── 文件事件进程上下文（消费线程按 (pid, start_time) 查进程树组装）────
// valid=true  ：树命中，uid/gid/ppid/exe/container_id 取自进程树节点
// valid=false ：树 miss，uid/gid 用事件值、user_name 用 getpwuid 兜底，
//               其余字段留空。getpwuid/container_id_of 仅在消费线程调用。
struct FileActorContext {
    unsigned int uid = 0;
    unsigned int gid = 0;
    unsigned int ppid = 0;
    std::string user_name;
    std::string exe;
    std::string container_id;
    // 祖先链 [{pid,comm,exe}] 自近及远 ≤8 层：以指针引用消费线程缓存
    // （cached_ancestors_of 条目，事件处理期内有效），避免每事件深拷贝；
    // 为空表示无/未知。ancestors_json 为其预序列化文本（空链为空串，
    // 对应原 "empty() ? \"\" : dump()" 语义）。
    const json* ancestors = nullptr;
    std::string ancestors_json;
    bool valid = false;
};

// AlertEvent 定义见 alert_event.hpp（外发渠道接口 notifier.hpp 与其共用）

class AlertManager {
public:
    AlertManager();
    ~AlertManager();

    // 加载配置：alert + db
    void LoadConfig(const AlertConfig& alert_cfg, const DbConfig& db_cfg);

    // 外发配置（notify: 段）：启动与 SIGHUP 热加载共用入口
    void UpdateNotifyConfig(const NotifyConfig& notify_cfg);

    // 外发计数快照（sent/failed/suppressed/dropped，自进程启动累计）
    NotifyStats GetNotifyStats() const;
    bool IsEnabled() const;

    // 绑定数据库（告警统一落库）
    void SetDB(BaselineDB* db);

    // 发送钉钉告警（内部自动落库到 alerts 表）
    // 返回值: 钉钉是否实际发送成功（被节流返回 false，但仍会落库）
    bool SendDingTalk(const AlertEvent& event);

    // 非侵入式节流窥探（不更新节流时间戳）：调用方可用它在构建 AlertEvent
    // 之前跳过无用功——节流窗口内 SendDingTalk 本来就不发不存。
    // 单线程调用（消费线程），与 SendDingTalk 的 IsThrottled 判定同源。
    bool ThrottledNow(const std::string& rule_id) const;
    
    // 执行保留策略清理（可由外部定期调用，如每1小时一次）
    // 返回删除的记录数
    int RunRetention();

    // 节流抑制统计（M5-3 "已抑制 N 条" 对账口径）：节流窗口内被跳过的告警数。
    // 单线程读写（消费线程），与 IsThrottled 同一调用上下文。
    uint64_t ThrottledTotal() const { return throttled_total_; }
    uint64_t ThrottledCount(const std::string& rule_id) const {
        auto it = throttled_by_rule_.find(rule_id);
        return it == throttled_by_rule_.end() ? 0 : it->second;
    }
    const std::unordered_map<std::string, uint64_t>& ThrottledByRule() const {
        return throttled_by_rule_;
    }
    // 预检路径（ThrottledNow 命中即提前返回、不走 SendDingTalk）的抑制计数入口；
    // SendDingTalk 内部节流分支用同一入口，保证每条被抑制告警恰好计一次。
    void NoteThrottled(const std::string& rule_id) {
        throttled_total_++;
        throttled_by_rule_[rule_id]++;
    }

private:
    std::string dingtalk_url_;
    std::string dingtalk_secret_;
    int throttle_seconds_ = 300;
    int retention_days_ = 30;          // 0=永久保留
    int retention_max_records_ = 10000; // 0=不限制
    BaselineDB* db_ = nullptr;

    // 记录每条规则最近一次告警时间: rule_id -> 上次告警时间点
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_alert_time_;

    // 节流抑制计数（被节流跳过的告警）：总数 + 按规则
    uint64_t throttled_total_ = 0;
    std::unordered_map<std::string, uint64_t> throttled_by_rule_;

    // 异步外发调度器（webhook 渠道）：SendDingTalk 落库后投递，不影响落库
    NotifyDispatcher notify_dispatcher_;

    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);
    bool PostJson(const std::string& url, const json& payload);

    // 检查是否允许发送告警（节流逻辑）
    bool IsThrottled(const std::string& rule_id);

    // 统一落库（被节流也记录）
    void SaveAlertToDB(const AlertEvent& event, bool dingtalk_sent);
};