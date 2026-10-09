#include "notify_dispatcher.hpp"
#include "notify_router.hpp"
#include "webhook_notifier.hpp"
#include <spdlog/spdlog.h>

NotifyDispatcher::NotifyDispatcher() {
    worker_ = std::thread(&NotifyDispatcher::WorkerMain, this);
}

NotifyDispatcher::~NotifyDispatcher() {
    {
        std::lock_guard<std::mutex> lk(mu_);
        stop_ = true;
    }
    cv_.notify_all();
    if (worker_.joinable()) {
        worker_.join();
    }
}

void NotifyDispatcher::UpdateConfig(const NotifyConfig& cfg) {
    std::lock_guard<std::mutex> lk(mu_);
    const bool url_changed = (cfg.webhook_url != cfg_.webhook_url);
    cfg_ = cfg;
    if (url_changed) {
        // 渠道对象随 url 整体换新（工作线程持 shared_ptr 快照，发送中途换 url 安全）
        notifier_.reset();
        if (!cfg_.webhook_url.empty()) {
            notifier_ = std::make_shared<WebhookNotifier>(cfg_.webhook_url);
        }
    }
}

void NotifyDispatcher::Dispatch(const AlertEvent& evt) {
    std::lock_guard<std::mutex> lk(mu_);

    if (!cfg_.enabled || !notifier_) {
        return;
    }

    // 级别路由：低于 min_level 仅落库，不外发（路由判定见 notify_router.hpp 单测）
    if (!notify::ShouldRouteByLevel(evt.severity, cfg_.min_level)) {
        spdlog::debug("[notify] routed out by min_level={}: rule={} severity={}",
                      cfg_.min_level, evt.rule_id, evt.severity);
        return;
    }

    // 静默窗口：同 (rule_id, 对象 key) 窗口内只外发 1 次；窗口内重复仍落库
    //（落库在 SendDingTalk 内先于 Dispatch 完成），此处计 suppressed
    if (cfg_.silence_minutes > 0) {
        const std::string key = evt.rule_id + "|" + notify::SilenceObjectKey(evt);
        const auto now = std::chrono::steady_clock::now();
        auto it = last_sent_.find(key);
        if (it != last_sent_.end() &&
            notify::SilenceWindowActive(it->second, now, cfg_.silence_minutes * 60)) {
            ++suppressed_;
            spdlog::debug("[notify] silenced: rule={} key={}", evt.rule_id, key);
            return;
        }
        // 仅在成功入队后才占用窗口槽位
        if (queue_.size() >= kMaxQueue) {
            ++dropped_;
            spdlog::warn("[notify] queue full ({}), alert dropped: rule={}",
                         kMaxQueue, evt.rule_id);
            return;
        }
        last_sent_[key] = now;
        if (last_sent_.size() > 4096) {   // 有界防膨胀（同祖先链缓存口径）
            last_sent_.clear();
            last_sent_[key] = now;
        }
        queue_.push(evt);
    } else {
        if (queue_.size() >= kMaxQueue) {
            ++dropped_;
            spdlog::warn("[notify] queue full ({}), alert dropped: rule={}",
                         kMaxQueue, evt.rule_id);
            return;
        }
        queue_.push(evt);
    }
    cv_.notify_one();
}

NotifyStats NotifyDispatcher::Stats() const {
    NotifyStats s;
    s.sent       = sent_.load();
    s.failed     = failed_.load();
    s.suppressed = suppressed_.load();
    s.dropped    = dropped_.load();
    return s;
}

void NotifyDispatcher::WorkerMain() {
    while (true) {
        AlertEvent evt;
        std::shared_ptr<INotifier> notifier;
        {
            std::unique_lock<std::mutex> lk(mu_);
            cv_.wait(lk, [this] { return stop_ || !queue_.empty(); });
            if (stop_) {
                return;   // 停机即退出，残余队列不再发送
            }
            evt = std::move(queue_.front());
            queue_.pop();
            notifier = notifier_;
        }

        // 锁外发送：首试 + 最多 2 次重试，重试间隔 200ms；耗尽计 failed
        bool ok = false;
        for (int attempt = 0; attempt <= kMaxRetries; ++attempt) {
            if (attempt > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(kRetryBackoffMs));
            }
            if (notifier->Send(evt)) {
                ok = true;
                break;
            }
        }
        if (ok) {
            ++sent_;
            spdlog::info("[notify] webhook sent: rule={} severity={} file={}",
                         evt.rule_id, evt.severity, evt.file_path);
        } else {
            ++failed_;
            spdlog::warn("[notify] webhook failed after {} retries, give up: rule={}",
                         kMaxRetries, evt.rule_id);
        }
    }
}
