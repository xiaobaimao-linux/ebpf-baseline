#pragma once
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include "alert_event.hpp"
#include "config.hpp"
#include "notifier.hpp"

// 外发计数（对账口径，自进程启动累计）：sent 成功 / failed 重试耗尽 /
// suppressed 静默窗口内被抑制 / dropped 队列满丢弃
struct NotifyStats {
    uint64_t sent = 0;
    uint64_t failed = 0;
    uint64_t suppressed = 0;
    uint64_t dropped = 0;
};

// 异步外发调度器（W5 D4）：Dispatch 由消费线程调用，只做级别路由 +
// 静默判定 + 入队（不等待、不做 IO）；工作线程串行发送（单次 ≤3s，
// 失败重试 ≤2 次后计 failed）。任何情况下不影响告警落库。
// 配置经 UpdateConfig 热加载（SIGHUP 路径），锁内整份替换。
class NotifyDispatcher {
public:
    NotifyDispatcher();
    ~NotifyDispatcher();   // 停工作线程并 join

    NotifyDispatcher(const NotifyDispatcher&) = delete;
    NotifyDispatcher& operator=(const NotifyDispatcher&) = delete;

    // 热加载入口（SIGHUP 路径与启动共用）
    void UpdateConfig(const NotifyConfig& cfg);

    // 消费线程入口：级别路由 + 静默判定 + 入队，全部 O(1)，无阻塞 IO
    void Dispatch(const AlertEvent& evt);

    NotifyStats Stats() const;

private:
    void WorkerMain();

    static constexpr size_t kMaxQueue = 1024;      // 队列上限，满则丢弃计 dropped
    static constexpr int kMaxRetries = 2;          // 失败后最多重试 2 次
    static constexpr int kRetryBackoffMs = 200;

    mutable std::mutex mu_;
    NotifyConfig cfg_;                             // 锁内整份替换
    std::shared_ptr<INotifier> notifier_;          // webhook 渠道（url 变更时整体换新）
    // 静默窗口：key = rule_id + "|" + 对象 key → 上次外发时间点
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_sent_;

    std::queue<AlertEvent> queue_;                 // 与 mu_ 同锁
    std::condition_variable cv_;
    std::thread worker_;
    bool stop_ = false;

    std::atomic<uint64_t> sent_{0};
    std::atomic<uint64_t> failed_{0};
    std::atomic<uint64_t> suppressed_{0};
    std::atomic<uint64_t> dropped_{0};
};
