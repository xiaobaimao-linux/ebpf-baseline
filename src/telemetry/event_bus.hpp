#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>

#include "event_record.hpp"

// ── 延迟统计（1024 采样环形缓冲，算 avg / p95）────────────────────
// 单线程使用（消费线程）：queue 延迟由消费线程记录，e2e 延迟由落库
// 刷新时在同一消费线程记录，均无需加锁。
class LatencyStats {
public:
    static constexpr size_t kCapacity = 1024;

    struct Summary {
        unsigned long long count = 0;  // 窗口内采样数（<= kCapacity）
        double avg_us = 0.0;
        unsigned long long p95_us = 0;
        bool valid = false;            // count>0 时为 true
    };

    void add(unsigned long long sample_ns);

    // 基于环形缓冲中当前样本计算 avg / p95（拷贝后排序，p95 取 95 分位）
    Summary summarize() const;

    void reset();

private:
    unsigned long long samples_[kCapacity] = {0};
    size_t idx_ = 0;    // 下一个写入位置（环形）
    size_t count_ = 0;  // 当前有效样本数（<= kCapacity）
};

// ── 有界 MPSC 队列（Vyukov 环形缓冲，非阻塞）─────────────────────
// 多生产者（rb 回调 / 压测线程）单消费者（消费线程）。try_push 满即
// 返回 false，不阻塞、不分配；槽位为定长 POD EventRecord。
class MpscQueue {
public:
    explicit MpscQueue(size_t capacity);   // 内部向上取 2 的幂
    ~MpscQueue();

    MpscQueue(const MpscQueue&) = delete;
    MpscQueue& operator=(const MpscQueue&) = delete;

    bool try_push(const EventRecord& rec); // 满返回 false
    bool try_pop(EventRecord& out);        // 空返回 false

    size_t capacity() const { return capacity_; }

private:
    size_t capacity_ = 0;
    size_t mask_ = 0;
    std::unique_ptr<std::atomic<unsigned long long>[]> seq_;  // 每槽序列号
    std::unique_ptr<EventRecord[]> data_;                     // 定长 POD 槽
    alignas(64) std::atomic<unsigned long long> enqueue_pos_{0};  // 生产者位置
    alignas(64) std::atomic<unsigned long long> dequeue_pos_{0};  // 消费者位置
};

// ── 事件总线：双有界 MPSC 队列 + 丢弃计数 + 排队延迟统计 ──────────
// hi 队列承载 priority<=1（file/priv/ns/process），lo 队列承载 priority>=2
// （network/dns）。消费侧严格先拉 hi 再拉 lo（由消费线程保证顺序）。
class EventBus {
public:
    EventBus(size_t hi_capacity = 32768, size_t lo_capacity = 65536);

    // 按 rec.priority 路由到 hi/lo；满则丢弃并按 per-queue per-priority 计数。
    // 返回 false 表示被丢弃。非阻塞，可在 rb 回调内调用。
    bool try_push(const EventRecord& rec);

    bool try_pop_hi(EventRecord& out);
    bool try_pop_lo(EventRecord& out);

    // per-queue per-priority 丢弃计数（priority 0..3）
    unsigned long long drop_count(bool hi, int priority) const;
    unsigned long long drop_count_total() const;

    // 成功入队总数（对账用）
    unsigned long long pushed_count() const { return pushed_.load(std::memory_order_relaxed); }

    // 排队延迟统计（消费线程在 dequeue 后记录）
    void record_queue_latency(unsigned long long sample_ns) { queue_lat_.add(sample_ns); }
    LatencyStats::Summary queue_latency_summary() const { return queue_lat_.summarize(); }

    size_t hi_capacity() const { return hi_.capacity(); }
    size_t lo_capacity() const { return lo_.capacity(); }

private:
    MpscQueue hi_;
    MpscQueue lo_;
    std::array<std::atomic<unsigned long long>, 4> drops_hi_{};
    std::array<std::atomic<unsigned long long>, 4> drops_lo_{};
    std::atomic<unsigned long long> pushed_{0};
    LatencyStats queue_lat_;  // 仅消费线程写
};
