#include "event_bus.hpp"

#include <algorithm>
#include <cstring>

// ── LatencyStats ──────────────────────────────────────────────────

void LatencyStats::add(unsigned long long sample_ns) {
    samples_[idx_] = sample_ns;
    idx_ = (idx_ + 1) % kCapacity;
    if (count_ < kCapacity)
        count_++;
}

LatencyStats::Summary LatencyStats::summarize() const {
    Summary s;
    if (count_ == 0)
        return s;

    // 拷贝窗口内样本（环形缓冲中最新的 count_ 个）后排序求 p95
    unsigned long long buf[kCapacity];
    std::memcpy(buf, samples_, count_ * sizeof(unsigned long long));
    std::sort(buf, buf + count_);

    unsigned long long sum = 0;
    for (size_t i = 0; i < count_; i++)
        sum += buf[i];

    s.count = count_;
    s.avg_us = static_cast<double>(sum) / static_cast<double>(count_) / 1000.0;
    // p95：升序取 95 分位（最近邻秩），下标收敛到 [0, count_-1]
    size_t rank = static_cast<size_t>(static_cast<double>(count_ - 1) * 0.95 + 0.5);
    if (rank >= count_)
        rank = count_ - 1;
    s.p95_us = buf[rank] / 1000;
    s.valid = true;
    return s;
}

void LatencyStats::reset() {
    idx_ = 0;
    count_ = 0;
}

// ── MpscQueue（Vyukov 有界环形 MPMC，MPSC 场景同样正确）────────────
//
// 每槽一个序列号 seq：入队成功后 seq=pos+1，消费取走后 seq=pos+mask+1，
// 槽位回到“可写”状态。生产者仅当 seq==pos（槽空）时 CAS 认领 enqueue_pos，
// 消费者仅当 seq==pos+1（槽满）时 CAS 认领 dequeue_pos；单消费者下
// dequeue CAS 必然成功。任何一步不满足即重读位置，无锁无分配。

MpscQueue::MpscQueue(size_t capacity) {
    // 向上取 2 的幂（掩码寻址要求）
    size_t cap = 1;
    while (cap < capacity)
        cap <<= 1;
    capacity_ = cap;
    mask_ = cap - 1;

    seq_ = std::make_unique<std::atomic<unsigned long long>[]>(cap);
    data_ = std::make_unique<EventRecord[]>(cap);
    for (size_t i = 0; i < cap; i++)
        seq_[i].store(i, std::memory_order_relaxed);
}

MpscQueue::~MpscQueue() = default;

bool MpscQueue::try_push(const EventRecord& rec) {
    unsigned long long pos = enqueue_pos_.load(std::memory_order_relaxed);
    for (;;) {
        std::atomic<unsigned long long>& cell_seq = seq_[pos & mask_];
        unsigned long long seq = cell_seq.load(std::memory_order_acquire);
        intptr_t dif = static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos);
        if (dif == 0) {
            if (enqueue_pos_.compare_exchange_weak(pos, pos + 1,
                                                   std::memory_order_relaxed))
                break;
        } else if (dif < 0) {
            return false;  // 队列满
        } else {
            pos = enqueue_pos_.load(std::memory_order_relaxed);
        }
    }
    data_[pos & mask_] = rec;
    seq_[pos & mask_].store(pos + 1, std::memory_order_release);
    return true;
}

bool MpscQueue::try_pop(EventRecord& out) {
    unsigned long long pos = dequeue_pos_.load(std::memory_order_relaxed);
    for (;;) {
        std::atomic<unsigned long long>& cell_seq = seq_[pos & mask_];
        unsigned long long seq = cell_seq.load(std::memory_order_acquire);
        intptr_t dif = static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos + 1);
        if (dif == 0) {
            if (dequeue_pos_.compare_exchange_weak(pos, pos + 1,
                                                   std::memory_order_relaxed))
                break;
        } else if (dif < 0) {
            return false;  // 队列空
        } else {
            pos = dequeue_pos_.load(std::memory_order_relaxed);
        }
    }
    out = data_[pos & mask_];
    seq_[pos & mask_].store(pos + mask_ + 1, std::memory_order_release);
    return true;
}

// ── EventBus ──────────────────────────────────────────────────────

EventBus::EventBus(size_t hi_capacity, size_t lo_capacity)
    : hi_(hi_capacity), lo_(lo_capacity) {
    for (auto& c : drops_hi_)
        c.store(0, std::memory_order_relaxed);
    for (auto& c : drops_lo_)
        c.store(0, std::memory_order_relaxed);
}

bool EventBus::try_push(const EventRecord& rec) {
    const int prio = rec.priority;
    const bool hi = (prio <= PRIO_CTRL);
    bool ok = hi ? hi_.try_push(rec) : lo_.try_push(rec);
    if (ok) {
        pushed_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
    // 满则丢弃，per-queue per-priority 计数
    if (prio >= 0 && prio < 4) {
        auto& cnt = hi ? drops_hi_[prio] : drops_lo_[prio];
        cnt.fetch_add(1, std::memory_order_relaxed);
    }
    return false;
}

bool EventBus::try_pop_hi(EventRecord& out) {
    return hi_.try_pop(out);
}

bool EventBus::try_pop_lo(EventRecord& out) {
    return lo_.try_pop(out);
}

unsigned long long EventBus::drop_count(bool hi, int priority) const {
    if (priority < 0 || priority >= 4)
        return 0;
    const auto& arr = hi ? drops_hi_ : drops_lo_;
    return arr[priority].load(std::memory_order_relaxed);
}

unsigned long long EventBus::drop_count_total() const {
    unsigned long long total = 0;
    for (int p = 0; p < 4; p++) {
        total += drop_count(true, p);
        total += drop_count(false, p);
    }
    return total;
}
