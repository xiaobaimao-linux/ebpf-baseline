// 单元测试：事件总线（EventBus：双有界 MPSC 队列 + 丢弃计数 + 延迟统计）
// 编译目标见 tests/Makefile（test_event_bus）。

#include <atomic>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

#include "event_bus.hpp"

// 构造一条测试事件：填 category/priority/pid/ppid，payload 置标记
static EventRecord make_rec(unsigned char category, unsigned char priority,
                            unsigned int pid, unsigned int ppid) {
    EventRecord rec{};
    rec.ts_ns = 1000;
    rec.enqueue_ts_ns = 2000;
    rec.pid = pid;
    rec.ppid = ppid;
    rec.category = category;
    rec.priority = priority;
    rec.action = 1;
    std::memset(rec.payload_raw, 0xAB, sizeof(rec.payload_raw));
    return rec;
}

// ====== BUS-001: push/pop 基本语义（FIFO） ======
static void test_push_pop_fifo() {
    EventBus bus(8, 8);
    for (unsigned int i = 0; i < 4; i++) {
        EventRecord r = make_rec(CAT_FILE, PRIO_FILE, 100 + i, 1);
        assert(bus.try_push(r));
    }
    assert(bus.pushed_count() == 4);
    // FIFO：按入队顺序弹出
    for (unsigned int i = 0; i < 4; i++) {
        EventRecord out;
        assert(bus.try_pop_hi(out));   // file 优先级进 hi 队列
        assert(out.pid == 100 + i);
    }
    EventRecord out;
    assert(!bus.try_pop_hi(out));      // 已空
    assert(!bus.try_pop_lo(out));
    printf("  [PASS] BUS-001: push/pop 基本语义（FIFO）\n");
}

// ====== BUS-002: 按 priority 路由 hi/lo 队列 ======
static void test_priority_routing() {
    EventBus bus(8, 8);
    // priority 0(file)/1(priv) -> hi；2(network)/3(dns) -> lo
    assert(bus.try_push(make_rec(CAT_FILE, PRIO_FILE, 1, 0)));
    assert(bus.try_push(make_rec(CAT_PRIV, PRIO_CTRL, 2, 0)));
    assert(bus.try_push(make_rec(CAT_NETWORK, PRIO_NETWORK, 3, 0)));
    assert(bus.try_push(make_rec(CAT_DNS, PRIO_DNS, 4, 0)));

    EventRecord out;
    // hi 队列应含 priority 0/1 两条
    assert(bus.try_pop_hi(out) && out.pid == 1);
    assert(bus.try_pop_hi(out) && out.pid == 2);
    assert(!bus.try_pop_hi(out));
    // lo 队列应含 priority 2/3 两条
    assert(bus.try_pop_lo(out) && out.pid == 3);
    assert(bus.try_pop_lo(out) && out.pid == 4);
    assert(!bus.try_pop_lo(out));
    printf("  [PASS] BUS-002: 按 priority 路由 hi/lo 队列\n");
}

// ====== BUS-003: 容量满丢弃与 per-queue per-priority 计数 ======
static void test_capacity_drop_counting() {
    EventBus bus(4, 4);   // hi/lo 各 4 槽
    // hi 队列灌满 4 条 file（priority 0）
    for (unsigned int i = 0; i < 4; i++)
        assert(bus.try_push(make_rec(CAT_FILE, PRIO_FILE, i, 0)));
    // 第 5 条丢弃，drop_count(hi, priority0) == 1
    assert(!bus.try_push(make_rec(CAT_FILE, PRIO_FILE, 99, 0)));
    assert(bus.drop_count(true, PRIO_FILE) == 1);
    assert(bus.drop_count(true, PRIO_CTRL) == 0);
    assert(bus.drop_count(false, PRIO_FILE) == 0);   // lo 队列不受影响
    assert(bus.pushed_count() == 4);                 // 只计成功入队

    // lo 队列灌满：2 条 network(priority2) + 2 条 dns(priority3)，再各丢 1 条
    for (unsigned int i = 0; i < 2; i++)
        assert(bus.try_push(make_rec(CAT_NETWORK, PRIO_NETWORK, i, 0)));
    for (unsigned int i = 0; i < 2; i++)
        assert(bus.try_push(make_rec(CAT_DNS, PRIO_DNS, i, 0)));
    assert(!bus.try_push(make_rec(CAT_NETWORK, PRIO_NETWORK, 99, 0)));
    assert(!bus.try_push(make_rec(CAT_DNS, PRIO_DNS, 99, 0)));
    assert(bus.drop_count(false, PRIO_NETWORK) == 1);
    assert(bus.drop_count(false, PRIO_DNS) == 1);
    assert(bus.drop_count(true, PRIO_FILE) == 1);    // hi 的 drop 不受影响
    assert(bus.drop_count_total() == 3);

    // hi 弹空后 drop 计数保持（累计值）
    EventRecord out;
    for (int i = 0; i < 4; i++)
        assert(bus.try_pop_hi(out));
    assert(!bus.try_pop_hi(out));
    assert(bus.drop_count(true, PRIO_FILE) == 1);
    printf("  [PASS] BUS-003: 容量满丢弃与 per-queue per-priority 计数\n");
}

// ====== BUS-004: hi 严格优先于 lo ======
static void test_hi_priority_over_lo() {
    EventBus bus(8, 8);
    // 先入 lo 再入 hi，模拟lo 队列先有积压
    assert(bus.try_push(make_rec(CAT_DNS, PRIO_DNS, 200, 0)));
    assert(bus.try_push(make_rec(CAT_NETWORK, PRIO_NETWORK, 201, 0)));
    assert(bus.try_push(make_rec(CAT_FILE, PRIO_FILE, 100, 0)));

    // 消费侧严格先拉 hi：先拿到 file(100)，lo 的 200/201 仍在 lo 队列
    EventRecord out;
    assert(bus.try_pop_hi(out) && out.pid == 100);
    assert(!bus.try_pop_hi(out));   // hi 已空
    assert(bus.try_pop_lo(out) && out.pid == 200);   // lo 保持 FIFO
    assert(bus.try_pop_lo(out) && out.pid == 201);
    printf("  [PASS] BUS-004: hi 严格优先于 lo\n");
}

// ====== BUS-005: 延迟统计 avg/p95 计算正确性 ======
static void test_latency_stats() {
    LatencyStats ls;
    // 空统计无效
    assert(!ls.summarize().valid);

    // 100 个样本：1us, 2us, ..., 100us（单位 ns）
    for (unsigned long long i = 1; i <= 100; i++)
        ls.add(i * 1000ULL);
    LatencyStats::Summary s = ls.summarize();
    assert(s.valid);
    assert(s.count == 100);
    // avg = (1+..+100)/100 = 50.5us
    assert(s.avg_us > 50.4 && s.avg_us < 50.6);
    // p95：升序第 94 下标（0 基）= 95us
    assert(s.p95_us == 95);

    // 环形缓冲只保留最近 1024 个：再压 1024 个 7us，把旧的 1..100us 全部覆盖
    for (int i = 0; i < 1024; i++)
        ls.add(7 * 1000ULL);
    s = ls.summarize();
    assert(s.valid);
    assert(s.count == 1024);         // 窗口上限 1024，旧的 1..100us 已被覆盖
    // 窗口内最近 1024 个样本全是 7us
    assert(s.avg_us > 6.9 && s.avg_us < 7.1);
    assert(s.p95_us == 7);

    // reset 后无效
    ls.reset();
    assert(!ls.summarize().valid);
    printf("  [PASS] BUS-005: 延迟统计 avg/p95 计算正确性\n");
}

// ====== BUS-006: 多生产者并发入队（MPSC 不丢不重、单生产者内 FIFO） ======
static void test_mpsc_concurrent() {
    const int kProducers = 4;
    const int kPerProducer = 5000;
    EventBus bus(kProducers * kPerProducer, 8);   // hi 队列足够大，不触发丢弃

    std::atomic<int> ready{0};
    std::vector<std::thread> producers;
    producers.reserve(kProducers);
    for (int p = 0; p < kProducers; p++) {
        producers.emplace_back([&, p] {
            ready.fetch_add(1);
            while (ready.load() < kProducers)
                ;   // 等所有生产者就位，放大并发
            for (int i = 0; i < kPerProducer; i++) {
                EventRecord r = make_rec(CAT_FILE, PRIO_FILE,
                                         static_cast<unsigned int>(p),
                                         static_cast<unsigned int>(i));
                while (!bus.try_push(r))
                    ;   // 队列满则自旋重试（测试容量足够，不应触发）
            }
        });
    }
    for (auto& t : producers)
        t.join();

    assert(bus.pushed_count() == static_cast<unsigned long long>(kProducers) * kPerProducer);
    assert(bus.drop_count_total() == 0);

    // 消费侧弹出全部：按生产者分桶校验数量与单生产者内 FIFO 顺序
    std::vector<int> counts(kProducers, 0);
    std::vector<unsigned int> next_seq(kProducers, 0);
    EventRecord out;
    long long total = 0;
    while (bus.try_pop_hi(out)) {
        total++;
        int p = static_cast<int>(out.pid);
        assert(p >= 0 && p < kProducers);
        // 单生产者内 FIFO：序号严格递增
        assert(out.ppid == next_seq[p]);
        next_seq[p]++;
        counts[p]++;
    }
    assert(total == static_cast<long long>(kProducers) * kPerProducer);
    for (int p = 0; p < kProducers; p++)
        assert(counts[p] == kPerProducer);
    printf("  [PASS] BUS-006: 多生产者并发入队（MPSC 不丢不重、单生产者内 FIFO）\n");
}

int main() {
    printf("=== test_event_bus ===\n");
    test_push_pop_fifo();
    test_priority_routing();
    test_capacity_drop_counting();
    test_hi_priority_over_lo();
    test_latency_stats();
    test_mpsc_concurrent();
    printf("=== all event_bus tests passed ===\n");
    return 0;
}
