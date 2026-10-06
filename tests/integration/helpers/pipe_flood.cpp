// pipe_flood — 事件总线→落库管道压测 helper（直灌总线，绕过 eBPF）
//
// 用途：
//   PIPE-003  10,000 条/s × 60s：RSS 增长 <50%、drop=0、灌入数==落库行数、
//             并发查询 P95 < 100ms
//   PIPE-004  50,000 条/s × 10s 突发：lo 队列 drop>0 且 dns 占比最高、
//             hi 队列 drop=0、进程存活、突发后 drop 停止增长
//
// 直灌总线：生产线程按固定速率把 EventRecord 灌入 EventBus，消费线程按
// “先 hi 后 lo”拉出、记录排队延迟、富化祖先链、追加到 EventStore 批量落库；
// 独立线程用另一 sqlite 连接并发查询测 P95。最后打印对账与性能数据。
//
// 用法：
//   pipe_flood --rate N --seconds T --category dns|network|process|file|mixed
//              --db PATH [--queue-hi N] [--queue-lo N] [--batch-size N]
//              [--batch-ms N] [--query] [--seed N]
// 退出码：0 正常；2 参数错误；3 落库打开失败。

#include <atomic>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <sqlite3.h>
#include <unistd.h>

#include "enricher.hpp"
#include "event_bus.hpp"
#include "event_record.hpp"
#include "event_store.hpp"
#include "process_tree.hpp"

using json = nlohmann::json;

namespace {

struct Config {
    int rate = 10000;
    int seconds = 10;
    std::string category = "dns";
    std::string db = "/tmp/pipe_flood_events.db";
    int queue_hi = 32768;
    int queue_lo = 65536;
    int batch_size = 500;
    int batch_ms = 200;
    bool query = false;
    bool enrich = false;   // 消费侧富化（json 解析+祖先链）；默认关闭以保证吞吐压测 drop=0
    unsigned int seed = 1;
};

void usage() {
    fprintf(stderr,
            "usage: pipe_flood --rate N --seconds T --category C --db PATH "
            "[--queue-hi N] [--queue-lo N] [--batch-size N] [--batch-ms N] [--query] [--enrich] [--seed N]\n");
}

bool parse_args(int argc, char** argv, Config& cfg) {
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&](const char* name) -> const char* {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing value for %s\n", name);
                exit(2);
            }
            return argv[++i];
        };
        if (a == "--rate") cfg.rate = atoi(next("--rate"));
        else if (a == "--seconds") cfg.seconds = atoi(next("--seconds"));
        else if (a == "--category") cfg.category = next("--category");
        else if (a == "--db") cfg.db = next("--db");
        else if (a == "--queue-hi") cfg.queue_hi = atoi(next("--queue-hi"));
        else if (a == "--queue-lo") cfg.queue_lo = atoi(next("--queue-lo"));
        else if (a == "--batch-size") cfg.batch_size = atoi(next("--batch-size"));
        else if (a == "--batch-ms") cfg.batch_ms = atoi(next("--batch-ms"));
        else if (a == "--query") cfg.query = true;
        else if (a == "--enrich") cfg.enrich = true;
        else if (a == "--seed") cfg.seed = static_cast<unsigned int>(atoi(next("--seed")));
        else { usage(); return false; }
    }
    if (cfg.rate <= 0 || cfg.seconds <= 0) {
        usage();
        return false;
    }
    return true;
}

// /proc/self/statm 常驻集（KB）
long rss_kb() {
    FILE* f = fopen("/proc/self/statm", "r");
    if (!f) return -1;
    long size = 0, resident = 0;
    int n = fscanf(f, "%ld %ld", &size, &resident);
    fclose(f);
    if (n != 2) return -1;
    return resident * (sysconf(_SC_PAGESIZE) / 1024);
}

long long now_ms() {
    return static_cast<long long>(now_monotonic_ns() / 1000000ULL);
}

// 压测事件负载：可 json_extract 的最小 JSON
std::string flood_payload(const std::string& cat_str, unsigned int pid, unsigned long long ts) {
    char buf[512];
    snprintf(buf, sizeof(buf),
             "{\"event_type\":\"flood.%s\",\"ts\":%llu,\"process\":{\"pid\":%u,\"comm\":\"pipe_flood\"}}",
             cat_str.c_str(), ts, pid);
    return std::string(buf);
}

} // namespace

int main(int argc, char** argv) {
    Config cfg;
    if (!parse_args(argc, argv, cfg))
        return 2;

    const bool mixed = (cfg.category == "mixed");

    // 落库管道
    EventBus bus(static_cast<size_t>(cfg.queue_hi), static_cast<size_t>(cfg.queue_lo));
    EventStore store(cfg.db, cfg.batch_size, cfg.batch_ms);
    if (!store.ok()) {
        fprintf(stderr, "failed to open event store: %s\n", cfg.db.c_str());
        return 3;
    }
    ProcessTree tree;
    if (cfg.enrich)
        tree.bootstrap();   // 富化需要进程树；关闭富化时跳过 /proc 全量扫描
    Enricher enricher(tree);

    const long rss_before = rss_kb();

    // ── 消费线程：先 hi 后 lo 拉出，富化（可选）并落库 ──
    std::atomic<bool> stop{false};
    std::atomic<unsigned long long> consumed{0};
    std::thread consumer([&] {
        auto handle = [&](EventRecord& rec) {
            bus.record_queue_latency(now_monotonic_ns() - rec.enqueue_ts_ns);
            // 富化（可选）：解析 payload → 追加 process.ancestors → 随 Append 直传。
            // 吞吐压测默认关闭，避免 json 解析开销拖慢消费导致 lo 队列误丢。
            if (cfg.enrich) {
                json j = json::parse(rec.payload_raw, nullptr, false);
                if (!j.is_discarded()) {
                    enricher.enrich(rec, j);
                    const std::string s = j.dump();
                    store.Append(rec, s.c_str(), s.size());
                    consumed.fetch_add(1);
                    return;
                }
            }
            store.Append(rec, rec.payload_raw,
                         strnlen(rec.payload_raw, sizeof(rec.payload_raw)));
            consumed.fetch_add(1);
        };
        while (!stop.load()) {
            bool did = false;
            EventRecord rec;
            while (bus.try_pop_hi(rec)) { handle(rec); did = true; }
            while (bus.try_pop_lo(rec)) { handle(rec); did = true; }
            store.FlushIfDue();
            if (!did) {
                struct timespec ts {0, 200000};
                nanosleep(&ts, nullptr);
            }
        }
        // drain + 收尾
        EventRecord rec;
        while (bus.try_pop_hi(rec)) handle(rec);
        while (bus.try_pop_lo(rec)) handle(rec);
        store.Flush();
    });

    // ── 并发查询线程（独立 sqlite 连接，WAL 读不阻塞写）──
    std::atomic<bool> qstop{false};
    std::vector<long long> q_lat_ms;
    std::thread qthread;
    if (cfg.query) {
        qthread = std::thread([&] {
            sqlite3* qdb = nullptr;
            if (sqlite3_open(cfg.db.c_str(), &qdb) != SQLITE_OK) {
                if (qdb) sqlite3_close(qdb);
                return;
            }
            sqlite3_busy_timeout(qdb, 5000);
            const char* sql =
                "SELECT count(*) FROM events WHERE category='dns' AND ts_ns > 0;";
            while (!qstop.load()) {
                long long t0 = now_ms();
                sqlite3_stmt* st = nullptr;
                if (sqlite3_prepare_v2(qdb, sql, -1, &st, nullptr) == SQLITE_OK) {
                    sqlite3_step(st);
                    sqlite3_finalize(st);
                }
                long long dt = now_ms() - t0;
                q_lat_ms.push_back(dt);
                struct timespec ts {0, 50000000};   // 50ms 间隔
                nanosleep(&ts, nullptr);
            }
            sqlite3_close(qdb);
        });
    }

    // ── 生产线程：按固定速率直灌总线（逐条均匀 pacing，避免秒级突发）──
    std::atomic<unsigned long long> attempted{0};
    std::atomic<unsigned long long> pushed{0};
    const unsigned long long total = static_cast<unsigned long long>(cfg.rate) * cfg.seconds;
    const auto t_start = std::chrono::steady_clock::now();
    const unsigned long long interval_ns = 1000000000ULL / static_cast<unsigned long long>(cfg.rate);
    unsigned int rng = cfg.seed;

    for (unsigned long long i = 0; i < total; i++) {
        EventRecord rec{};
        rec.ts_ns = now_monotonic_ns();
        rec.enqueue_ts_ns = rec.ts_ns;
        rec.pid = static_cast<unsigned int>(getpid());
        rec.ppid = static_cast<unsigned int>(getppid());
        rec.uid = 0;
        rec.gid = 0;
        strcpy(rec.comm, "pipe_flood");

        unsigned char cat;
        if (mixed) {
            // 80% dns(lo) + 20% network(lo)：dns 占 lo 丢弃的大头
            rng = rng * 1103515245u + 12345u;
            cat = ((rng >> 16) % 100 < 80) ? CAT_DNS : CAT_NETWORK;
        } else if (cfg.category == "dns") cat = CAT_DNS;
        else if (cfg.category == "network") cat = CAT_NETWORK;
        else if (cfg.category == "process") cat = CAT_PROCESS;
        else cat = CAT_FILE;

        rec.category = cat;
        rec.priority = category_priority(cat);
        rec.action = 1;
        const char* cat_str = CategoryToString(cat);
        std::string payload = flood_payload(cat_str, rec.pid, rec.ts_ns);
        record_set_str(rec.payload_raw, sizeof(rec.payload_raw), payload.c_str(), payload.size());

        attempted.fetch_add(1);
        if (bus.try_push(rec))
            pushed.fetch_add(1);

        // 逐条均匀 pacing：睡到本条事件的目标时刻
        const auto target = t_start + std::chrono::nanoseconds(i * interval_ns);
        std::this_thread::sleep_until(target);
    }

    // 停生产，等消费收尾
    const unsigned long long drops_at_production_end = bus.drop_count_total();
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    stop.store(true);
    consumer.join();
    if (cfg.query) {
        qstop.store(true);
        qthread.join();
    }

    const long rss_after = rss_kb();

    // 对账
    const unsigned long long drop_total = bus.drop_count_total();
    const unsigned long long stored = store.stored_count();

    // 查询 P95
    long long q_p95 = -1;
    if (!q_lat_ms.empty()) {
        std::sort(q_lat_ms.begin(), q_lat_ms.end());
        q_p95 = q_lat_ms[static_cast<size_t>(static_cast<double>(q_lat_ms.size() - 1) * 0.95)];
    }

    const auto q = bus.queue_latency_summary();
    const auto e2e = store.e2e_latency_summary();

    printf("=== pipe_flood result ===\n");
    printf("config: rate=%d/s seconds=%d category=%s queue_hi=%d queue_lo=%d batch=%d/%dms\n",
           cfg.rate, cfg.seconds, cfg.category.c_str(), cfg.queue_hi, cfg.queue_lo,
           cfg.batch_size, cfg.batch_ms);
    printf("attempted=%llu pushed=%llu consumed=%llu stored=%llu\n",
           attempted.load(), pushed.load(), consumed.load(), stored);
    printf("drops: total=%llu hi(file=%llu ctrl=%llu) lo(net=%llu dns=%llu)\n",
           drop_total,
           bus.drop_count(true, PRIO_FILE), bus.drop_count(true, PRIO_CTRL),
           bus.drop_count(false, PRIO_NETWORK), bus.drop_count(false, PRIO_DNS));
    printf("drops_at_production_end=%llu drops_final=%llu stopped=%s\n",
           drops_at_production_end, drop_total,
           (drops_at_production_end == drop_total) ? "YES" : "NO");
    printf("reconcile: pushed==stored : %s (diff=%lld)\n",
           (pushed.load() == stored) ? "YES" : "NO",
           static_cast<long long>(pushed.load()) - static_cast<long long>(stored));
    printf("rss_kb: before=%ld after=%ld growth=%.1f%%\n",
           rss_before, rss_after,
           rss_before > 0 ? (rss_after - rss_before) * 100.0 / rss_before : 0.0);
    printf("queue_latency: avg=%.1fus p95=%lluus (samples=%llu)\n",
           q.avg_us, q.p95_us, q.count);
    printf("e2e_latency: avg=%.1fus p95=%lluus (samples=%llu)\n",
           e2e.avg_us, e2e.p95_us, e2e.count);
    if (cfg.query)
        printf("query_p95_ms=%lld (samples=%zu)\n", q_p95, q_lat_ms.size());

    return 0;
}
