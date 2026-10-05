#pragma once

#include <atomic>
#include <cstdint>
#include <sqlite3.h>
#include <string>
#include <vector>

#include "event_record.hpp"
#include "event_bus.hpp"   // LatencyStats

// ── 遥测事件落库管道 ──────────────────────────────────────────────
// 消费线程驱动：Append 累积批次，FlushIfDue 按 batch_size / batch_ms
// 触发一事务写入；prepared statement 复用；WAL + synchronous=NORMAL +
// busy_timeout=5000。event_id 为精简 ULID（48bit ms + 80bit 随机，
// Crockford base32 26 字符）；host_id = hostname + boot_id。
class EventStore {
public:
    EventStore(const std::string& db_path, int batch_size = 500, int batch_ms = 200);
    ~EventStore();

    EventStore(const EventStore&) = delete;
    EventStore& operator=(const EventStore&) = delete;

    bool ok() const { return db_ != nullptr; }

    // 累积一条待写入事件（生成 event_id，提取列）。达到 batch_size 立即刷新。
    // 单线程调用（消费线程）。
    void Append(const EventRecord& rec);

    // 缓冲非空且距上次刷新 >= batch_ms 时刷新一事务
    void FlushIfDue();

    // 强制刷新（缓冲非空时一事务写入）
    void Flush();

    unsigned long long stored_count() const { return stored_.load(std::memory_order_relaxed); }
    // 事务写入失败（BEGIN/insert/COMMIT 任一失败 ROLLBACK）累计丢弃的行数
    unsigned long long failed_count() const { return failed_.load(std::memory_order_relaxed); }
    const std::string& host_id() const { return host_id_; }
    const std::string& db_path() const { return db_path_; }

    // 端到端延迟（落库完成 - 事件 ts_ns），刷新时记录
    LatencyStats::Summary e2e_latency_summary() const { return e2e_lat_.summarize(); }

private:
    struct PendingRow {
        std::string event_id;
        unsigned long long ts_ns = 0;
        std::string category;
        std::string action;
        int priority = 0;
        std::string severity;
        unsigned int pid = 0;
        unsigned int ppid = 0;
        unsigned int uid = 0;
        std::string exe;
        std::string container_id;
        std::string payload;
    };

    void Open();
    void CreateSchema();
    void Prepare();
    void WriteBatch();

    std::string db_path_;
    int batch_size_ = 500;
    int batch_ms_ = 200;

    sqlite3* db_ = nullptr;
    sqlite3_stmt* insert_stmt_ = nullptr;
    std::vector<PendingRow> pending_;
    // atomic：stats 同步在主循环线程读取，写仅在消费线程
    std::atomic<unsigned long long> stored_{0};
    std::atomic<unsigned long long> failed_{0};   // ROLLBACK 丢弃的行数累计（store_failed 计数器）
    std::string host_id_;

    // 上次刷新时间（steady_clock ms），用于 batch_ms 判定
    long long last_flush_ms_ = 0;

    LatencyStats e2e_lat_;  // 仅消费线程写
};

// 生成一个精简 ULID（26 字符 Crockford base32）
std::string GenerateUlid();

// category -> 字符串（file/process/priv/ns/network/dns）
const char* CategoryToString(unsigned char category);

// (category, action) -> action 字符串（read/exec/setuid/mount/connect/query...）
const char* ActionToString(unsigned char category, unsigned char action);

// category -> severity 字符串（priv/ns=medium，其余 low）
const char* CategoryToSeverity(unsigned char category);
