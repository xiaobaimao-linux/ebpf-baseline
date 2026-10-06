#include "event_store.hpp"

#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#include <spdlog/spdlog.h>

// BPF 事件头：仅取常量定义（数值宏，无 BPF 依赖），用于 action 列映射
#include "event.h"
#include "net_event.h"
#include "priv_event.h"
#include "proc_event.h"

#include "commonfun.hpp"   // GetHostname

namespace {

long long now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<long long>(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
}

unsigned long long now_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<unsigned long long>(ts.tv_sec) * 1000000000ULL +
           static_cast<unsigned long long>(ts.tv_nsec);
}

// 读 /proc/sys/kernel/random/boot_id，失败返回空串
std::string boot_id() {
    std::string id;
    std::ifstream f("/proc/sys/kernel/random/boot_id");
    if (f.is_open())
        std::getline(f, id);
    return id;
}

// Crockford base32 字母表（去 I L O U）
constexpr char kCrockford[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

// 16 字节（48bit ms + 80bit 随机）按 ULID 规范编码为 26 字符
void UlidEncode(const unsigned char b[16], char out[26]) {
    out[0]  = kCrockford[(b[0] & 0xE0) >> 5];
    out[1]  = kCrockford[b[0] & 0x1F];
    out[2]  = kCrockford[(b[1] & 0xF8) >> 3];
    out[3]  = kCrockford[((b[1] & 0x07) << 2) | ((b[2] & 0xC0) >> 6)];
    out[4]  = kCrockford[(b[2] & 0x3E) >> 1];
    out[5]  = kCrockford[((b[2] & 0x01) << 4) | ((b[3] & 0xF0) >> 4)];
    out[6]  = kCrockford[((b[3] & 0x0F) << 1) | ((b[4] & 0x80) >> 7)];
    out[7]  = kCrockford[(b[4] & 0x7C) >> 2];
    out[8]  = kCrockford[((b[4] & 0x03) << 3) | ((b[5] & 0xE0) >> 5)];
    out[9]  = kCrockford[b[5] & 0x1F];
    out[10] = kCrockford[(b[6] & 0xF8) >> 3];
    out[11] = kCrockford[((b[6] & 0x07) << 2) | ((b[7] & 0xC0) >> 6)];
    out[12] = kCrockford[(b[7] & 0x3E) >> 1];
    out[13] = kCrockford[((b[7] & 0x01) << 4) | ((b[8] & 0xF0) >> 4)];
    out[14] = kCrockford[((b[8] & 0x0F) << 1) | ((b[9] & 0x80) >> 7)];
    out[15] = kCrockford[(b[9] & 0x7C) >> 2];
    out[16] = kCrockford[((b[9] & 0x03) << 3) | ((b[10] & 0xE0) >> 5)];
    out[17] = kCrockford[b[10] & 0x1F];
    out[18] = kCrockford[(b[11] & 0xF8) >> 3];
    out[19] = kCrockford[((b[11] & 0x07) << 2) | ((b[12] & 0xC0) >> 6)];
    out[20] = kCrockford[(b[12] & 0x3E) >> 1];
    out[21] = kCrockford[((b[12] & 0x01) << 4) | ((b[13] & 0xF0) >> 4)];
    out[22] = kCrockford[((b[13] & 0x0F) << 1) | ((b[14] & 0x80) >> 7)];
    out[23] = kCrockford[(b[14] & 0x7C) >> 2];
    out[24] = kCrockford[((b[14] & 0x03) << 3) | ((b[15] & 0xE0) >> 5)];
    out[25] = kCrockford[b[15] & 0x1F];
}

} // namespace

std::string GenerateUlid() {
    unsigned char b[16];
    // 48bit 毫秒时间戳（大端）
    const unsigned long long ms =
        static_cast<unsigned long long>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
    b[0] = static_cast<unsigned char>((ms >> 40) & 0xFF);
    b[1] = static_cast<unsigned char>((ms >> 32) & 0xFF);
    b[2] = static_cast<unsigned char>((ms >> 24) & 0xFF);
    b[3] = static_cast<unsigned char>((ms >> 16) & 0xFF);
    b[4] = static_cast<unsigned char>((ms >> 8) & 0xFF);
    b[5] = static_cast<unsigned char>(ms & 0xFF);
    // 80bit 随机
    size_t got = 0;
    while (got < 10) {
        ssize_t n = getrandom(b + 6 + got, 10 - got, 0);
        if (n <= 0)
            break;
        got += static_cast<size_t>(n);
    }
    for (size_t i = got; i < 10; i++)  // getrandom 失败时退化为地址/时间混合
        b[6 + i] = static_cast<unsigned char>((now_ns() >> (i * 8)) ^ (reinterpret_cast<uintptr_t>(&b) >> (i % 8)));

    char out[26];
    UlidEncode(b, out);
    return std::string(out, 26);
}

const char* CategoryToString(unsigned char category) {
    switch (category) {
    case CAT_FILE:    return "file";
    case CAT_PROCESS: return "process";
    case CAT_PRIV:    return "priv";
    case CAT_NS:      return "ns";
    case CAT_NETWORK: return "network";
    case CAT_DNS:     return "dns";
    default:          return "unknown";
    }
}

const char* ActionToString(unsigned char category, unsigned char action) {
    switch (category) {
    case CAT_FILE:
        switch (action) {
        case EVENT_READ:   return "read";
        case EVENT_WRITE:  return "write";
        case EVENT_CHMOD:  return "chmod";
        case EVENT_CHOWN:  return "chown";
        case EVENT_UNLINK: return "unlink";
        case EVENT_RENAME: return "rename";
        case EVENT_MMAP:   return "mmap";
        default:           return "access";
        }
    case CAT_PROCESS:
        switch (action) {
        case PROC_KIND_FORK: return "fork";
        case PROC_KIND_EXEC: return "exec";
        case PROC_KIND_EXIT: return "exit";
        default:             return "unknown";
        }
    case CAT_PRIV:
        switch (action) {
        case PRIV_KIND_SETUID:      return "setuid";
        case PRIV_KIND_SETGID:      return "setgid";
        case PRIV_KIND_CAPSET:      return "capset";
        case PRIV_KIND_PTRACE:      return "ptrace";
        case PRIV_KIND_MODULE_LOAD: return "module_load";
        default:                    return "unknown";
        }
    case CAT_NS:
        switch (action) {
        case PRIV_KIND_MOUNT:   return "mount";
        case PRIV_KIND_UNSHARE: return "unshare";
        case PRIV_KIND_SETNS:   return "setns";
        default:                return "unknown";
        }
    case CAT_NETWORK:
        switch (action) {
        case NET_EVENT_CONNECT: return "connect";
        case NET_EVENT_ACCEPT:  return "accept";
        case NET_EVENT_BIND:    return "bind";
        default:                return "unknown";
        }
    case CAT_DNS:
        return "query";
    default:
        return "unknown";
    }
}

const char* CategoryToSeverity(unsigned char category) {
    switch (category) {
    case CAT_PRIV:
    case CAT_NS:
        return "medium";
    default:
        return "low";
    }
}

// ── EventStore ────────────────────────────────────────────────────

EventStore::EventStore(const std::string& db_path, int batch_size, int batch_ms)
    : db_path_(db_path), batch_size_(batch_size > 0 ? batch_size : 500),
      batch_ms_(batch_ms > 0 ? batch_ms : 200) {
    Open();
    if (db_) {
        CreateSchema();
        Prepare();
    }
    host_id_ = GetHostname() + "-" + boot_id();
    last_flush_ms_ = now_ms();
}

EventStore::~EventStore() {
    Flush();
    if (insert_stmt_)
        sqlite3_finalize(insert_stmt_);
    if (db_)
        sqlite3_close(db_);
}

void EventStore::Open() {
    const std::filesystem::path path(db_path_);
    if (path.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(path.parent_path(), ec);
        if (ec) {
            spdlog::error("[event_store] failed to create db dir: {}", ec.message());
            return;
        }
    }
    if (sqlite3_open(db_path_.c_str(), &db_) != SQLITE_OK) {
        spdlog::error("[event_store] failed to open db {}: {}", db_path_,
                      db_ ? sqlite3_errmsg(db_) : "null");
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return;
    }
    // WAL + synchronous=NORMAL + busy_timeout=5000（并发查询不被写阻塞）
    char* err = nullptr;
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, &err);
    sqlite3_free(err);
    err = nullptr;
    sqlite3_exec(db_, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, &err);
    sqlite3_free(err);
    sqlite3_busy_timeout(db_, 5000);
}

void EventStore::CreateSchema() {
    const char* sql = R"SQL(
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE,
            ts_ns INTEGER,
            category TEXT,
            action TEXT,
            priority INTEGER,
            severity TEXT,
            pid INTEGER,
            ppid INTEGER,
            uid INTEGER,
            exe TEXT,
            container_id TEXT,
            host_id TEXT,
            payload TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_ns);
        CREATE INDEX IF NOT EXISTS idx_events_category_ts ON events(category, ts_ns);
        CREATE INDEX IF NOT EXISTS idx_events_container_ts ON events(container_id, ts_ns);
        CREATE INDEX IF NOT EXISTS idx_events_exe_ts ON events(exe, ts_ns);
    )SQL";
    char* err = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        spdlog::error("[event_store] failed to create schema: {}",
                      err ? err : sqlite3_errmsg(db_));
        sqlite3_free(err);
    }
}

void EventStore::Prepare() {
    const char* sql =
        "INSERT INTO events (event_id, ts_ns, category, action, priority, severity,"
        " pid, ppid, uid, exe, container_id, host_id, payload)"
        " VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13);";
    if (sqlite3_prepare_v2(db_, sql, -1, &insert_stmt_, nullptr) != SQLITE_OK) {
        spdlog::error("[event_store] failed to prepare insert: {}", sqlite3_errmsg(db_));
        insert_stmt_ = nullptr;
    }
}

void EventStore::Append(const EventRecord& rec, const char* payload, size_t payload_len) {
    if (!db_ || !insert_stmt_)
        return;

    PendingRow row;
    row.event_id = GenerateUlid();
    row.ts_ns = rec.ts_ns;
    row.category = CategoryToString(rec.category);
    row.action = ActionToString(rec.category, rec.action);
    row.priority = rec.priority;
    row.severity = CategoryToSeverity(rec.category);
    row.pid = rec.pid;
    row.ppid = rec.ppid;
    row.uid = rec.uid;
    row.exe.assign(rec.exe, strnlen(rec.exe, sizeof(rec.exe)));
    row.container_id.assign(rec.container_id, strnlen(rec.container_id, sizeof(rec.container_id)));
    row.payload.assign(payload, payload_len);

    pending_.push_back(std::move(row));

    if (static_cast<int>(pending_.size()) >= batch_size_)
        Flush();
}

void EventStore::FlushIfDue() {
    if (pending_.empty())
        return;
    if (now_ms() - last_flush_ms_ >= batch_ms_)
        Flush();
}

void EventStore::Flush() {
    if (!db_ || !insert_stmt_ || pending_.empty())
        return;

    WriteBatch();
    pending_.clear();
    // 容量随历史峰值驻留：远超稳态批量时归还（R13 内存收敛）
    if (pending_.capacity() > static_cast<size_t>(batch_size_) * 4)
        std::vector<PendingRow>().swap(pending_);
    last_flush_ms_ = now_ms();
}

void EventStore::WriteBatch() {
    char* err = nullptr;
    if (sqlite3_exec(db_, "BEGIN;", nullptr, nullptr, &err) != SQLITE_OK) {
        sqlite3_free(err);
        spdlog::error("[event_store] BEGIN failed: {}", sqlite3_errmsg(db_));
        failed_ += pending_.size();
        return;
    }

    const unsigned long long flush_ts = now_ns();
    unsigned long long batch_stored = 0;
    for (const auto& row : pending_) {
        sqlite3_bind_text(insert_stmt_, 1, row.event_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(insert_stmt_, 2, static_cast<long long>(row.ts_ns));
        sqlite3_bind_text(insert_stmt_, 3, row.category.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(insert_stmt_, 4, row.action.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(insert_stmt_, 5, row.priority);
        sqlite3_bind_text(insert_stmt_, 6, row.severity.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(insert_stmt_, 7, static_cast<int>(row.pid));
        sqlite3_bind_int(insert_stmt_, 8, static_cast<int>(row.ppid));
        sqlite3_bind_int(insert_stmt_, 9, static_cast<int>(row.uid));
        sqlite3_bind_text(insert_stmt_, 10, row.exe.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(insert_stmt_, 11, row.container_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(insert_stmt_, 12, host_id_.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(insert_stmt_, 13, row.payload.c_str(), -1, SQLITE_TRANSIENT);

        int rc = sqlite3_step(insert_stmt_);
        if (rc != SQLITE_DONE) {
            spdlog::error("[event_store] insert failed: {}", sqlite3_errmsg(db_));
            sqlite3_reset(insert_stmt_);
            sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
            failed_ += pending_.size();   // 整批回滚，全部计入丢失
            return;
        }
        sqlite3_reset(insert_stmt_);

        // 端到端延迟：落库完成时间 - 事件时间
        if (flush_ts >= row.ts_ns)
            e2e_lat_.add(flush_ts - row.ts_ns);
        batch_stored++;
    }

    if (sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, &err) != SQLITE_OK) {
        sqlite3_free(err);
        spdlog::error("[event_store] COMMIT failed: {}", sqlite3_errmsg(db_));
        failed_ += pending_.size();   // COMMIT 失败整批未落库
        return;
    }
    stored_ += batch_stored;   // COMMIT 成功才计入，避免 ROLLBACK 虚增
}
