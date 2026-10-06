#include "baseline_db.hpp"
#include "commonfun.hpp"

#include <spdlog/spdlog.h>

#include <sqlite3.h>
#include <cstring>
#include <filesystem>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

// alerts 表列探测结果（老库兼容：缺列查询侧补空串）
struct AlertsColumns {
    bool user_name = false;
    bool uid = false;
    bool exe = false;
    bool container_id = false;
    bool ancestors = false;
    bool attack = false;
};

// PRAGMA table_info 探测 alerts 表已有列
AlertsColumns ProbeAlertsColumns(sqlite3* db) {
    AlertsColumns cols;
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, "PRAGMA table_info(alerts);", -1, &stmt, nullptr) != SQLITE_OK)
        return cols;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* name = sqlite3_column_text(stmt, 1);
        if (name == nullptr)
            continue;
        const std::string col = reinterpret_cast<const char*>(name);
        if (col == "user_name")         cols.user_name = true;
        else if (col == "uid")          cols.uid = true;
        else if (col == "exe")          cols.exe = true;
        else if (col == "container_id") cols.container_id = true;
        else if (col == "ancestors")    cols.ancestors = true;
        else if (col == "attack")       cols.attack = true;
    }
    sqlite3_finalize(stmt);
    return cols;
}

// 组装 alerts 查询 SELECT 列表：既有 14 列顺序逐字节不变，进程上下文扩展列
// （exe/container_id/ancestors）追加在 recorded_at 之后；老库缺列补空串。
std::string BuildAlertsSelect(const AlertsColumns& cols) {
    std::string sql =
        "SELECT rule_id, rule_name, severity, file_path, event_type, process_name, pid, ";
    sql += (cols.user_name && cols.uid) ? "user_name, uid, " : "'' AS user_name, '' AS uid, ";
    sql += "expected, actual, action_taken, dingtalk_sent, recorded_at, ";
    sql += cols.exe ? "exe, " : "'' AS exe, ";
    sql += cols.container_id ? "container_id, " : "'' AS container_id, ";
    sql += cols.ancestors ? "ancestors, " : "'' AS ancestors, ";
    sql += cols.attack ? "attack" : "'' AS attack";
    return sql;
}

} // namespace

BaselineDB::BaselineDB(const std::string &db_path) {
    const std::filesystem::path path(db_path);
    if (path.has_parent_path()) {
        std::error_code ec;
        std::filesystem::create_directories(path.parent_path(), ec);
        if (ec) {
            throw std::runtime_error("Failed to create database directory: " + ec.message());
        }
    }

    if (sqlite3_open(db_path.c_str(), &db_) != SQLITE_OK) {
        throw std::runtime_error("Failed to open database: " + std::string(sqlite3_errmsg(db_)));
    }

    setWAL();
    InitTable();
}

void BaselineDB::setWAL() {
    const char *sql_wal = "PRAGMA journal_mode=WAL;";
    char *err_msg = nullptr;
    const int rc = sqlite3_exec(db_, sql_wal, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::debug("set sqlite WAL failed: {}", err_msg != nullptr ? err_msg : sqlite3_errmsg(db_));
    }
    sqlite3_free(err_msg);
}

BaselineDB::~BaselineDB() {
    sqlite3_close(db_);
}

void BaselineDB::InitTable() {
    const char *sql = R"SQL(
        CREATE TABLE IF NOT EXISTS baselines (
            file_path TEXT PRIMARY KEY,
            hash TEXT,
            permission TEXT,
            owner TEXT,
            grp TEXT,
            recorded_at TEXT
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT NOT NULL,
            rule_name TEXT,
            severity TEXT,
            file_path TEXT NOT NULL,
            event_type TEXT,
            process_name TEXT,
            pid INTEGER,
            user_name TEXT,
            uid TEXT,
            expected TEXT,
            actual TEXT,
            action_taken TEXT,
            dingtalk_sent INTEGER DEFAULT 0,
            recorded_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(recorded_at);
        CREATE TABLE IF NOT EXISTS baseline_entries (
            file_path TEXT PRIMARY KEY,
            file_type TEXT NOT NULL DEFAULT 'regular',
            hash TEXT NOT NULL,
            permission TEXT NOT NULL,
            uid INTEGER NOT NULL DEFAULT 0,
            gid INTEGER NOT NULL DEFAULT 0,
            owner TEXT,
            grp TEXT,
            file_size INTEGER NOT NULL DEFAULT 0,
            mtime INTEGER NOT NULL DEFAULT 0,
            snapshot_id TEXT NOT NULL,
            label TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS baseline_snapshots (
            snapshot_id TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT NOT NULL,
            status TEXT NOT NULL,
            roots TEXT NOT NULL,
            excludes TEXT NOT NULL,
            recursive INTEGER NOT NULL,
            scanned_count INTEGER NOT NULL DEFAULT 0,
            added_count INTEGER NOT NULL DEFAULT 0,
            modified_count INTEGER NOT NULL DEFAULT 0,
            removed_count INTEGER NOT NULL DEFAULT 0,
            unchanged_count INTEGER NOT NULL DEFAULT 0,
            error_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS baseline_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id TEXT NOT NULL,
            label TEXT NOT NULL,
            file_path TEXT NOT NULL,
            change_type TEXT NOT NULL,
            old_file_type TEXT,
            old_hash TEXT,
            old_permission TEXT,
            old_uid INTEGER,
            old_gid INTEGER,
            old_owner TEXT,
            old_grp TEXT,
            old_file_size INTEGER,
            old_mtime INTEGER,
            new_file_type TEXT,
            new_hash TEXT,
            new_permission TEXT,
            new_uid INTEGER,
            new_gid INTEGER,
            new_owner TEXT,
            new_grp TEXT,
            new_file_size INTEGER,
            new_mtime INTEGER,
            changed_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_baseline_audit_path_time
            ON baseline_audit(file_path, changed_at);
        CREATE INDEX IF NOT EXISTS idx_baseline_audit_snapshot
            ON baseline_audit(snapshot_id);
        CREATE INDEX IF NOT EXISTS idx_baseline_snapshots_label
            ON baseline_snapshots(label, started_at);
    )SQL";
    char *err_msg = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err_msg) != SQLITE_OK) {
        const std::string error = err_msg != nullptr ? err_msg : sqlite3_errmsg(db_);
        sqlite3_free(err_msg);
        throw std::runtime_error("Failed to initialize database: " + error);
    }

    // 兼容旧版 alerts 表：重复执行 ALTER TABLE 时忽略 duplicate column 错误。
    sqlite3_exec(db_, "ALTER TABLE alerts ADD COLUMN user_name TEXT DEFAULT '';", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "ALTER TABLE alerts ADD COLUMN uid TEXT DEFAULT '';", nullptr, nullptr, nullptr);

    // 进程上下文扩展列（M0-1）：PRAGMA table_info 探测，缺列才 ALTER 补加。
    // 老库首次打开即完成迁移；ALTER 失败（极端场景）由查询侧补空串兜底。
    const AlertsColumns alerts_cols = ProbeAlertsColumns(db_);
    if (!alerts_cols.exe)
        sqlite3_exec(db_, "ALTER TABLE alerts ADD COLUMN exe TEXT;", nullptr, nullptr, nullptr);
    if (!alerts_cols.container_id)
        sqlite3_exec(db_, "ALTER TABLE alerts ADD COLUMN container_id TEXT;", nullptr, nullptr, nullptr);
    if (!alerts_cols.ancestors)
        sqlite3_exec(db_, "ALTER TABLE alerts ADD COLUMN ancestors TEXT;", nullptr, nullptr, nullptr);
    if (!alerts_cols.attack)
        sqlite3_exec(db_, "ALTER TABLE alerts ADD COLUMN attack TEXT;", nullptr, nullptr, nullptr);

    const char *copy_sql = R"SQL(
        INSERT OR IGNORE INTO baseline_entries
        (file_path, file_type, hash, permission, uid, gid, owner, grp,
         file_size, mtime, snapshot_id, label, recorded_at)
        SELECT file_path, 'regular', hash, permission,
               CASE WHEN owner GLOB '[0-9]*' THEN CAST(owner AS INTEGER) ELSE 0 END,
               CASE WHEN grp GLOB '[0-9]*' THEN CAST(grp AS INTEGER) ELSE 0 END,
               owner, grp, 0, 0, 'legacy-migration', 'default', recorded_at
        FROM baselines;
    )SQL";
    if (sqlite3_exec(db_, copy_sql, nullptr, nullptr, &err_msg) != SQLITE_OK) {
        // 只读打开（如普通用户读 root 拥有的库）时迁移必然失败：降级为警告，
        // 读路径（report/alerts/list）继续可用；库后续以可写方式打开时迁移会补跑
        // （INSERT OR IGNORE 幂等）。不可视为致命错误，否则 CLI 直接 core dump。
        const std::string error = err_msg != nullptr ? err_msg : sqlite3_errmsg(db_);
        sqlite3_free(err_msg);
        spdlog::warn("[baseline_db] legacy baselines migration skipped: {}", error);
    }

    // M1-2 assets 表：独立执行。只读打开（非 root 打开 root 拥有的旧库）时
    // CREATE TABLE 需要写权限，降级为警告——读路径（alerts/report/asset list）
    // 继续可用；库后续以可写方式打开时自动补建（CREATE TABLE IF NOT EXISTS 幂等）。
    const char *assets_sql = R"SQL(
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_type TEXT NOT NULL,
            name TEXT NOT NULL,
            detail_json TEXT NOT NULL DEFAULT '',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(asset_type, name)
        );
        CREATE INDEX IF NOT EXISTS idx_assets_type_name ON assets(asset_type, name);
    )SQL";
    if (sqlite3_exec(db_, assets_sql, nullptr, nullptr, &err_msg) != SQLITE_OK) {
        const std::string error = err_msg != nullptr ? err_msg : sqlite3_errmsg(db_);
        sqlite3_free(err_msg);
        spdlog::warn("[baseline_db] assets table init skipped: {}", error);
    }
}

bool BaselineDB::ApplySnapshot(const std::string& snapshot_id,
                               const std::string& label,
                               const std::vector<SnapshotEntry>& entries,
                               const std::vector<SnapshotScope>& scopes,
                               const std::vector<std::string>& excludes,
                               bool recursive,
                               const std::string& roots_text,
                               const std::string& excludes_text,
                               const std::string& started_at,
                               const std::string& finished_at,
                               SnapshotStats& stats,
                               std::string& error) {
    auto exec = [&](const char* sql) {
        char* err_msg = nullptr;
        const int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &err_msg);
        if (rc != SQLITE_OK) {
            error = err_msg != nullptr ? err_msg : sqlite3_errmsg(db_);
            sqlite3_free(err_msg);
            return false;
        }
        return true;
    };
    auto rollback = [&]() {
        sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
    };
    auto bind_text = [](sqlite3_stmt* stmt, int index, const std::string& value) {
        return sqlite3_bind_text(stmt, index, value.c_str(), -1, SQLITE_TRANSIENT) == SQLITE_OK;
    };
    auto bind_nullable_text = [](sqlite3_stmt* stmt, int index, const std::string& value) {
        if (value.empty()) {
            return sqlite3_bind_null(stmt, index) == SQLITE_OK;
        }
        return sqlite3_bind_text(stmt, index, value.c_str(), -1, SQLITE_TRANSIENT) == SQLITE_OK;
    };

    std::map<std::string, SnapshotEntry> current;
    sqlite3_stmt* read_stmt = nullptr;
    const char* read_sql =
        "SELECT file_path, file_type, hash, permission, uid, gid, owner, grp, file_size, mtime "
        "FROM baseline_entries;";
    if (sqlite3_prepare_v2(db_, read_sql, -1, &read_stmt, nullptr) != SQLITE_OK) {
        error = sqlite3_errmsg(db_);
        return false;
    }
    while (sqlite3_step(read_stmt) == SQLITE_ROW) {
        SnapshotEntry entry;
        entry.file_path = reinterpret_cast<const char*>(sqlite3_column_text(read_stmt, 0));
        entry.file_type = reinterpret_cast<const char*>(sqlite3_column_text(read_stmt, 1));
        entry.hash = reinterpret_cast<const char*>(sqlite3_column_text(read_stmt, 2));
        entry.permission = reinterpret_cast<const char*>(sqlite3_column_text(read_stmt, 3));
        entry.uid = sqlite3_column_int64(read_stmt, 4);
        entry.gid = sqlite3_column_int64(read_stmt, 5);
        const auto* owner = sqlite3_column_text(read_stmt, 6);
        const auto* grp = sqlite3_column_text(read_stmt, 7);
        entry.owner = owner != nullptr ? reinterpret_cast<const char*>(owner) : "";
        entry.grp = grp != nullptr ? reinterpret_cast<const char*>(grp) : "";
        entry.file_size = sqlite3_column_int64(read_stmt, 8);
        entry.mtime = sqlite3_column_int64(read_stmt, 9);
        current.emplace(entry.file_path, std::move(entry));
    }
    sqlite3_finalize(read_stmt);

    std::map<std::string, SnapshotEntry> scanned;
    for (const auto& entry : entries) {
        scanned[entry.file_path] = entry;
    }

    const auto under = [](const std::string& path, const SnapshotScope& scope) {
        if (scope.exact_file) {
            return path == scope.path;
        }
        if (scope.path == path) {
            return true;
        }
        if (!scope.recursive) {
            return std::filesystem::path(path).parent_path().string() == scope.path;
        }
        return path.size() > scope.path.size() &&
               path.compare(0, scope.path.size(), scope.path) == 0 &&
               path[scope.path.size()] == '/';
    };
    const auto excluded = [&](const std::string& path) {
        for (const auto& exclude : excludes) {
            if (path == exclude ||
                (path.size() > exclude.size() && path.compare(0, exclude.size(), exclude) == 0 &&
                 path[exclude.size()] == '/')) {
                return true;
            }
        }
        return false;
    };
    const auto in_scope = [&](const std::string& path) {
        if (excluded(path)) {
            return false;
        }
        for (const auto& scope : scopes) {
            if (under(path, scope)) {
                return true;
            }
        }
        return false;
    };
    for (const auto& [path, old_entry] : current) {
        if (in_scope(path) && scanned.find(path) == scanned.end()) {
            ++stats.removed;
        }
    }

    if (!exec("BEGIN IMMEDIATE;")) {
        return false;
    }

    const char* audit_sql = R"SQL(
        INSERT INTO baseline_audit (
            snapshot_id, label, file_path, change_type,
            old_file_type, old_hash, old_permission, old_uid, old_gid, old_owner, old_grp,
            old_file_size, old_mtime, new_file_type, new_hash, new_permission, new_uid, new_gid,
            new_owner, new_grp, new_file_size, new_mtime, changed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    )SQL";
    sqlite3_stmt* audit_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, audit_sql, -1, &audit_stmt, nullptr) != SQLITE_OK) {
        error = sqlite3_errmsg(db_);
        rollback();
        return false;
    }

    const auto write_audit = [&](const std::string& type, const std::string& path,
                                const SnapshotEntry* old_entry, const SnapshotEntry* new_entry) {
        sqlite3_reset(audit_stmt);
        sqlite3_clear_bindings(audit_stmt);
        int index = 1;
        bool ok = bind_text(audit_stmt, index++, snapshot_id) && bind_text(audit_stmt, index++, label) &&
                  bind_text(audit_stmt, index++, path) && bind_text(audit_stmt, index++, type);
        const auto bind_old = [&](const SnapshotEntry* entry) {
            if (!entry) {
                for (int i = 0; i < 9; ++i) {
                    if (sqlite3_bind_null(audit_stmt, index++) != SQLITE_OK) return false;
                }
                return true;
            }
            return bind_text(audit_stmt, index++, entry->file_type) && bind_text(audit_stmt, index++, entry->hash) &&
                   bind_text(audit_stmt, index++, entry->permission) && sqlite3_bind_int64(audit_stmt, index++, entry->uid) == SQLITE_OK &&
                   sqlite3_bind_int64(audit_stmt, index++, entry->gid) == SQLITE_OK && bind_nullable_text(audit_stmt, index++, entry->owner) &&
                   bind_nullable_text(audit_stmt, index++, entry->grp) && sqlite3_bind_int64(audit_stmt, index++, entry->file_size) == SQLITE_OK &&
                   sqlite3_bind_int64(audit_stmt, index++, entry->mtime) == SQLITE_OK;
        };
        const auto bind_new = [&](const SnapshotEntry* entry) {
            return bind_old(entry);
        };
        ok = ok && bind_old(old_entry) && bind_new(new_entry) && bind_text(audit_stmt, index++, finished_at);
        if (!ok || sqlite3_step(audit_stmt) != SQLITE_DONE) {
            error = sqlite3_errmsg(db_);
            return false;
        }
        return true;
    };

    const char* upsert_sql = R"SQL(
        INSERT INTO baseline_entries
        (file_path, file_type, hash, permission, uid, gid, owner, grp, file_size, mtime,
         snapshot_id, label, recorded_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(file_path) DO UPDATE SET
            file_type=excluded.file_type, hash=excluded.hash, permission=excluded.permission,
            uid=excluded.uid, gid=excluded.gid, owner=excluded.owner, grp=excluded.grp,
            file_size=excluded.file_size, mtime=excluded.mtime, snapshot_id=excluded.snapshot_id,
            label=excluded.label, recorded_at=excluded.recorded_at;
    )SQL";
    sqlite3_stmt* upsert_stmt = nullptr;
    const char* delete_sql = "DELETE FROM baseline_entries WHERE file_path = ?;";
    sqlite3_stmt* delete_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, upsert_sql, -1, &upsert_stmt, nullptr) != SQLITE_OK ||
        sqlite3_prepare_v2(db_, delete_sql, -1, &delete_stmt, nullptr) != SQLITE_OK) {
        error = sqlite3_errmsg(db_);
        sqlite3_finalize(upsert_stmt);
        sqlite3_finalize(delete_stmt);
        sqlite3_finalize(audit_stmt);
        rollback();
        return false;
    }

    const auto write_entry = [&](const SnapshotEntry& entry) {
        sqlite3_reset(upsert_stmt);
        sqlite3_clear_bindings(upsert_stmt);
        int i = 1;
        return bind_text(upsert_stmt, i++, entry.file_path) && bind_text(upsert_stmt, i++, entry.file_type) &&
               bind_text(upsert_stmt, i++, entry.hash) && bind_text(upsert_stmt, i++, entry.permission) &&
               sqlite3_bind_int64(upsert_stmt, i++, entry.uid) == SQLITE_OK && sqlite3_bind_int64(upsert_stmt, i++, entry.gid) == SQLITE_OK &&
               bind_nullable_text(upsert_stmt, i++, entry.owner) && bind_nullable_text(upsert_stmt, i++, entry.grp) &&
               sqlite3_bind_int64(upsert_stmt, i++, entry.file_size) == SQLITE_OK && sqlite3_bind_int64(upsert_stmt, i++, entry.mtime) == SQLITE_OK &&
               bind_text(upsert_stmt, i++, snapshot_id) && bind_text(upsert_stmt, i++, label) && bind_text(upsert_stmt, i++, finished_at) &&
               sqlite3_step(upsert_stmt) == SQLITE_DONE;
    };
    const auto delete_entry = [&](const std::string& path) {
        sqlite3_reset(delete_stmt);
        sqlite3_clear_bindings(delete_stmt);
        return bind_text(delete_stmt, 1, path) && sqlite3_step(delete_stmt) == SQLITE_DONE;
    };

    for (const auto& [path, entry] : scanned) {
        const auto old_it = current.find(path);
        const SnapshotEntry* old_entry = old_it == current.end() ? nullptr : &old_it->second;
        const bool changed = old_entry == nullptr || old_entry->file_type != entry.file_type ||
                             old_entry->hash != entry.hash || old_entry->permission != entry.permission ||
                             old_entry->uid != entry.uid || old_entry->gid != entry.gid ||
                             old_entry->owner != entry.owner || old_entry->grp != entry.grp ||
                             old_entry->file_size != entry.file_size || old_entry->mtime != entry.mtime;
        if (!changed) {
            ++stats.unchanged;
        } else {
            if (old_entry == nullptr) {
                ++stats.added;
            } else {
                ++stats.modified;
            }
            if (!write_audit(old_entry == nullptr ? "added" : "modified", path, old_entry, &entry) ||
                !write_entry(entry)) {
                error = sqlite3_errmsg(db_);
                sqlite3_finalize(upsert_stmt);
                sqlite3_finalize(delete_stmt);
                sqlite3_finalize(audit_stmt);
                rollback();
                return false;
            }
        }
    }
    for (const auto& [path, old_entry] : current) {
        if (in_scope(path) && scanned.find(path) == scanned.end()) {
            if (!write_audit("removed", path, &old_entry, nullptr) || !delete_entry(path)) {
                error = sqlite3_errmsg(db_);
                sqlite3_finalize(upsert_stmt);
                sqlite3_finalize(delete_stmt);
                sqlite3_finalize(audit_stmt);
                rollback();
                return false;
            }
        }
    }

    const char* snapshot_sql = R"SQL(
        INSERT INTO baseline_snapshots
        (snapshot_id, label, started_at, finished_at, status, roots, excludes, recursive,
         scanned_count, added_count, modified_count, removed_count, unchanged_count, error_count)
        VALUES (?, ?, ?, ?, 'success', ?, ?, ?, ?, ?, ?, ?, ?, ?);
    )SQL";
    sqlite3_stmt* snapshot_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, snapshot_sql, -1, &snapshot_stmt, nullptr) != SQLITE_OK) {
        error = sqlite3_errmsg(db_);
        sqlite3_finalize(upsert_stmt);
        sqlite3_finalize(delete_stmt);
        sqlite3_finalize(audit_stmt);
        rollback();
        return false;
    }
    int i = 1;
    const bool bound = bind_text(snapshot_stmt, i++, snapshot_id) && bind_text(snapshot_stmt, i++, label) &&
                       bind_text(snapshot_stmt, i++, started_at) && bind_text(snapshot_stmt, i++, finished_at) &&
                       bind_text(snapshot_stmt, i++, roots_text) && bind_text(snapshot_stmt, i++, excludes_text) &&
                       sqlite3_bind_int(snapshot_stmt, i++, recursive ? 1 : 0) == SQLITE_OK &&
                       sqlite3_bind_int64(snapshot_stmt, i++, stats.scanned) == SQLITE_OK &&
                       sqlite3_bind_int64(snapshot_stmt, i++, stats.added) == SQLITE_OK &&
                       sqlite3_bind_int64(snapshot_stmt, i++, stats.modified) == SQLITE_OK &&
                       sqlite3_bind_int64(snapshot_stmt, i++, stats.removed) == SQLITE_OK &&
                       sqlite3_bind_int64(snapshot_stmt, i++, stats.unchanged) == SQLITE_OK &&
                       sqlite3_bind_int64(snapshot_stmt, i++, stats.errors) == SQLITE_OK &&
                       sqlite3_step(snapshot_stmt) == SQLITE_DONE;
    if (!bound || !exec("COMMIT;")) {
        if (error.empty()) error = sqlite3_errmsg(db_);
        sqlite3_finalize(snapshot_stmt);
        sqlite3_finalize(upsert_stmt);
        sqlite3_finalize(delete_stmt);
        sqlite3_finalize(audit_stmt);
        rollback();
        return false;
    }
    sqlite3_finalize(snapshot_stmt);
    sqlite3_finalize(upsert_stmt);
    sqlite3_finalize(delete_stmt);
    sqlite3_finalize(audit_stmt);
    stats.scanned = static_cast<std::int64_t>(entries.size());
    return true;
}

std::vector<SnapshotEntry> BaselineDB::GetSnapshotEntries() {
    std::vector<SnapshotEntry> result;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT file_path, file_type, hash, permission, uid, gid, owner, grp, file_size, mtime FROM baseline_entries ORDER BY file_path;";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return result;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        SnapshotEntry entry;
        entry.file_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        entry.file_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        entry.hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        entry.permission = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        entry.uid = sqlite3_column_int64(stmt, 4);
        entry.gid = sqlite3_column_int64(stmt, 5);
        const auto* owner = sqlite3_column_text(stmt, 6);
        const auto* grp = sqlite3_column_text(stmt, 7);
        entry.owner = owner != nullptr ? reinterpret_cast<const char*>(owner) : "";
        entry.grp = grp != nullptr ? reinterpret_cast<const char*>(grp) : "";
        entry.file_size = sqlite3_column_int64(stmt, 8);
        entry.mtime = sqlite3_column_int64(stmt, 9);
        result.push_back(std::move(entry));
    }
    sqlite3_finalize(stmt);
    return result;
}

int BaselineDB::GetBaselineAuditCount() {
    sqlite3_stmt* stmt = nullptr;
    int count = 0;
    if (sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM baseline_audit;", -1, &stmt, nullptr) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return count;
}

// 保存或更新基线
void BaselineDB::SaveBaseline(const BaselineRecord &record) {
    const char *sql = R"(
            INSERT OR REPLACE INTO baselines
            (file_path, hash, permission, owner, grp, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?);
        )";

    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);

    sqlite3_bind_text(stmt, 1, record.file_path.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, record.hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, record.permission.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, record.owner.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, record.grp.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, record.recorded_at.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        spdlog::error("Save baseline failed: {}", sqlite3_errmsg(db_));
    }
    sqlite3_finalize(stmt);
}

// 保存告警记录
void BaselineDB::SaveAlert(const AlertRecord &record) {
    const char *sql = R"(
            INSERT INTO alerts
            (rule_id, rule_name, severity, file_path, event_type,
             process_name, pid, user_name, uid, expected, actual, action_taken,
             dingtalk_sent, recorded_at, exe, container_id, ancestors, attack)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        )";

    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);

    sqlite3_bind_text(stmt, 1, record.rule_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, record.rule_name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, record.severity.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, record.file_path.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, record.event_type.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, record.process_name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 7, record.pid);
    sqlite3_bind_text(stmt, 8, record.user_name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 9, record.uid.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 10, record.expected.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 11, record.actual.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 12, record.action_taken.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 13, record.dingtalk_sent ? 1 : 0);
    sqlite3_bind_text(stmt, 14, record.recorded_at.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 15, record.exe.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 16, record.container_id.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 17, record.ancestors.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 18, record.attack.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        spdlog::error("Save alert failed: {}", sqlite3_errmsg(db_));
    } else {
        spdlog::info("[DB] Alert saved: {} | {} | {}", record.rule_id, record.file_path,
                     record.recorded_at);
    }
    sqlite3_finalize(stmt);
}

// === Retention: 按天数清理 ===
// 返回删除的记录数
int BaselineDB::PurgeAlertsByAge(int retention_days) {
    if (retention_days <= 0) {
        return 0; // 永久保留
    }

    const char *sql = R"(
            DELETE FROM alerts
            WHERE recorded_at < datetime('now', '-' || ? || ' days');
        )";

    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, retention_days);

    int deleted = 0;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        deleted = sqlite3_changes(db_);
    }
    sqlite3_finalize(stmt);
    return deleted;
}

// === Retention: 按数量上限清理（保留最新的N条）===
// 返回删除的记录数
int BaselineDB::PurgeAlertsByCount(int max_records) {
    if (max_records <= 0) {
        return 0; // 不限制
    }

    const char *sql = R"(
            DELETE FROM alerts
            WHERE id NOT IN (
                SELECT id FROM alerts
                ORDER BY recorded_at DESC
                LIMIT ?
            );
        )";

    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, max_records);

    int deleted = 0;
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        deleted = sqlite3_changes(db_);
    }
    sqlite3_finalize(stmt);
    return deleted;
}

// === 回收数据库空间（VACUUM）===
void BaselineDB::Vacuum() {
    sqlite3_exec(db_, "VACUUM;", nullptr, nullptr, nullptr);
}

// === 获取当前告警总数 ===
int BaselineDB::GetAlertCount() {
    const char *sql = "SELECT COUNT(*) FROM alerts;";
    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return count;
}

// 查询基线
BaselineRecord BaselineDB::GetBaseline(const std::string &file_path) {
    const char *sql = "SELECT * FROM baselines WHERE file_path = ?;";
    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, file_path.c_str(), -1, SQLITE_STATIC);

    BaselineRecord record;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        record.file_path = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
        record.hash = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
        record.permission = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
        record.owner = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
        record.grp = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 4));
        record.recorded_at = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5));
    }

    sqlite3_finalize(stmt);
    return record;
}

// 获取所有基线（用于报告生成）
std::vector<BaselineRecord> BaselineDB::GetAllBaselines() {
    const char *sql = "SELECT * FROM baselines ORDER BY file_path;";
    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);

    std::vector<BaselineRecord> results;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        BaselineRecord r;
        r.file_path = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
        r.hash = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
        r.permission = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
        r.owner = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
        r.grp = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 4));
        r.recorded_at = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5));
        results.push_back(r);
    }

    sqlite3_finalize(stmt);
    return results;
}


// 辅助函数：从 sqlite3_stmt 读取一行 AlertRecord（前 14 列为既有字段，
// 顺序逐字节不变；第 15~17 列为进程上下文扩展，老库查询补空串时按列数跳过）
static AlertRecord ReadAlertRecord(sqlite3_stmt* stmt) {
    AlertRecord r;
    r.rule_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    r.rule_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    r.severity = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    r.file_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
    r.event_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
    r.process_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
    r.pid = sqlite3_column_int(stmt, 6);
    r.user_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
    r.uid = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
    r.expected = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
    r.actual = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
    r.action_taken = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
    r.dingtalk_sent = sqlite3_column_int(stmt, 12) != 0;
    r.recorded_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 13));
    // 进程上下文扩展列（NULL 视为空串）
    const int ncols = sqlite3_column_count(stmt);
    if (ncols > 14) {
        const auto* exe = sqlite3_column_text(stmt, 14);
        if (exe != nullptr)
            r.exe = reinterpret_cast<const char*>(exe);
    }
    if (ncols > 15) {
        const auto* cid = sqlite3_column_text(stmt, 15);
        if (cid != nullptr)
            r.container_id = reinterpret_cast<const char*>(cid);
    }
    if (ncols > 16) {
        const auto* anc = sqlite3_column_text(stmt, 16);
        if (anc != nullptr)
            r.ancestors = reinterpret_cast<const char*>(anc);
    }
    if (ncols > 17) {
        const auto* atk = sqlite3_column_text(stmt, 17);
        if (atk != nullptr)
            r.attack = reinterpret_cast<const char*>(atk);
    }
    return r;
}

// 查询告警记录：支持 rule 过滤、今日过滤、数量限制
std::vector<AlertRecord> BaselineDB::GetAlerts(const std::string &rule_filter, int limit,
                                               bool today) {
    const AlertsColumns cols = ProbeAlertsColumns(db_);
    std::string sql = BuildAlertsSelect(cols) + " FROM alerts";

    if (!rule_filter.empty() || today) {
        sql += " WHERE ";
    }

    if (!rule_filter.empty()) {
        sql += "(rule_id = ? OR rule_name = ?)";
    }

    if (today) {
        if (!rule_filter.empty()) {
            sql += " AND ";
        }
        sql += "date(recorded_at) = date('now')";
    }

    sql += " ORDER BY recorded_at DESC LIMIT ?;";

    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);

    int param_idx = 1;
    if (!rule_filter.empty()) {
        sqlite3_bind_text(stmt, param_idx++, rule_filter.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, param_idx++, rule_filter.c_str(), -1, SQLITE_STATIC);
    }
    sqlite3_bind_int(stmt, param_idx, limit);

    std::vector<AlertRecord> results;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        results.push_back(ReadAlertRecord(stmt));
    }

    sqlite3_finalize(stmt);
    return results;
}

std::vector<AlertRecord> BaselineDB::GetMonitorEvents(const std::string& start,
                                                       const std::string& end) {
    const std::string normalized_time = R"(CASE
        WHEN length(recorded_at) >= 17 AND substr(recorded_at, 5, 1) != '-' THEN
            substr(recorded_at, 1, 4) || '-' || substr(recorded_at, 5, 2) || '-' ||
            substr(recorded_at, 7, 2) || ' ' || substr(recorded_at, 10, 2) || ':' ||
            substr(recorded_at, 13, 2) || ':' || substr(recorded_at, 16, 2)
        ELSE replace(substr(recorded_at, 1, 19), 'T', ' ')
    END)";

    std::string sql = BuildAlertsSelect(ProbeAlertsColumns(db_)) + " FROM alerts";
    if (!start.empty() || !end.empty()) {
        sql += " WHERE ";
        if (!start.empty()) {
            sql += "(" + normalized_time + ") >= ?";
        }
        if (!start.empty() && !end.empty()) {
            sql += " AND ";
        }
        if (!end.empty()) {
            sql += "(" + normalized_time + ") <= ?";
        }
    }
    sql += " ORDER BY (" + normalized_time + ") DESC, id DESC;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("Prepare monitor event query failed: {}", sqlite3_errmsg(db_));
        return {};
    }

    int param_idx = 1;
    if (!start.empty()) {
        sqlite3_bind_text(stmt, param_idx++, start.c_str(), -1, SQLITE_TRANSIENT);
    }
    if (!end.empty()) {
        sqlite3_bind_text(stmt, param_idx++, end.c_str(), -1, SQLITE_TRANSIENT);
    }

    std::vector<AlertRecord> results;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        results.push_back(ReadAlertRecord(stmt));
    }
    sqlite3_finalize(stmt);
    return results;
}

// 删除基线条目：精确匹配 + 可选递归前缀匹配，并写入审计记录
int BaselineDB::DeleteBaselineEntries(const std::vector<std::string>& paths, bool recursive,
                                      const std::string& source_label) {
    if (paths.empty()) {
        return 0;
    }

    // 收集需要删除的条目（先读取再删除，以便写入审计记录）
    std::vector<SnapshotEntry> to_delete;

    // 构建 SQL：对每个路径精确匹配；recursive 时对目录路径额外加前缀匹配
    std::string sql = "SELECT file_path, file_type, hash, permission, uid, gid, owner, grp, "
                      "file_size, mtime FROM baseline_entries WHERE ";
    std::vector<std::string> conditions;
    for (const auto& path : paths) {
        if (recursive) {
            // 精确匹配 OR 前缀匹配（path/ 开头）
            conditions.push_back(
                "(file_path = '" + path + "' OR "
                "(file_path LIKE '" + path + "/%' ESCAPE '\\'))");
        } else {
            conditions.push_back("file_path = '" + path + "'");
        }
    }
    for (size_t i = 0; i < conditions.size(); ++i) {
        sql += conditions[i];
        if (i + 1 < conditions.size()) sql += " OR ";
    }
    sql += ";";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("DeleteBaselineEntries: prepare query failed: {}", sqlite3_errmsg(db_));
        return 0;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        SnapshotEntry entry;
        entry.file_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        entry.file_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        entry.hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        entry.permission = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        entry.uid = sqlite3_column_int64(stmt, 4);
        entry.gid = sqlite3_column_int64(stmt, 5);
        const auto* owner = sqlite3_column_text(stmt, 6);
        const auto* grp = sqlite3_column_text(stmt, 7);
        entry.owner = owner != nullptr ? reinterpret_cast<const char*>(owner) : "";
        entry.grp = grp != nullptr ? reinterpret_cast<const char*>(grp) : "";
        entry.file_size = sqlite3_column_int64(stmt, 8);
        entry.mtime = sqlite3_column_int64(stmt, 9);
        to_delete.push_back(std::move(entry));
    }
    sqlite3_finalize(stmt);

    if (to_delete.empty()) {
        return 0;
    }

    // 在事务中执行删除 + 写入审计记录
    char* err_msg = nullptr;
    if (sqlite3_exec(db_, "BEGIN IMMEDIATE;", nullptr, nullptr, &err_msg) != SQLITE_OK) {
        spdlog::error("DeleteBaselineEntries: begin transaction failed: {}",
                      err_msg != nullptr ? err_msg : sqlite3_errmsg(db_));
        sqlite3_free(err_msg);
        return 0;
    }

    // 审计插入语句
    const char* audit_sql = R"SQL(
        INSERT INTO baseline_audit (
            snapshot_id, label, file_path, change_type,
            old_file_type, old_hash, old_permission, old_uid, old_gid, old_owner, old_grp,
            old_file_size, old_mtime,
            new_file_type, new_hash, new_permission, new_uid, new_gid,
            new_owner, new_grp, new_file_size, new_mtime,
            changed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, ?);
    )SQL";
    sqlite3_stmt* audit_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, audit_sql, -1, &audit_stmt, nullptr) != SQLITE_OK) {
        spdlog::error("DeleteBaselineEntries: prepare audit failed: {}", sqlite3_errmsg(db_));
        sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
        return 0;
    }

    // 删除语句
    const char* delete_sql = "DELETE FROM baseline_entries WHERE file_path = ?;";
    sqlite3_stmt* delete_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, delete_sql, -1, &delete_stmt, nullptr) != SQLITE_OK) {
        spdlog::error("DeleteBaselineEntries: prepare delete failed: {}", sqlite3_errmsg(db_));
        sqlite3_finalize(audit_stmt);
        sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
        return 0;
    }

    const std::string now_str = NowIso();

    int deleted_count = 0;
    for (const auto& entry : to_delete) {
        // 写入审计记录
        sqlite3_reset(audit_stmt);
        sqlite3_clear_bindings(audit_stmt);
        int idx = 1;
        sqlite3_bind_text(audit_stmt, idx++, source_label.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(audit_stmt, idx++, source_label.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(audit_stmt, idx++, entry.file_path.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(audit_stmt, idx++, "delete", -1, SQLITE_STATIC);
        // old_* 字段
        sqlite3_bind_text(audit_stmt, idx++, entry.file_type.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(audit_stmt, idx++, entry.hash.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(audit_stmt, idx++, entry.permission.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(audit_stmt, idx++, entry.uid);
        sqlite3_bind_int64(audit_stmt, idx++, entry.gid);
        if (entry.owner.empty()) {
            sqlite3_bind_null(audit_stmt, idx++);
        } else {
            sqlite3_bind_text(audit_stmt, idx++, entry.owner.c_str(), -1, SQLITE_STATIC);
        }
        if (entry.grp.empty()) {
            sqlite3_bind_null(audit_stmt, idx++);
        } else {
            sqlite3_bind_text(audit_stmt, idx++, entry.grp.c_str(), -1, SQLITE_STATIC);
        }
        sqlite3_bind_int64(audit_stmt, idx++, entry.file_size);
        sqlite3_bind_int64(audit_stmt, idx++, entry.mtime);
        // new_* 全部为 NULL（已在 SQL 中硬编码）
        sqlite3_bind_text(audit_stmt, idx++, now_str.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(audit_stmt) != SQLITE_DONE) {
            spdlog::error("DeleteBaselineEntries: audit insert failed for {}: {}",
                          entry.file_path, sqlite3_errmsg(db_));
            sqlite3_finalize(audit_stmt);
            sqlite3_finalize(delete_stmt);
            sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
            return deleted_count;
        }

        // 删除基线条目
        sqlite3_reset(delete_stmt);
        sqlite3_clear_bindings(delete_stmt);
        sqlite3_bind_text(delete_stmt, 1, entry.file_path.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(delete_stmt) != SQLITE_DONE) {
            spdlog::error("DeleteBaselineEntries: delete failed for {}: {}",
                          entry.file_path, sqlite3_errmsg(db_));
            sqlite3_finalize(audit_stmt);
            sqlite3_finalize(delete_stmt);
            sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
            return deleted_count;
        }
        ++deleted_count;
    }

    sqlite3_finalize(audit_stmt);
    sqlite3_finalize(delete_stmt);

    if (sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, &err_msg) != SQLITE_OK) {
        spdlog::error("DeleteBaselineEntries: commit failed: {}",
                      err_msg != nullptr ? err_msg : sqlite3_errmsg(db_));
        sqlite3_free(err_msg);
        return 0;
    }

    return deleted_count;
}

// 分页查询 baseline_entries
ListResult BaselineDB::ListBaselineEntries(const std::string& path_filter,
                                            int limit,
                                            int offset) {
    ListResult result;

    // 1. 查询总数
    std::string count_sql = "SELECT COUNT(*) FROM baseline_entries";
    if (!path_filter.empty()) {
        count_sql += " WHERE file_path LIKE ?";
    }
    count_sql += ";";

    sqlite3_stmt* count_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, count_sql.c_str(), -1, &count_stmt, nullptr) != SQLITE_OK) {
        spdlog::error("ListBaselineEntries: count prepare failed: {}", sqlite3_errmsg(db_));
        return result;
    }
    if (!path_filter.empty()) {
        sqlite3_bind_text(count_stmt, 1, path_filter.c_str(), -1, SQLITE_STATIC);
    }
    if (sqlite3_step(count_stmt) == SQLITE_ROW) {
        result.total_count = sqlite3_column_int64(count_stmt, 0);
    }
    sqlite3_finalize(count_stmt);

    if (result.total_count == 0) {
        return result;
    }

    // 2. 查询当前页数据
    std::string sql = "SELECT file_path, file_type, hash, permission, uid, gid, owner, grp, "
                      "file_size, mtime, snapshot_id, label, recorded_at "
                      "FROM baseline_entries";
    if (!path_filter.empty()) {
        sql += " WHERE file_path LIKE ?";
    }
    sql += " ORDER BY file_path";
    if (limit > 0) {
        sql += " LIMIT ?";
    }
    if (offset > 0) {
        sql += " OFFSET ?";
    }
    sql += ";";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("ListBaselineEntries: query prepare failed: {}", sqlite3_errmsg(db_));
        return result;
    }

    int param_idx = 1;
    if (!path_filter.empty()) {
        sqlite3_bind_text(stmt, param_idx++, path_filter.c_str(), -1, SQLITE_STATIC);
    }
    if (limit > 0) {
        sqlite3_bind_int(stmt, param_idx++, limit);
    }
    if (offset > 0) {
        sqlite3_bind_int(stmt, param_idx++, offset);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ListEntry entry;
        entry.file_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        entry.file_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        entry.hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        entry.permission = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        entry.uid = sqlite3_column_int64(stmt, 4);
        entry.gid = sqlite3_column_int64(stmt, 5);
        const auto* owner = sqlite3_column_text(stmt, 6);
        const auto* grp = sqlite3_column_text(stmt, 7);
        entry.owner = owner != nullptr ? reinterpret_cast<const char*>(owner) : "";
        entry.grp = grp != nullptr ? reinterpret_cast<const char*>(grp) : "";
        entry.file_size = sqlite3_column_int64(stmt, 8);
        entry.mtime = sqlite3_column_int64(stmt, 9);
        entry.snapshot_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
        entry.label = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
        entry.recorded_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
        result.entries.push_back(std::move(entry));
    }
    sqlite3_finalize(stmt);

    return result;
}

// 获取全部基线条目（含快照元信息）
std::vector<CheckEntry> BaselineDB::GetAllBaselineEntries() {
    std::vector<CheckEntry> results;
    const char* sql = "SELECT file_path, file_type, hash, permission, uid, gid, owner, grp, "
                      "file_size, mtime, snapshot_id, label, recorded_at "
                      "FROM baseline_entries ORDER BY file_path;";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("GetAllBaselineEntries: prepare failed: {}", sqlite3_errmsg(db_));
        return results;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CheckEntry entry;
        entry.file_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        entry.file_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        entry.hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        entry.permission = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        entry.uid = sqlite3_column_int64(stmt, 4);
        entry.gid = sqlite3_column_int64(stmt, 5);
        const auto* owner = sqlite3_column_text(stmt, 6);
        const auto* grp = sqlite3_column_text(stmt, 7);
        entry.owner = owner != nullptr ? reinterpret_cast<const char*>(owner) : "";
        entry.grp = grp != nullptr ? reinterpret_cast<const char*>(grp) : "";
        entry.file_size = sqlite3_column_int64(stmt, 8);
        entry.mtime = sqlite3_column_int64(stmt, 9);
        entry.snapshot_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
        entry.label = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
        entry.recorded_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
        results.push_back(std::move(entry));
    }
    sqlite3_finalize(stmt);
    return results;
}

// 查询单条基线条目（按 file_path 精确匹配 baseline_entries 表）
bool BaselineDB::GetBaselineEntry(const std::string& file_path, CheckEntry& out) {
    const char* sql = "SELECT file_path, file_type, hash, permission, uid, gid, "
                      "owner, grp, file_size, mtime, snapshot_id, label, recorded_at "
                      "FROM baseline_entries WHERE file_path = ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("GetBaselineEntry: prepare failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    sqlite3_bind_text(stmt, 1, file_path.c_str(), -1, SQLITE_STATIC);

    bool found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        out.file_path   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        out.file_type   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        out.hash        = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        out.permission  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        out.uid         = sqlite3_column_int64(stmt, 4);
        out.gid         = sqlite3_column_int64(stmt, 5);
        const auto* owner = sqlite3_column_text(stmt, 6);
        const auto* grp   = sqlite3_column_text(stmt, 7);
        out.owner       = owner != nullptr ? reinterpret_cast<const char*>(owner) : "";
        out.grp         = grp   != nullptr ? reinterpret_cast<const char*>(grp)   : "";
        out.file_size   = sqlite3_column_int64(stmt, 8);
        out.mtime       = sqlite3_column_int64(stmt, 9);
        out.snapshot_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
        out.label       = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
        out.recorded_at = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
        found = true;
    }
    sqlite3_finalize(stmt);
    return found;
}

// === M1-2 资产清点 ===

AssetUpsertResult BaselineDB::UpsertAssets(const std::vector<AssetRecord>& assets) {
    AssetUpsertResult result;
    if (assets.empty()) {
        return result;
    }

    const char* insert_sql =
        "INSERT OR IGNORE INTO assets (asset_type, name, detail_json, first_seen, "
        "last_seen) VALUES (?, ?, ?, ?, ?);";
    const char* update_sql =
        "UPDATE assets SET detail_json = ?, last_seen = ? WHERE asset_type = ? AND name = ?;";
    sqlite3_stmt* insert_stmt = nullptr;
    sqlite3_stmt* update_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, insert_sql, -1, &insert_stmt, nullptr) != SQLITE_OK ||
        sqlite3_prepare_v2(db_, update_sql, -1, &update_stmt, nullptr) != SQLITE_OK) {
        sqlite3_finalize(insert_stmt);
        sqlite3_finalize(update_stmt);
        throw std::runtime_error(std::string("UpsertAssets: prepare failed: ") +
                                 sqlite3_errmsg(db_));
    }

    char* err_msg = nullptr;
    if (sqlite3_exec(db_, "BEGIN IMMEDIATE TRANSACTION;", nullptr, nullptr, &err_msg) !=
        SQLITE_OK) {
        const std::string error = err_msg != nullptr ? err_msg : sqlite3_errmsg(db_);
        sqlite3_free(err_msg);
        sqlite3_finalize(insert_stmt);
        sqlite3_finalize(update_stmt);
        throw std::runtime_error("UpsertAssets: begin transaction failed: " + error);
    }

    // 同批次内 (asset_type, name) 重复时保留首条（如端口 SO_REUSEPORT 场景）
    std::set<std::pair<std::string, std::string>> seen_in_batch;
    bool failed = false;
    std::string fail_reason;
    for (const auto& asset : assets) {
        const std::string now = NowIso();
        if (!seen_in_batch.emplace(asset.asset_type, asset.name).second) {
            continue;
        }
        sqlite3_bind_text(insert_stmt, 1, asset.asset_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(insert_stmt, 2, asset.name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(insert_stmt, 3, asset.detail_json.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(insert_stmt, 4, now.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(insert_stmt, 5, now.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(insert_stmt) != SQLITE_DONE) {
            failed = true;
            fail_reason = sqlite3_errmsg(db_);
            break;
        }
        if (sqlite3_changes(db_) > 0) {
            ++result.inserted;
        } else {
            sqlite3_bind_text(update_stmt, 1, asset.detail_json.c_str(), -1,
                              SQLITE_TRANSIENT);
            sqlite3_bind_text(update_stmt, 2, now.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(update_stmt, 3, asset.asset_type.c_str(), -1,
                              SQLITE_TRANSIENT);
            sqlite3_bind_text(update_stmt, 4, asset.name.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(update_stmt) != SQLITE_DONE) {
                failed = true;
                fail_reason = sqlite3_errmsg(db_);
                break;
            }
            ++result.updated;
        }
        sqlite3_reset(insert_stmt);
        sqlite3_reset(update_stmt);
        sqlite3_clear_bindings(insert_stmt);
        sqlite3_clear_bindings(update_stmt);
    }

    if (failed) {
        sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
    } else if (sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, &err_msg) != SQLITE_OK) {
        fail_reason = err_msg != nullptr ? err_msg : sqlite3_errmsg(db_);
        sqlite3_free(err_msg);
        failed = true;
        sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
    }
    sqlite3_finalize(insert_stmt);
    sqlite3_finalize(update_stmt);
    if (failed) {
        throw std::runtime_error("UpsertAssets: " + fail_reason);
    }
    return result;
}

std::int64_t BaselineDB::CountAssets(const std::string& asset_type) {
    const char* sql = asset_type.empty() ? "SELECT COUNT(*) FROM assets;"
                                         : "SELECT COUNT(*) FROM assets WHERE asset_type = ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("CountAssets: prepare failed: {}", sqlite3_errmsg(db_));
        return 0;
    }
    if (!asset_type.empty()) {
        sqlite3_bind_text(stmt, 1, asset_type.c_str(), -1, SQLITE_STATIC);
    }
    std::int64_t count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return count;
}

std::vector<AssetRecord> BaselineDB::GetAssets(const std::string& asset_type,
                                               std::int64_t limit, std::int64_t offset) {
    std::string sql =
        "SELECT id, asset_type, name, detail_json, first_seen, last_seen FROM assets";
    if (!asset_type.empty()) {
        sql += " WHERE asset_type = ?";
    }
    sql += " ORDER BY asset_type, name, id";
    if (limit > 0) {
        sql += " LIMIT ?";
        if (offset > 0) {
            sql += " OFFSET ?";
        }
    }
    sql += ";";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        spdlog::error("GetAssets: prepare failed: {}", sqlite3_errmsg(db_));
        return {};
    }
    int idx = 1;
    if (!asset_type.empty()) {
        sqlite3_bind_text(stmt, idx++, asset_type.c_str(), -1, SQLITE_STATIC);
    }
    if (limit > 0) {
        sqlite3_bind_int64(stmt, idx++, limit);
        if (offset > 0) {
            sqlite3_bind_int64(stmt, idx++, offset);
        }
    }
    std::vector<AssetRecord> records;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        AssetRecord record;
        record.id = sqlite3_column_int64(stmt, 0);
        const auto* type = sqlite3_column_text(stmt, 1);
        const auto* name = sqlite3_column_text(stmt, 2);
        const auto* detail = sqlite3_column_text(stmt, 3);
        const auto* first = sqlite3_column_text(stmt, 4);
        const auto* last = sqlite3_column_text(stmt, 5);
        record.asset_type = type != nullptr ? reinterpret_cast<const char*>(type) : "";
        record.name = name != nullptr ? reinterpret_cast<const char*>(name) : "";
        record.detail_json = detail != nullptr ? reinterpret_cast<const char*>(detail) : "";
        record.first_seen = first != nullptr ? reinterpret_cast<const char*>(first) : "";
        record.last_seen = last != nullptr ? reinterpret_cast<const char*>(last) : "";
        records.push_back(std::move(record));
    }
    sqlite3_finalize(stmt);
    return records;
}
