#include "baseline_db.hpp"

#include <spdlog/spdlog.h>

#include <sqlite3.h>
#include <stdexcept>
#include <string>
#include <vector>

BaselineDB::BaselineDB(const std::string &db_path) {
    // 创建目录
    size_t pos = db_path.find_last_of('/');
    if (pos != std::string::npos) {
        std::string cmd = "mkdir -p " + db_path.substr(0, pos);
        system(cmd.c_str());
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
        // 输出警告日志，但是程序可以继续跑
        spdlog::debug("set sqlite WAL failed: {}", err_msg != nullptr ? err_msg : sqlite3_errmsg(db_));
    }
    sqlite3_free(err_msg);
}

BaselineDB::~BaselineDB() {
    sqlite3_close(db_);
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
             dingtalk_sent, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
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


// 查询告警记录：支持 rule 过滤、今日过滤、数量限制
std::vector<AlertRecord> BaselineDB::GetAlerts(const std::string &rule_filter, int limit,
                                               bool today) {
    bool has_user_name = false;
    bool has_uid = false;

    const char *info_sql = "PRAGMA table_info(alerts);";
    sqlite3_stmt *info_stmt = nullptr;
    sqlite3_prepare_v2(db_, info_sql, -1, &info_stmt, nullptr);
    while (sqlite3_step(info_stmt) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(info_stmt, 1);
        if (name != nullptr) {
            const std::string col = reinterpret_cast<const char *>(name);
            if (col == "user_name") {
                has_user_name = true;
            }
            if (col == "uid") {
                has_uid = true;
            }
        }
    }
    sqlite3_finalize(info_stmt);

    std::string sql;
    if (has_user_name && has_uid) {
        sql = "SELECT rule_id, rule_name, severity, file_path, event_type, process_name, pid, "
              "user_name, uid, expected, actual, action_taken, dingtalk_sent, recorded_at FROM alerts";
    } else {
        sql = "SELECT rule_id, rule_name, severity, file_path, event_type, process_name, pid, "
              "'' AS user_name, '' AS uid, expected, actual, action_taken, dingtalk_sent, recorded_at FROM alerts";
    }

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
        AlertRecord r;
        r.rule_id = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
        r.rule_name = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
        r.severity = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
        r.file_path = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
        r.event_type = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 4));
        r.process_name = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5));
        r.pid = sqlite3_column_int(stmt, 6);
        r.user_name = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 7));
        r.uid = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 8));
        r.expected = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 9));
        r.actual = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 10));
        r.action_taken = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 11));
        r.dingtalk_sent = sqlite3_column_int(stmt, 12) != 0;
        r.recorded_at = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 13));
        results.push_back(r);
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

    std::string sql =
        "SELECT rule_id, rule_name, severity, file_path, event_type, process_name, pid, "
        "user_name, uid, expected, actual, action_taken, dingtalk_sent, recorded_at "
        "FROM alerts";
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
        results.push_back(r);
    }
    sqlite3_finalize(stmt);
    return results;
}
