#pragma once
#include <sqlite3.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <iostream>

struct BaselineRecord {
    std::string file_path;
    std::string hash;           // sha256
    std::string permission;     // 如 "0644"
    std::string owner;          // uid或用户名
    std::string grp;          // gid或组名
    std::string recorded_at;    // ISO 8601时间
};

// 告警记录结构体
struct AlertRecord {
    std::string rule_id;        // 规则ID
    std::string rule_name;      // 规则名称
    std::string severity;       // 严重级别
    std::string file_path;      // 被访问文件路径
    std::string event_type;     // 事件类型: read / write
    std::string process_name;   // 进程名
    int pid = 0;                // 进程PID
    std::string expected;       // 预期值（如权限或哈希）
    std::string actual;         // 实际值
    std::string action_taken;   // 采取的动作: alert / block
    bool dingtalk_sent = false; // 是否成功发送钉钉告警
    std::string recorded_at;    // 记录时间
};

class BaselineDB {
public:
    explicit BaselineDB(const std::string& db_path = "/var/lib/baseline-guard/baseline.db") {
        // 创建目录
        size_t pos = db_path.find_last_of('/');
        if (pos != std::string::npos) {
            std::string cmd = "mkdir -p " + db_path.substr(0, pos);
            system(cmd.c_str());
        }

        if (sqlite3_open(db_path.c_str(), &db_) != SQLITE_OK) {
            throw std::runtime_error("Failed to open database: " + std::string(sqlite3_errmsg(db_)));
        }
        InitTable();
    }

    ~BaselineDB() {
        sqlite3_close(db_);
    }

    // 保存或更新基线
    void SaveBaseline(const BaselineRecord& record) {
        const char* sql = R"(
            INSERT OR REPLACE INTO baselines
            (file_path, hash, permission, owner, grp, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?);
        )";

        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);

        sqlite3_bind_text(stmt, 1, record.file_path.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, record.hash.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, record.permission.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, record.owner.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 5, record.grp.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 6, record.recorded_at.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Save baseline failed: " << sqlite3_errmsg(db_) << std::endl;
        }
        sqlite3_finalize(stmt);
    }

    // 保存告警记录
    void SaveAlert(const AlertRecord& record) {
        const char* sql = R"(
            INSERT INTO alerts
            (rule_id, rule_name, severity, file_path, event_type,
             process_name, pid, expected, actual, action_taken,
             dingtalk_sent, recorded_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        )";

        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);

        sqlite3_bind_text(stmt,  1, record.rule_id.c_str(),      -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt,  2, record.rule_name.c_str(),     -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt,  3, record.severity.c_str(),      -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt,  4, record.file_path.c_str(),     -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt,  5, record.event_type.c_str(),    -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt,  6, record.process_name.c_str(),  -1, SQLITE_STATIC);
        sqlite3_bind_int (stmt,  7, record.pid);
        sqlite3_bind_text(stmt,  8, record.expected.c_str(),      -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt,  9, record.actual.c_str(),        -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 10, record.action_taken.c_str(),  -1, SQLITE_STATIC);
        sqlite3_bind_int (stmt, 11, record.dingtalk_sent ? 1 : 0);
        sqlite3_bind_text(stmt, 12, record.recorded_at.c_str(),   -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Save alert failed: " << sqlite3_errmsg(db_) << std::endl;
        } else {
            std::cout << "[DB] Alert saved: " << record.rule_id
                      << " | " << record.file_path
                      << " | " << record.recorded_at << std::endl;
        }
        sqlite3_finalize(stmt);
    }

    // === Retention: 按天数清理 ===
    // 返回删除的记录数
    int PurgeAlertsByAge(int retention_days) {
        if (retention_days <= 0) {
            return 0;  // 永久保留
        }

        const char* sql = R"(
            DELETE FROM alerts
            WHERE recorded_at < datetime('now', '-' || ? || ' days');
        )";

        sqlite3_stmt* stmt = nullptr;
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
    int PurgeAlertsByCount(int max_records) {
        if (max_records <= 0) {
            return 0;  // 不限制
        }

        const char* sql = R"(
            DELETE FROM alerts
            WHERE id NOT IN (
                SELECT id FROM alerts
                ORDER BY recorded_at DESC
                LIMIT ?
            );
        )";

        sqlite3_stmt* stmt = nullptr;
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
    void Vacuum() {
        sqlite3_exec(db_, "VACUUM;", nullptr, nullptr, nullptr);
    }

    // === 获取当前告警总数 ===
    int GetAlertCount() {
        const char* sql = "SELECT COUNT(*) FROM alerts;";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);

        int count = 0;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            count = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
        return count;
    }

    // 查询基线
    BaselineRecord GetBaseline(const std::string& file_path) {
        const char* sql = "SELECT * FROM baselines WHERE file_path = ?;";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
        sqlite3_bind_text(stmt, 1, file_path.c_str(), -1, SQLITE_STATIC);

        BaselineRecord record;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            record.file_path = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            record.hash      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            record.permission= reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            record.owner     = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            record.grp     = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
            record.recorded_at=reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        }

        sqlite3_finalize(stmt);
        return record;
    }

    // 获取所有基线（用于报告生成）
    std::vector<BaselineRecord> GetAllBaselines() {
        const char* sql = "SELECT * FROM baselines ORDER BY file_path;";
        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);

        std::vector<BaselineRecord> results;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            BaselineRecord r;
            r.file_path  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            r.hash       = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            r.permission = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            r.owner      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            r.grp      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
            r.recorded_at= reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
            results.push_back(r);
        }

        sqlite3_finalize(stmt);
        return results;
    }

    // 查询告警记录
    std::vector<AlertRecord> GetAlerts(const std::string& rule_id = "",
                                        int limit = 100) {
        std::string sql = "SELECT * FROM alerts";
        if (!rule_id.empty()) {
            sql += " WHERE rule_id = ?";
        }
        sql += " ORDER BY recorded_at DESC LIMIT ?;";

        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);

        int param_idx = 1;
        if (!rule_id.empty()) {
            sqlite3_bind_text(stmt, param_idx++, rule_id.c_str(), -1, SQLITE_STATIC);
        }
        sqlite3_bind_int(stmt, param_idx, limit);

        std::vector<AlertRecord> results;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            AlertRecord r;
            r.rule_id       = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            r.rule_name     = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            r.severity      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            r.file_path     = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
            r.event_type    = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
            r.process_name  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
            r.pid           = sqlite3_column_int(stmt, 7);
            r.expected      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
            r.actual        = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
            r.action_taken  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
            r.dingtalk_sent = sqlite3_column_int(stmt, 11) != 0;
            r.recorded_at   = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 12));
            results.push_back(r);
        }

        sqlite3_finalize(stmt);
        return results;
    }

private:
    sqlite3* db_ = nullptr;

    void InitTable() {
        // 基线表
        const char* sql_baselines = R"(
            CREATE TABLE IF NOT EXISTS baselines (
                file_path   TEXT PRIMARY KEY,
                hash        TEXT,
                permission  TEXT,
                owner       TEXT,
                grp         TEXT,
                recorded_at TEXT
            );
        )";
        sqlite3_exec(db_, sql_baselines, nullptr, nullptr, nullptr);

        // 告警记录表
        const char* sql_alerts = R"(
            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id     TEXT NOT NULL,
                rule_name   TEXT,
                severity    TEXT,
                file_path   TEXT NOT NULL,
                event_type  TEXT,
                process_name TEXT,
                pid         INTEGER,
                expected    TEXT,
                actual      TEXT,
                action_taken TEXT,
                dingtalk_sent INTEGER DEFAULT 0,
                recorded_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);
            CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(recorded_at);
        )";
        sqlite3_exec(db_, sql_alerts, nullptr, nullptr, nullptr);
    }
};