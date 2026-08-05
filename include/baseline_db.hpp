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
    std::string group;          // gid或组名
    std::string recorded_at;    // ISO 8601时间
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
            (file_path, hash, permission, owner, group, recorded_at) 
            VALUES (?, ?, ?, ?, ?, ?);
        )";

        sqlite3_stmt* stmt = nullptr;
        sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);

        sqlite3_bind_text(stmt, 1, record.file_path.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, record.hash.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, record.permission.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, record.owner.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 5, record.group.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 6, record.recorded_at.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Save baseline failed: " << sqlite3_errmsg(db_) << std::endl;
        }
        sqlite3_finalize(stmt);
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
            record.group     = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
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
            r.group      = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
            r.recorded_at= reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
            results.push_back(r);
        }

        sqlite3_finalize(stmt);
        return results;
    }

private:
    sqlite3* db_ = nullptr;

    void InitTable() {
        const char* sql = R"(
            CREATE TABLE IF NOT EXISTS baselines (
                file_path   TEXT PRIMARY KEY,
                hash        TEXT,
                permission  TEXT,
                owner       TEXT,
                group_name  TEXT,
                recorded_at TEXT
            );
        )";
        sqlite3_exec(db_, sql, nullptr, nullptr, nullptr);
    }
};