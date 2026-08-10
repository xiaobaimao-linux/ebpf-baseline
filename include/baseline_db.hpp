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
    std::string user_name;      // 触发告警的用户名
    std::string uid;            // 触发告警的 uid
    std::string expected;       // 预期值（如权限或哈希）
    std::string actual;         // 实际值
    std::string action_taken;   // 采取的动作: alert / block
    bool dingtalk_sent = false; // 是否成功发送钉钉告警
    std::string recorded_at;    // 记录时间
};

class BaselineDB {
public:
    explicit BaselineDB(const std::string& db_path = "/var/lib/baseline-guard/baseline.db");

    ~BaselineDB();

    // 保存或更新基线
    void SaveBaseline(const BaselineRecord& record);

    // 保存告警记录
    void SaveAlert(const AlertRecord& record);

    // === Retention: 按天数清理 ===
    // 返回删除的记录数
    int PurgeAlertsByAge(int retention_days);

    // === Retention: 按数量上限清理（保留最新的N条）===
    // 返回删除的记录数
    int PurgeAlertsByCount(int max_records);

    // === 回收数据库空间（VACUUM）===
    void Vacuum();
    // === 获取当前告警总数 ===
    int GetAlertCount();

    // 查询基线
    BaselineRecord GetBaseline(const std::string& file_path);

    // 获取所有基线（用于报告生成）
    std::vector<BaselineRecord> GetAllBaselines();

    // 查询告警记录：支持 rule 过滤、今日过滤、数量限制
    std::vector<AlertRecord> GetAlerts(const std::string& rule_filter = "",
                                        int limit = 20,
                                        bool today = false);

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
                user_name   TEXT,
                uid         TEXT,
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

        // 兼容旧版 alerts 表：如果已有旧库文件，则补齐新字段
        sqlite3_exec(db_, "ALTER TABLE alerts ADD COLUMN user_name TEXT DEFAULT '';", nullptr, nullptr, nullptr);
        sqlite3_exec(db_, "ALTER TABLE alerts ADD COLUMN uid TEXT DEFAULT '';", nullptr, nullptr, nullptr);
    }
};