#pragma once

#include <cstdint>
#include <sqlite3.h>
#include <string>
#include <vector>

struct BaselineRecord {
    std::string file_path;
    std::string hash;           // sha256
    std::string permission;     // 如 "0644"
    std::string owner;          // uid或用户名
    std::string grp;            // gid或组名
    std::string recorded_at;    // ISO 8601时间
};

struct SnapshotEntry {
    std::string file_path;
    std::string file_type = "regular";
    std::string hash;
    std::string permission;
    std::int64_t uid = 0;
    std::int64_t gid = 0;
    std::string owner;
    std::string grp;
    std::int64_t file_size = 0;
    std::int64_t mtime = 0;
};

// list 子命令使用的扩展条目（含快照元信息）
struct ListEntry : SnapshotEntry {
    std::string snapshot_id;
    std::string label;
    std::string recorded_at;
};

// list 查询结果：entries 为当前页数据，total_count 为过滤后总行数
struct ListResult {
    std::vector<ListEntry> entries;
    std::int64_t total_count = 0;
};

struct SnapshotScope {
    std::string path;
    bool recursive = true;
    bool exact_file = false;
};

struct SnapshotStats {
    std::int64_t scanned = 0;
    std::int64_t added = 0;
    std::int64_t modified = 0;
    std::int64_t removed = 0;
    std::int64_t unchanged = 0;
    std::int64_t errors = 0;
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

    // 设置 SQLite WAL 日志模式
    void setWAL();

    // 保存或更新旧版 check 观察记录
    void SaveBaseline(const BaselineRecord& record);

    // 原子应用一次文件基线快照
    bool ApplySnapshot(const std::string& snapshot_id,
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
                      std::string& error);

    // 快照当前基线和审计记录查询，供测试及后续历史命令使用
    std::vector<SnapshotEntry> GetSnapshotEntries();
    int GetBaselineAuditCount();

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

    // 查询 monitor 原始事件：时间边界均为包含式，空边界表示不限制
    std::vector<AlertRecord> GetMonitorEvents(const std::string& start = "",
                                               const std::string& end = "");

    // 删除基线条目：paths 中的每个路径精确匹配；recursive=true 时目录路径启用前缀匹配
    // 返回实际删除的条目数
    int DeleteBaselineEntries(const std::vector<std::string>& paths, bool recursive);

    // 分页查询 baseline_entries：path_filter 使用 SQL LIKE 语法，limit/offset 控制分页
    // 返回 entries（当前页）和 total_count（过滤后总行数）
    ListResult ListBaselineEntries(const std::string& path_filter,
                                   int limit,
                                   int offset);

private:
    sqlite3* db_ = nullptr;

    void InitTable();
};
