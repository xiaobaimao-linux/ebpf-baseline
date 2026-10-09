#ifndef CONFIG_H
#define CONFIG_H


#include <string>
#include <vector>

#include "baseline.hpp"


using namespace std;


struct AlertConfig {
    std::string dingtalk_webhook;
    std::string dingtalk_secret;
    int throttle_seconds = 300;       // 钉钉节流：默认5分钟
};

// 数据库配置（独立节点 db:）
struct DbConfig {
    int retention_days = 30;           // 告警保留天数：默认30天，0=永久保留
    int retention_max_records = 10000; // 告警最大记录数：默认1万条，0=不限制
};

// 告警外发配置（独立节点 notify:，W5 D4；webhook 为首个渠道）
struct NotifyConfig {
    bool enabled = false;              // 外发总开关，默认关闭（行为与旧版本一致）
    std::string webhook_url;           // webhook POST 地址，空=不外发
    std::string min_level = "high";    // 外发最低级别：critical/high 外发，medium/low 仅落库
    int silence_minutes = 10;          // 静默窗口：同 (rule_id, 对象) 窗口内只外发 1 次，0=关闭
    int aggregation_window_minutes = 5;  // 聚合窗口：同 (rule_id, 对象) 窗口内重复告警合并，
                                         // 窗末补发一条 occurrences=N 摘要；0=关闭。
                                         // 摘要仍受静默窗口约束，建议聚合窗口 >= 静默窗口
};

// 遥测配置（独立节点 telemetry:）
struct TelemetryConfig {
    bool network = false;              // 网络连接事件遥测（connect/accept/bind），默认关闭
    bool dns = false;                  // DNS 查询遥测（net_watch 内，随其加载），默认关闭
    bool privilege = false;            // 权限事件遥测（setuid/capset/ptrace/module_load），默认关闭
    bool store = false;                // 遥测落库开关（events 表），默认关闭；关闭时仅走原有日志输出
    std::string events_db = "baselines/events.db";  // 遥测事件库路径（telemetry.events_db）
    int queue_hi = 32768;              // 事件总线 hi 队列槽数（file/priv/ns/process）
    int queue_lo = 65536;              // 事件总线 lo 队列槽数（network/dns）
    int batch_size = 500;              // 落库批量条数（一事务）
    int batch_ms = 200;                // 落库批量间隔（毫秒，一事务）
};


// 规则引擎配置（独立节点 rule_engine:，DSL 规则见 docs/rule-dsl-v1.md）
struct RuleEngineConfig {
    bool enabled = true;               // DSL 规则引擎开关，默认开启
    std::string rules_dir = "rules";   // 规则目录（*.yaml/*.yml 全量加载）
};


struct Config {
    std::vector<Rule> rules;
    AlertConfig alert;   //
    DbConfig db;         // 数据库保留策略配置
    NotifyConfig notify; // 告警外发（webhook 渠道，SIGHUP 热加载）
    TelemetryConfig telemetry;  // 遥测开关
    RuleEngineConfig rule_engine;  // DSL 规则引擎
};



// 将字符串转为 Action 枚举
Action stringToAction(const string& str);

// 将 Action 枚举转为字符串
string actionToString(Action action);

// 将 severity 字符串转为数值 (SEVERITY_LOW ~ SEVERITY_CRITICAL)
unsigned char stringToSeverity(const std::string& s);

// 将 severity 数值转为字符串
std::string severityToString(unsigned char sev);

// 解析 YAML 文件，返回完整配置对象（lenient：坏规则跳过并告警，供 check 等命令使用）
Config parseYamlFile(const string& filename);

// 严格解析：任何规则/whitelist 解析失败（缩进/类型错）即整体失败，
// err 携带 "文件:行号: 原因"。供 monitor 冷启动与 SIGHUP 热加载使用，
// 热加载失败时调用方保留旧配置。
bool tryParseYamlFile(const string& filename, Config& out, string& err);

// 打印规则列表（调试用）
void printRules(const vector<Rule>& rules);

void compute_inodes(Config& config);

#endif