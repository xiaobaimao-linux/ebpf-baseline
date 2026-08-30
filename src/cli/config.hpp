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


struct Config {
    std::vector<Rule> rules;
    AlertConfig alert;   // 
    DbConfig db;         // 数据库保留策略配置
};



// 将字符串转为 Action 枚举
Action stringToAction(const string& str);

// 将 Action 枚举转为字符串
string actionToString(Action action);

// 将 severity 字符串转为数值 (SEVERITY_LOW ~ SEVERITY_CRITICAL)
unsigned char stringToSeverity(const std::string& s);

// 将 severity 数值转为字符串
std::string severityToString(unsigned char sev);

// 解析 YAML 文件，返回完整配置对象
Config parseYamlFile(const string& filename);

// 打印规则列表（调试用）
void printRules(const vector<Rule>& rules);

void compute_inodes(Config& config);

#endif