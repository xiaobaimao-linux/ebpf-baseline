#ifndef CONFIG_H
#define CONFIG_H


#include <string>
#include <vector>

#include "baseline.hpp"


using namespace std;


struct AlertConfig {
    std::string dingtalk_webhook;
    std::string dingtalk_secret;
    int throttle_seconds = 300;  // 默认5分钟节流
};


struct Config {
    std::vector<Rule> rules;
    AlertConfig alert;   // 
};



// 将字符串转为 Action 枚举
Action stringToAction(const string& str);

// 将 Action 枚举转为字符串
string actionToString(Action action);

// 解析 YAML 文件，返回完整配置对象
Config parseYamlFile(const string& filename);

// 打印规则列表（调试用）
void printRules(const vector<Rule>& rules);

void compute_inodes(Config& config);

#endif