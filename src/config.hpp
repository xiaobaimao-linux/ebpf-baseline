#ifndef CONFIG_H
#define CONFIG_H


#include <string>
#include <vector>

#include "baseline.hpp"


using namespace std;


// 将字符串转为 Action 枚举
Action stringToAction(const string& str);

// 将 Action 枚举转为字符串
string actionToString(Action action);

// 解析 YAML 文件，返回 Rule 列表
vector<Rule> parseYamlFile(const string& filename);

// 打印规则列表（调试用）
void printRules(const vector<Rule>& rules);

void compute_inodes(Config& config);

#endif