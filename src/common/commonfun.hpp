#include <unistd.h>    // for gethostname
#include <fstream>     // 读取 /etc/hostname


#include <iostream>
#include <chrono>
#include <iomanip>
#include <string>

using namespace std;


// 获取当前时间字符串
std::string NowString();

// 辅助函数：判断字符串是否以指定后缀结尾

bool ends_with(const string& str, const string& suffix);
std::string GetHostname();

// 输入格式  示例  输出格式
// 标准格式  2024-01-15 14:30:25  2024-01-15 14:30:25（不变）
// 紧凑格式  20240115-143025 2024-01-15 14:30:25
// 其他格式 2024/01/15  2024/01/15（原样返回）
std::string NormalizeTimestamp(const std::string &timestamp);

std::string SeverityClass(const std::string &severity);