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
