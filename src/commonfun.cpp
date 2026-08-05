#include <iostream>
#include "commonfun.hpp"


std::string NowString() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&t), "%Y%m%d-%H:%M:%S");
    return ss.str();
}


// 辅助函数：判断字符串是否以指定后缀结尾
bool ends_with(const string& str, const string& suffix) {
    if (suffix.size() > str.size()) return false;
    return equal(suffix.rbegin(), suffix.rend(), str.rbegin());
}
