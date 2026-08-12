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


std::string GetHostname() {
    char buf[256] = {0};
    if (gethostname(buf, sizeof(buf)) == 0) {
        return std::string(buf);
    }
    
    // fallback
    std::ifstream f("/etc/hostname");
    if (f.is_open()) {
        std::string name;
        std::getline(f, name);
        return name;
    }
    
    return "unknown";
}

std::string NormalizeTimestamp(const std::string &timestamp) {
    if (timestamp.size() >= 19 && timestamp[4] == '-' && timestamp[7] == '-') {
        return timestamp;
    }

    if (timestamp.size() >= 17 && timestamp[8] == '-') {
        return timestamp.substr(0, 4) + "-" + timestamp.substr(4, 2) + "-" +
               timestamp.substr(6, 2) + " " + timestamp.substr(9, 2) + ":" +
               timestamp.substr(12, 2) + ":" + timestamp.substr(15, 2);
    }

    return timestamp;
}


std::string SeverityClass(const std::string &severity) {
    if (severity == "critical" || severity == "high" || severity == "medium" || severity == "low") {
        return "severity-" + severity;
    }
    return "";
}