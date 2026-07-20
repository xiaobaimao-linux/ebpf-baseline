#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <regex>
#include <spdlog/spdlog.h>

#include "config.hpp"

using namespace std;


// 将字符串转为 Action 枚举
Action stringToAction(const std::string& str) {
    if (str == "allow") return Action::LOG;
    if (str == "block") return Action::BLOCK;
    return Action::UNKNOWN;
}

// 将 Action 枚举转为字符串（用于打印）
std::string actionToString(Action action) {
    switch (action) {
        case Action::LOG: return "allow";
        case Action::BLOCK: return "block";
        default: return "unknown";
    }
}

// 解析单个 section 的键值对
std::unordered_map<std::string, std::string> parseSection(const std::string& content) {
    std::unordered_map<std::string, std::string> kv;
    std::istringstream stream(content);
    std::string line;
    
    while (std::getline(stream, line)) {
        // 去除前后空白
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        
        // 跳过空行和注释
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        
        size_t eq_pos = line.find('=');
        if (eq_pos == std::string::npos) continue;
        
        std::string key = line.substr(0, eq_pos);
        std::string value = line.substr(eq_pos + 1);
        
        // 去除 key/value 的空白
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t") + 1);
        
        kv[key] = value;
    }
    
    return kv;
}

// 解析 INI 文件内容，返回 Rule 列表
std::vector<Rule> parseIniFile(const std::string& filename) {
    std::vector<Rule> rules;
    std::ifstream file(filename);
    
    if (!file.is_open()) {
        spdlog::error("无法打开文件: {}", filename);
        return rules;
    }
    
    std::string line;
    std::string currentSection;
    std::string sectionContent;
    std::regex sectionRegex(R"(\[([^\]]+)\])");
    
    while (std::getline(file, line)) {
        // 去除行尾回车
        if (!line.empty() && line.back() == '\r') line.pop_back();
        
        std::smatch match;
        if (std::regex_match(line, match, sectionRegex)) {
            // 处理上一个 section
            if (!currentSection.empty() && !sectionContent.empty()) {
                auto kv = parseSection(sectionContent);
                
                Rule rule;
                rule.name = currentSection;
                
                if (kv.count("path")) rule.path = kv["path"];
                if (kv.count("mode")) {
                    try {
                        // 解析八进制权限（如 600）
                        rule.mode = std::stoul(kv["mode"], nullptr, 8);
                    } catch (...) {
                        spdlog::warn("无法解析 mode 值: {} (section: {})", kv["mode"], currentSection);
                    }
                }
                if (kv.count("hash")) {
                    rule.hash = kv["hash"];
                    rule.has_hash = true;
                }
                if (kv.count("action")) {
                    rule.action = stringToAction(kv["action"]);
                }
                
                rules.push_back(rule);
                spdlog::debug("解析规则: name={}, path={}, mode={:o}, hash={}, action={}",
                              rule.name, rule.path, rule.mode,
                              rule.has_hash ? rule.hash : "(无)",
                              actionToString(rule.action));
            }
            
            // 开始新的 section
            currentSection = match[1].str();
            sectionContent.clear();
        } else {
            sectionContent += line + "\n";
        }
    }
    
    // 处理最后一个 section
    if (!currentSection.empty() && !sectionContent.empty()) {
        auto kv = parseSection(sectionContent);
        
        Rule rule;
        rule.name = currentSection;
        
        if (kv.count("path")) rule.path = kv["path"];
        if (kv.count("mode")) {
            try {
                rule.mode = std::stoul(kv["mode"], nullptr, 8);
            } catch (...) {
                spdlog::warn("无法解析 mode 值: {} (section: {})", kv["mode"], currentSection);
            }
        }
        if (kv.count("hash")) {
            rule.hash = kv["hash"];
            rule.has_hash = true;
        }
        if (kv.count("action")) {
            rule.action = stringToAction(kv["action"]);
        }
        
        rules.push_back(rule);
    }
    
    file.close();
    return rules;
}

// 打印规则列表
void printRules(const std::vector<Rule>& rules) {
    spdlog::info("共解析 {} 条规则:", rules.size());
    for (const auto& rule : rules) {
        spdlog::info("  [{}]", rule.name);
        spdlog::info("    path:   {}", rule.path);
        spdlog::info("    mode:   {:o}", rule.mode);
        if (rule.has_hash) {
            spdlog::info("    hash:   {}", rule.hash);
        } else {
            spdlog::info("    hash:   (未设置)");
        }
        spdlog::info("    action: {}", actionToString(rule.action));
    }
}

// // 使用示例
// int main() {
//     // 设置日志级别
//     spdlog::set_level(spdlog::level::debug);
//     spdlog::set_pattern("[%H:%M:%S.%e] [%^%l%$] %v");
    
//     // 解析 INI 文件
//     auto rules = parseIniFile("/home/sf/rules.ini");
    
//     // 打印结果
//     printRules(rules);
    
//     return 0;
// }