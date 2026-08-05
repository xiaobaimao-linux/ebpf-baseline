#pragma once
#include <string>
#include <vector>
#include <ctime>

struct CheckResult {
    std::string rule_id;
    std::string rule_name;
    std::string file_path;
    std::string expected;
    std::string actual;
    bool passed;
    std::string severity;
};

class ReportGenerator {
public:
    bool GenerateHtml(const std::vector<CheckResult>& results,
                      const std::string& output_path);
    
private:
    std::string EscapeHtml(const std::string& raw);
    std::string GetCurrentTime();
};