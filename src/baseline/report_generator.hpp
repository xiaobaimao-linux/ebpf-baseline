#pragma once
#include "baseline_db.hpp"


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
    bool GenerateCheckHtml(const std::vector<CheckResult>& results,
                           const std::string& output_path);
    
    bool GenerateMonitorEventsHtml(const std::vector<AlertRecord> &records,
                               const std::string &output_path, const std::string &start,
                               const std::string &end);
private:
    std::string EscapeHtml(const std::string& raw);
    std::string GetCurrentTime();
};