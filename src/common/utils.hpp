#include <spdlog/spdlog.h>
#include <string>

using namespace std;

void log_pass(const std::string& name, const std::string& msg);

void log_fail(const std::string& name, const std::string& msg);

string mode_to_string(mode_t mode);

string compute_sha256(const string& path);