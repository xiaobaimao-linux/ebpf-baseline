#include <spdlog/spdlog.h>
#include <string>

using namespace std;

void log_pass(const std::string& name, const std::string& msg);

void log_fail(const std::string& name, const std::string& msg);

string mode_to_string(mode_t mode);

string compute_sha256(const string& path);

// 路径标准化：转为绝对路径并规范化
std::string NormalizePath(const std::string& value);

// 命令行参数解析辅助：从 argv[(*idx)+1] 取下一个值
bool TakeArgValue(int& idx, int argc, char* argv[], const std::string& opt, std::string& target);

// 权限/宿主比对结果（has_diff=false 时表示完全一致）
struct PermOwnershipDiff {
    bool has_diff = false;
    std::string expected;  // 如 "mode=rwxr-xr-x, uid=0"
    std::string actual;    // 如 "mode=rwxrwxrwx, uid=1000"
};

// 比对文件的 permission / uid / gid，返回差异描述
PermOwnershipDiff ComparePermOwnership(mode_t actual_mode, uid_t actual_uid, gid_t actual_gid,
                                       const std::string& expected_perm,
                                       int64_t expected_uid, int64_t expected_gid);