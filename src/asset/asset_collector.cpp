#include "asset_collector.hpp"

#include <nlohmann/json.hpp>

#include <spdlog/spdlog.h>

#include <arpa/inet.h>

#include <sys/types.h>
#include <unistd.h>

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;
using json = nlohmann::json;

std::string Trim(const std::string& value) {
    size_t begin = 0;
    while (begin < value.size() &&
           std::isspace(static_cast<unsigned char>(value[begin]))) {
        ++begin;
    }
    size_t end = value.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
        --end;
    }
    return value.substr(begin, end - begin);
}

std::vector<std::string> SplitWs(const std::string& line) {
    std::vector<std::string> tokens;
    std::istringstream iss(line);
    std::string token;
    while (iss >> token) {
        tokens.push_back(token);
    }
    return tokens;
}

// 读取整个文件；失败返回 false（文件不存在视为正常缺失）
bool ReadWholeFile(const std::string& path, std::string& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    return true;
}

std::string JoinTokens(const std::vector<std::string>& tokens, size_t begin) {
    std::string out;
    for (size_t i = begin; i < tokens.size(); ++i) {
        if (!out.empty()) {
            out += ' ';
        }
        out += tokens[i];
    }
    return out;
}

// epoch 秒 → 本地 ISO 时间（与 NowIso() 的 %Y-%m-%dT%H:%M:%S 格式一致）
std::string EpochToIso(std::time_t epoch) {
    std::tm tm_value = {};
    localtime_r(&epoch, &tm_value);
    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &tm_value);
    return buffer;
}

std::vector<fs::path> ListNumericDirs(const std::string& path) {
    std::vector<fs::path> dirs;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(path, ec)) {
        const std::string name = entry.path().filename().string();
        if (!name.empty() &&
            std::all_of(name.begin(), name.end(),
                        [](unsigned char c) { return std::isdigit(c) != 0; })) {
            dirs.push_back(entry.path());
        }
    }
    return dirs;
}

// ---------------- 软件包 ----------------

struct DpkgPkg {
    std::string name;
    std::string version;
    std::string arch;
};

// 多架构同名的包（如 libc6 同时装 amd64/i386）在 name 后补 :arch 区分，
// 与 dpkg 包名语法一致（dpkg-query -W libc6:i386 可用）；单架构包保持纯包名
std::vector<AssetItem> EmitPackages(std::vector<DpkgPkg>&& pkgs) {
    std::map<std::string, int> name_count;
    for (const auto& pkg : pkgs) {
        ++name_count[pkg.name];
    }
    std::vector<AssetItem> items;
    for (auto& pkg : pkgs) {
        json detail;
        detail["manager"] = "dpkg";
        detail["version"] = pkg.version;
        detail["arch"] = pkg.arch;
        std::string name = pkg.name;
        if (name_count[pkg.name] > 1) {
            name += ":" + pkg.arch;
        }
        items.push_back({"package", name, detail.dump()});
    }
    return items;
}

std::vector<AssetItem> ParseDpkgStatus(const std::string& content) {
    std::vector<DpkgPkg> pkgs;
    std::istringstream stream(content);
    std::string line;
    // 段落间以空行分隔；字段行 "Key: value"，续行（空格/tab 开头）忽略
    auto flush_block = [&](const std::string& raw) {
        std::map<std::string, std::string> fields;
        std::istringstream lines(raw);
        std::string current;
        while (std::getline(lines, current)) {
            if (!current.empty() && current.back() == '\r') {
                current.pop_back();
            }
            if (current.empty() || std::isspace(static_cast<unsigned char>(current[0]))) {
                continue;
            }
            const size_t colon = current.find(':');
            if (colon == std::string::npos) {
                continue;
            }
            fields[current.substr(0, colon)] = Trim(current.substr(colon + 1));
        }
        if (fields["Package"].empty()) {
            return;
        }
        if (fields["Status"] != "install ok installed") {
            return;
        }
        pkgs.push_back({fields["Package"], fields["Version"], fields["Architecture"]});
    };
    std::string pending;
    while (std::getline(stream, line)) {
        if (line.empty() || line == "\r") {
            flush_block(pending);
            pending.clear();
        } else {
            pending += line;
            pending += '\n';
        }
    }
    flush_block(pending);
    return EmitPackages(std::move(pkgs));
}

// dpkg status 缺失时 dpkg-query 兜底
std::vector<AssetItem> CollectDpkgQuery() {
    std::vector<DpkgPkg> pkgs;
    FILE* pipe = popen("dpkg-query -W -f='${Package}\\t${Version}\\t${Architecture}"
                       "\\t${db:Status-Status}\\n' 2>/dev/null",
                       "r");
    if (pipe == nullptr) {
        return {};
    }
    char buffer[4096];
    std::string output;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    pclose(pipe);
    std::istringstream lines(output);
    std::string line;
    while (std::getline(lines, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        const std::vector<std::string> fields = SplitWs(line);
        if (fields.size() < 4 || fields[3] != "installed") {
            continue;
        }
        pkgs.push_back({fields[0], fields[1], fields[2]});
    }
    return EmitPackages(std::move(pkgs));
}

std::vector<AssetItem> CollectRpm() {
    std::vector<AssetItem> items;
    const bool rpm_present = fs::exists("/usr/bin/rpm") || fs::exists("/var/lib/rpm") ||
                             fs::exists("/usr/lib/sysimage/rpm");
    if (!rpm_present) {
        spdlog::debug("[asset] rpm not found on this host, skip rpm packages");
        return items;
    }
    FILE* pipe = popen("rpm -qa --queryformat '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n' "
                       "2>/dev/null",
                       "r");
    if (pipe == nullptr) {
        spdlog::warn("[asset] failed to run rpm -qa");
        return items;
    }
    char buffer[4096];
    std::string output;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    const int rc = pclose(pipe);
    if (rc != 0) {
        spdlog::warn("[asset] rpm -qa failed (rc={}), rpm packages degraded", rc);
        return items;
    }
    std::istringstream lines(output);
    std::string line;
    while (std::getline(lines, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        const std::vector<std::string> fields = SplitWs(line);
        if (fields.empty()) {
            continue;
        }
        json detail;
        detail["manager"] = "rpm";
        detail["version"] = fields.size() > 1 ? fields[1] : "";
        detail["arch"] = fields.size() > 2 ? fields[2] : "";
        items.push_back({"package", fields[0], detail.dump()});
    }
    return items;
}

// ---------------- 监听端口 ----------------

struct RawPort {
    std::string proto;  // tcp / tcp6 / udp / udp6
    std::string addr;
    uint32_t port = 0;
    uint64_t inode = 0;
};

// /proc/net/tcp{,6} 地址为按 32 位小端字打印的十六进制；解码为点分/压缩 IPv6 文本
std::string DecodeIPv4(const std::string& hex) {
    if (hex.size() != 8) {
        return "";
    }
    const unsigned long value = std::stoul(hex, nullptr, 16);
    unsigned char bytes[4];
    for (size_t b = 0; b < 4; ++b) {
        bytes[b] = static_cast<unsigned char>((value >> (8 * b)) & 0xff);
    }
    char text[INET_ADDRSTRLEN] = {0};
    if (inet_ntop(AF_INET, bytes, text, sizeof(text)) == nullptr) {
        return "";
    }
    return text;
}

std::string DecodeIPv6(const std::string& hex) {
    if (hex.size() != 32) {
        return "";
    }
    unsigned char bytes[16];
    for (size_t word = 0; word < 4; ++word) {
        const unsigned long value = std::stoul(hex.substr(word * 8, 8), nullptr, 16);
        for (size_t b = 0; b < 4; ++b) {
            bytes[word * 4 + b] = static_cast<unsigned char>((value >> (8 * b)) & 0xff);
        }
    }
    char text[INET6_ADDRSTRLEN] = {0};
    if (inet_ntop(AF_INET6, bytes, text, sizeof(text)) == nullptr) {
        return "";
    }
    return text;
}

std::vector<RawPort> ParseProcNet(const std::string& path, const std::string& proto,
                                  bool is_tcp) {
    std::vector<RawPort> ports;
    std::string content;
    if (!ReadWholeFile(path, content)) {
        return ports;
    }
    std::istringstream lines(content);
    std::string line;
    bool header = true;
    while (std::getline(lines, line)) {
        if (header) {  // 跳过表头
            header = false;
            continue;
        }
        const std::vector<std::string> fields = SplitWs(line);
        // sl local_address rem_address st ... inode(列9)
        if (fields.size() < 10) {
            continue;
        }
        if (is_tcp && fields[3] != "0A") {  // TCP_LISTEN
            continue;
        }
        if (!is_tcp && fields[3] != "07") {  // UDP 未连接（绑定）套接字
            continue;
        }
        const size_t colon = fields[1].find(':');
        if (colon == std::string::npos) {
            continue;
        }
        RawPort port;
        port.proto = proto;
        const std::string hex_addr = fields[1].substr(0, colon);
        port.port = static_cast<uint32_t>(std::stoul(fields[1].substr(colon + 1), nullptr, 16));
        port.addr = proto.size() > 3 && proto.find('6') != std::string::npos
                        ? DecodeIPv6(hex_addr)
                        : DecodeIPv4(hex_addr);
        if (port.addr.empty()) {
            continue;
        }
        try {
            port.inode = std::stoull(fields[9]);
        } catch (...) {
            continue;
        }
        ports.push_back(port);
    }
    return ports;
}

// 扫 /proc/*/fd 反查 socket inode → (pid, comm)，归属失败仅填空串
std::map<uint64_t, std::pair<int, std::string>> BuildInodeOwnerMap(
    const std::set<uint64_t>& wanted) {
    std::map<uint64_t, std::pair<int, std::string>> owner;
    if (wanted.empty()) {
        return owner;
    }
    for (const auto& pid_dir : ListNumericDirs("/proc")) {
        const int pid = std::stoi(pid_dir.filename().string());
        std::string comm;
        ReadWholeFile(pid_dir.string() + "/comm", comm);
        comm = Trim(comm);
        std::error_code ec;
        const std::string fd_dir = pid_dir.string() + "/fd";
        for (const auto& fd : fs::directory_iterator(fd_dir, ec)) {
            char target[256];
            const ssize_t n = readlink(fd.path().c_str(), target, sizeof(target) - 1);
            if (n <= 0) {
                continue;
            }
            target[n] = '\0';
            const std::string link(target);
            if (link.rfind("socket:[", 0) != 0) {
                continue;
            }
            const size_t close = link.find(']');
            if (close == std::string::npos) {
                continue;
            }
            uint64_t inode = 0;
            try {
                inode = std::stoull(link.substr(8, close - 8));
            } catch (...) {
                continue;
            }
            if (wanted.count(inode) > 0 && owner.find(inode) == owner.end()) {
                owner[inode] = {pid, comm};
            }
        }
    }
    return owner;
}

// ---------------- 运行进程 ----------------

// /proc/<pid>/stat 中 comm 可能含空格/括号，取首个 '(' 至最后一个 ')' 之间
bool ParseStatFile(const std::string& content, std::string& comm, int64_t& ppid,
                   int64_t& start_ticks) {
    const size_t open = content.find('(');
    const size_t close = content.rfind(')');
    if (open == std::string::npos || close == std::string::npos || close <= open) {
        return false;
    }
    comm = content.substr(open + 1, close - open - 1);
    const std::vector<std::string> fields = SplitWs(content.substr(close + 1));
    // comm 之后：state(0) ppid(1) ... starttime(19)
    if (fields.size() < 20) {
        return false;
    }
    try {
        ppid = std::stoll(fields[1]);
        start_ticks = std::stoll(fields[19]);
    } catch (...) {
        return false;
    }
    return true;
}

int64_t ReadBtime() {
    std::string stat;
    if (!ReadWholeFile("/proc/stat", stat)) {
        return 0;
    }
    std::istringstream lines(stat);
    std::string line;
    while (std::getline(lines, line)) {
        if (line.rfind("btime ", 0) == 0) {
            try {
                return std::stoll(Trim(line.substr(6)));
            } catch (...) {
                return 0;
            }
        }
    }
    return 0;
}

int64_t ReadRealUid(const std::string& status_content) {
    std::istringstream lines(status_content);
    std::string line;
    while (std::getline(lines, line)) {
        if (line.rfind("Uid:", 0) == 0) {
            const std::vector<std::string> fields = SplitWs(line);
            if (fields.size() >= 2) {
                try {
                    return std::stoll(fields[1]);
                } catch (...) {
                    return -1;
                }
            }
        }
    }
    return -1;
}

// ---------------- AI 工作负载特征匹配 ----------------

// cmdline 命中 torch/tensorflow 关键路径（site-packages/dist-packages 下的包目录）
std::vector<std::string> MatchCmdlineAiSignals(const std::string& cmdline) {
    std::vector<std::string> signals;
    for (const char* framework : {"torch", "tensorflow"}) {
        for (const char* prefix : {"site-packages/", "dist-packages/"}) {
            if (cmdline.find(std::string(prefix) + framework) != std::string::npos) {
                signals.push_back(std::string("cmdline:") + framework + "_path");
                break;
            }
        }
    }
    return signals;
}

// environ 为 NUL 分隔的 KEY=VALUE，按变量边界匹配（避免 X_CUDA_VISIBLE_DEVICES 误命中）
bool EnvironHasCudaVisibleDevices(const std::string& environ) {
    const std::string key = "CUDA_VISIBLE_DEVICES=";
    size_t pos = 0;
    while ((pos = environ.find(key, pos)) != std::string::npos) {
        if (pos == 0 || environ[pos - 1] == '\0') {
            return true;
        }
        pos += key.size();
    }
    return false;
}

// maps 行尾为映射文件绝对路径，"/libcuda.so" 同时覆盖 libcuda.so.1 等版本后缀
std::vector<std::string> MatchMapsAiSignals(const std::string& maps) {
    std::vector<std::string> signals;
    if (maps.find("/libcuda.so") != std::string::npos) {
        signals.push_back("maps:libcuda");
    }
    if (maps.find("/libnvidia-ml.so") != std::string::npos) {
        signals.push_back("maps:libnvidia_ml");
    }
    return signals;
}

// ---------------- 自启项 ----------------

// systemctl 失败时降级：扫描 /etc/systemd/system 下 .wants/.requires 软链
std::vector<AssetItem> CollectSystemdUnitsFallback() {
    std::vector<AssetItem> items;
    std::error_code ec;
    const fs::path etc_systemd("/etc/systemd/system");
    if (!fs::exists(etc_systemd, ec)) {
        return items;
    }
    std::set<std::string> seen;
    for (const auto& entry : fs::directory_iterator(etc_systemd, ec)) {
        const std::string name = entry.path().filename().string();
        const bool wants = name.size() > 6 && name.rfind(".wants") == name.size() - 6;
        const bool is_requires =
            name.size() > 9 && name.rfind(".requires") == name.size() - 9;
        if (!wants && !is_requires) {
            continue;
        }
        std::error_code inner_ec;
        for (const auto& unit :
             fs::directory_iterator(entry.path(), inner_ec)) {
            const std::string unit_name = unit.path().filename().string();
            if (seen.count(unit_name) > 0) {
                continue;
            }
            seen.insert(unit_name);
            json detail;
            detail["source"] = "systemd";
            detail["state"] = "enabled";
            detail["method"] = "symlink-scan";
            items.push_back({"autostart", unit_name, detail.dump()});
        }
    }
    return items;
}

std::vector<AssetItem> CollectSystemdUnits() {
    std::vector<AssetItem> items;
    FILE* pipe = popen("systemctl list-unit-files --state=enabled --no-legend "
                       "--no-pager 2>/dev/null",
                       "r");
    if (pipe == nullptr) {
        spdlog::warn("[asset] failed to run systemctl, fallback to symlink scan");
        return CollectSystemdUnitsFallback();
    }
    char buffer[4096];
    std::string output;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    const int rc = pclose(pipe);
    if (rc != 0) {
        spdlog::warn("[asset] systemctl list-unit-files failed (rc={}), fallback to "
                     "symlink scan",
                     rc);
        return CollectSystemdUnitsFallback();
    }
    std::istringstream lines(output);
    std::string line;
    while (std::getline(lines, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        const std::vector<std::string> fields = SplitWs(line);
        if (fields.size() < 2 || fields[0] == "UNIT") {
            continue;
        }
        json detail;
        detail["source"] = "systemd";
        detail["state"] = fields[1];
        if (fields.size() > 2) {
            detail["preset"] = fields[2];
        }
        items.push_back({"autostart", fields[0], detail.dump()});
    }
    return items;
}

} // namespace

std::vector<AssetItem> CollectPackages() {
    std::vector<AssetItem> items;
    std::string status;
    if (ReadWholeFile("/var/lib/dpkg/status", status)) {
        items = ParseDpkgStatus(status);
    } else if (access("/usr/bin/dpkg-query", X_OK) == 0) {
        items = CollectDpkgQuery();
    } else {
        spdlog::debug("[asset] dpkg database not found on this host");
    }
    std::vector<AssetItem> rpm_items = CollectRpm();
    items.insert(items.end(), rpm_items.begin(), rpm_items.end());
    return items;
}

std::vector<AssetItem> CollectPorts() {
    std::vector<RawPort> raw;
    std::vector<RawPort> part;
    part = ParseProcNet("/proc/net/tcp", "tcp", true);
    raw.insert(raw.end(), part.begin(), part.end());
    part = ParseProcNet("/proc/net/tcp6", "tcp6", true);
    raw.insert(raw.end(), part.begin(), part.end());
    part = ParseProcNet("/proc/net/udp", "udp", false);
    raw.insert(raw.end(), part.begin(), part.end());
    part = ParseProcNet("/proc/net/udp6", "udp6", false);
    raw.insert(raw.end(), part.begin(), part.end());

    std::set<uint64_t> inodes;
    for (const auto& port : raw) {
        inodes.insert(port.inode);
    }
    const auto owner = BuildInodeOwnerMap(inodes);

    std::vector<AssetItem> items;
    for (const auto& port : raw) {
        const bool ipv6 = port.proto.find('6') != std::string::npos;
        const std::string display_addr = ipv6 ? "[" + port.addr + "]" : port.addr;
        int pid = 0;
        std::string process;
        const auto it = owner.find(port.inode);
        if (it != owner.end()) {
            pid = it->second.first;
            process = it->second.second;
        }
        json detail;
        detail["proto"] = port.proto;
        detail["addr"] = port.addr;
        detail["port"] = port.port;
        detail["inode"] = port.inode;
        detail["pid"] = pid;
        detail["process"] = process;
        items.push_back({/*asset_type=*/"port",
                         port.proto + "://" + display_addr + ":" +
                             std::to_string(port.port),
                         detail.dump()});
    }
    return items;
}

std::vector<AssetItem> CollectProcesses() {
    std::vector<AssetItem> items;
    const int64_t btime = ReadBtime();
    const long hz = sysconf(_SC_CLK_TCK);
    const int self_pid = getpid();  // 采集器自身是瞬时进程，不计入资产（保证重复采集幂等）
    for (const auto& pid_dir : ListNumericDirs("/proc")) {
        const std::string pid_str = pid_dir.filename().string();
        if (std::stoi(pid_str) == self_pid) {
            continue;
        }
        std::string stat;
        if (!ReadWholeFile(pid_dir.string() + "/stat", stat)) {
            continue;  // 进程退出或不可读，跳过
        }
        std::string comm;
        int64_t ppid = 0;
        int64_t start_ticks = 0;
        if (!ParseStatFile(stat, comm, ppid, start_ticks)) {
            continue;
        }
        // 内核 6.2+ 的 comm 扩展名会超出 TASK_COMM_LEN(15)，截断以对齐 ps %comm 口径
        if (comm.size() > 15) {
            comm.resize(15);
        }
        std::string status;
        const int64_t uid = ReadWholeFile(pid_dir.string() + "/status", status)
                                ? ReadRealUid(status)
                                : -1;
        std::string cmdline;
        if (ReadWholeFile(pid_dir.string() + "/cmdline", cmdline)) {
            for (auto& ch : cmdline) {
                if (ch == '\0') {
                    ch = ' ';
                }
            }
            cmdline = Trim(cmdline);
        }
        // cmdline 为空 = 内核线程（kworker 等）或僵尸进程：内核线程随内核调度频繁
        // 生灭，计入会导致重复采集行数永不收敛，且非用户态工作负载，跳过
        if (cmdline.empty()) {
            continue;
        }
        char exe_buffer[4096];
        std::string exe;
        const ssize_t n = readlink((pid_dir.string() + "/exe").c_str(), exe_buffer,
                                   sizeof(exe_buffer) - 1);
        if (n > 0) {
            exe.assign(exe_buffer, static_cast<size_t>(n));
        }
        std::string start_iso;
        if (btime > 0 && hz > 0) {
            start_iso = EpochToIso(static_cast<std::time_t>(
                btime + static_cast<double>(start_ticks) / hz));
        }
        // W5 AI 工作负载识别：cmdline 已读先行判定；未命中再按需读 environ/maps
        // （maps 较大，仅在前两个特征都没命中时读取，降低全进程扫描开销）
        std::vector<std::string> ai_signals = MatchCmdlineAiSignals(cmdline);
        if (ai_signals.empty()) {
            std::string environ;
            if (ReadWholeFile(pid_dir.string() + "/environ", environ) &&
                EnvironHasCudaVisibleDevices(environ)) {
                ai_signals.push_back("env:CUDA_VISIBLE_DEVICES");
            }
        }
        if (ai_signals.empty()) {
            std::string maps;
            if (ReadWholeFile(pid_dir.string() + "/maps", maps)) {
                ai_signals = MatchMapsAiSignals(maps);
            }
        }
        json detail;
        detail["pid"] = std::stoi(pid_str);
        detail["ppid"] = ppid;
        detail["comm"] = comm;
        detail["exe"] = exe;
        detail["cmdline"] = cmdline;
        detail["uid"] = uid;
        detail["start_time"] = start_iso;
        detail["ai_workload"] = !ai_signals.empty();
        if (!ai_signals.empty()) {
            detail["ai_signals"] = ai_signals;
        }
        items.push_back(
            {/*asset_type=*/"process", comm + "(" + pid_str + ")", detail.dump()});
    }
    return items;
}

std::vector<AssetItem> CollectAutostart() {
    std::vector<AssetItem> items;
    if (fs::exists("/run/systemd/system")) {
        std::vector<AssetItem> units = CollectSystemdUnits();
        items.insert(items.end(), units.begin(), units.end());
    } else {
        spdlog::debug("[asset] non-systemd init detected, skip systemd units");
    }
    std::error_code ec;
    if (fs::exists("/etc/rc.local", ec)) {
        json detail;
        detail["source"] = "rclocal";
        detail["path"] = "/etc/rc.local";
        detail["executable"] =
            (fs::status("/etc/rc.local", ec).permissions() &
             fs::perms::owner_exec) != fs::perms::none;
        items.push_back({"autostart", "rc.local", detail.dump()});
    }
    const fs::path initd("/etc/init.d");
    if (fs::is_directory(initd, ec)) {
        for (const auto& entry : fs::directory_iterator(initd, ec)) {
            const std::string name = entry.path().filename().string();
            if (name.empty() || name[0] == '.' ||
                !fs::is_regular_file(entry.status(ec))) {
                continue;
            }
            json detail;
            detail["source"] = "initd";
            detail["path"] = entry.path().string();
            detail["executable"] =
                (entry.status(ec).permissions() & fs::perms::owner_exec) !=
                fs::perms::none;
            items.push_back({"autostart", name, detail.dump()});
        }
    }
    return items;
}

std::vector<AssetItem> CollectCron() {
    struct CronSource {
        std::string path;
        bool user_field;
    };
    std::vector<CronSource> sources;
    if (fs::exists("/etc/crontab")) {
        sources.push_back({"/etc/crontab", true});
    }
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator("/etc/cron.d", ec)) {
        if (fs::is_regular_file(entry.status(ec))) {
            sources.push_back({entry.path().string(), true});
        }
    }
    std::set<std::string> seen_files;
    for (const char* dir : {"/var/spool/cron/crontabs", "/var/spool/cron"}) {
        std::error_code dir_ec;
        const fs::directory_iterator end;
        fs::directory_iterator it(dir, dir_ec);
        if (dir_ec) {
            if (fs::exists(dir)) {
                spdlog::warn("[asset] cannot read cron dir {}: {}", dir,
                             dir_ec.message());
            }
            continue;  // 目录不存在属正常，权限不足记 warn 并降级
        }
        for (; it != end; it.increment(dir_ec)) {
            if (dir_ec) {
                spdlog::warn("[asset] cannot iterate cron dir {}: {}", dir,
                             dir_ec.message());
                break;
            }
            if (!fs::is_regular_file(it->status())) {
                continue;
            }
            const std::string canonical =
                fs::weakly_canonical(it->path(), dir_ec).string();
            if (!seen_files.insert(canonical).second) {
                continue;  // 同一文件经两个 spool 路径重复出现时去重
            }
            sources.push_back({it->path().string(), false});
        }
    }
    std::vector<AssetItem> items;
    for (const auto& source : sources) {
        std::string content;
        if (!ReadWholeFile(source.path, content)) {
            spdlog::warn("[asset] failed to read cron file: {}", source.path);
            continue;
        }
        std::istringstream lines(content);
        std::string line;
        int lineno = 0;
        while (std::getline(lines, line)) {
            ++lineno;
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            const std::string trimmed = Trim(line);
            if (trimmed.empty() || trimmed[0] == '#') {
                continue;
            }
            const std::vector<std::string> tokens = SplitWs(trimmed);
            json detail;
            detail["file"] = source.path;
            detail["line"] = lineno;
            std::string schedule;
            std::string user;
            std::string command;
            const bool env_line =
                !tokens.empty() && tokens[0].find('=') != std::string::npos &&
                (std::isalpha(static_cast<unsigned char>(tokens[0][0])) != 0);
            if (env_line) {
                command = trimmed;
                detail["env"] = true;
            } else {
                size_t cursor = 0;
                if (!tokens.empty() && !tokens[0].empty() && tokens[0][0] == '@') {
                    schedule = tokens[0];
                    cursor = 1;
                } else if (tokens.size() >= 5) {
                    schedule = JoinTokens(std::vector<std::string>(tokens.begin(),
                                                                 tokens.begin() + 5),
                                          0);
                    cursor = 5;
                }
                if (source.user_field && tokens.size() > cursor) {
                    user = tokens[cursor];
                    ++cursor;
                }
                command = JoinTokens(tokens, cursor);
                detail["env"] = false;
            }
            detail["schedule"] = schedule;
            detail["user"] = user;
            detail["command"] = command;
            items.push_back(
                {/*asset_type=*/"cron", source.path + " :: " + trimmed, detail.dump()});
        }
    }
    return items;
}

std::vector<std::string> AiWorkloadSignals(const std::string& cmdline,
                                           const std::string& environ,
                                           const std::string& maps) {
    std::vector<std::string> signals = MatchCmdlineAiSignals(cmdline);
    if (EnvironHasCudaVisibleDevices(environ)) {
        signals.push_back("env:CUDA_VISIBLE_DEVICES");
    }
    std::vector<std::string> maps_signals = MatchMapsAiSignals(maps);
    signals.insert(signals.end(), maps_signals.begin(), maps_signals.end());
    return signals;
}

bool IsAiWorkload(const std::string& cmdline, const std::string& environ,
                  const std::string& maps) {
    return !AiWorkloadSignals(cmdline, environ, maps).empty();
}
