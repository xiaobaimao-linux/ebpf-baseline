#include "process_tree.hpp"

#include <chrono>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <time.h>
#include <unistd.h>
#include <vector>

#include <spdlog/spdlog.h>

#include "container.hpp"   // exe_path_of

namespace {

long long now_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<long long>(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
}

long clk_tck() {
    static long hz = sysconf(_SC_CLK_TCK);
    return hz > 0 ? hz : 100;
}

// 解析 /proc/<pid>/stat：comm 取第一个 '(' 与最后一个 ')' 之间（comm 可含
// 空格/括号，必须找最后一个 ')'）；')' 之后字段从 state(3) 起，ppid=字段4、
// starttime=字段22。starttime 单位为 clock ticks，换算为 ns。
// 任一解析失败返回 false（短寿进程 /proc 已回收属正常场景）。
bool read_proc_stat(int pid, std::string* comm, unsigned int* ppid,
                    unsigned long long* start_time_ns) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    std::ifstream in(path);
    if (!in.is_open())
        return false;

    // /proc/<pid>/stat 读取与进程退出存在竞态：打开成功（进程活着）后进程退出，
    // libstdc++ 的 basic_filebuf::underflow 遇 ESRCH 直接抛 ios_failure，
    // 必须兜底，否则异常穿透导致 monitor 进程 terminate
    std::string content;
    try {
        content.assign(std::istreambuf_iterator<char>(in),
                       std::istreambuf_iterator<char>());
    } catch (const std::ios_base::failure&) {
        return false;
    }
    const size_t lparen = content.find('(');
    const size_t rparen = content.rfind(')');
    if (lparen == std::string::npos || rparen == std::string::npos || rparen < lparen)
        return false;

    if (comm)
        *comm = content.substr(lparen + 1, rparen - lparen - 1);

    // ')' 之后：state ppid pgrp session tty_nr tpgid flags minflt cminflt
    // majflt cmajflt utime stime cutime cstime priority nice num_threads
    // itrealvalue starttime（字段 3..22）
    std::istringstream iss(content.substr(rparen + 1));
    std::string state;
    long long ppid_raw = 0;
    long long start_ticks = 0;
    iss >> state >> ppid_raw;                    // state(3), ppid(4)
    for (int field = 5; field <= 21; field++) {  // 跳过字段 5..21
        long long skip;
        if (!(iss >> skip))
            return false;
    }
    if (!(iss >> start_ticks))                   // starttime(22)
        return false;

    if (ppid)
        *ppid = static_cast<unsigned int>(ppid_raw);
    if (start_time_ns)
        *start_time_ns = static_cast<unsigned long long>(start_ticks) * 1000000000ULL /
                         static_cast<unsigned long long>(clk_tck());
    return true;
}

// 解析 /proc/<pid>/status 的 Uid/Gid 行（real 值，即每行第 1 个数字）；
// 读不到（短寿进程已回收）返回 false，输出保持 0。bootstrap 补进程身份用。
bool read_proc_status_ids(int pid, unsigned int* uid, unsigned int* gid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    std::ifstream in(path);
    if (!in.is_open())
        return false;

    // 同 read_proc_stat：打开后进程退出，getline 遇 ESRCH 抛 ios_failure，兜底
    bool got_uid = false, got_gid = false;
    std::string line;
    try {
        while (std::getline(in, line)) {
            std::istringstream iss(line);
            std::string key;
            unsigned long value = 0;
            if (line.rfind("Uid:", 0) == 0) {
                iss >> key >> value;
                *uid = static_cast<unsigned int>(value);
                got_uid = true;
            } else if (line.rfind("Gid:", 0) == 0) {
                iss >> key >> value;
                *gid = static_cast<unsigned int>(value);
                got_gid = true;
            }
            if (got_uid && got_gid)
                break;
        }
    } catch (const std::ios_base::failure&) {
        return false;
    }
    return got_uid || got_gid;
}

} // namespace

void ProcessTree::bootstrap() {
    DIR* dir = opendir("/proc");
    if (!dir) {
        spdlog::warn("[process_tree] failed to open /proc for bootstrap");
        return;
    }
    int loaded = 0;
    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        // 仅处理数字目录（pid）
        if (ent->d_name[0] < '0' || ent->d_name[0] > '9')
            continue;
        const int pid = atoi(ent->d_name);
        if (pid <= 0)
            continue;

        ProcNode node;
        node.pid = static_cast<unsigned int>(pid);
        std::string comm;
        unsigned int ppid = 0;
        unsigned long long start_ns = 0;
        if (read_proc_stat(pid, &comm, &ppid, &start_ns)) {
            node.ppid = ppid;
            node.start_time = start_ns;
            if (!comm.empty())
                record_set_str(node.comm, sizeof(node.comm), comm.c_str(), comm.size());
        }
        std::string exe = exe_path_of(pid);
        if (!exe.empty())
            record_set_str(node.exe, sizeof(node.exe), exe.c_str(), exe.size());
        // 进程身份：/proc status 的 Uid/Gid 行 + 容器短 ID（宿主机为空串）
        unsigned int uid = 0, gid = 0;
        if (read_proc_status_ids(pid, &uid, &gid)) {
            node.uid = uid;
            node.gid = gid;
        }
        const std::string cid = container_id_of(pid);
        if (!cid.empty())
            record_set_str(node.container_id, sizeof(node.container_id),
                           cid.c_str(), cid.size());
        upsert(std::move(node));
        loaded++;
    }
    closedir(dir);
    spdlog::info("[process_tree] bootstrap loaded {} processes", loaded);
}

void ProcessTree::apply(const proc_event& pe) {
    switch (pe.kind) {
    case PROC_KIND_FORK: {
        // 建子进程节点。ppid 以事件（tracepoint parent_pid）为准；
        // fork 事件 start_time 为 0（内核侧不可得），读 /proc/<child>/stat
        // 仅补 start_time（尽力；子进程可能已退出则保持 0）。
        ProcNode node;
        node.pid = pe.pid;
        node.ppid = pe.ppid;
        node.uid = pe.uid;
        node.gid = pe.gid;
        record_set_str(node.comm, sizeof(node.comm), pe.comm, strnlen(pe.comm, sizeof(pe.comm)));
        // fork 不填 container_id：子进程尚未 exec，等 exec 事件统一填

        unsigned long long start_ns = 0;
        if (read_proc_stat(static_cast<int>(pe.pid), nullptr, nullptr, &start_ns))
            node.start_time = start_ns;
        std::string exe = exe_path_of(static_cast<int>(pe.pid));
        if (!exe.empty())
            record_set_str(node.exe, sizeof(node.exe), exe.c_str(), exe.size());
        upsert(std::move(node));
        break;
    }
    case PROC_KIND_EXEC: {
        // exec 更新 comm/exe；树中无此 pid 则就地补建；start_time 不同
        // 视为 pid 复用（新进程），重置节点。
        auto it = nodes_.find(pe.pid);
        if (it == nodes_.end()) {
            // 就地补建：同样存事件 uid/gid，并按当前 /proc 状态填容器 ID
            ProcNode node;
            node.pid = pe.pid;
            node.ppid = pe.ppid;
            node.uid = pe.uid;
            node.gid = pe.gid;
            node.start_time = pe.start_time;
            record_set_str(node.comm, sizeof(node.comm), pe.comm,
                           strnlen(pe.comm, sizeof(pe.comm)));
            std::string exe = exe_path_of(static_cast<int>(pe.pid));
            if (!exe.empty())
                record_set_str(node.exe, sizeof(node.exe), exe.c_str(), exe.size());
            else
                record_set_str(node.exe, sizeof(node.exe), pe.exe, strnlen(pe.exe, sizeof(pe.exe)));
            const std::string cid = container_id_of(static_cast<int>(pe.pid));
            if (!cid.empty())
                record_set_str(node.container_id, sizeof(node.container_id),
                               cid.c_str(), cid.size());
            upsert(std::move(node));
            break;
        }
        ProcNode& node = it->second;
        if (pe.start_time != 0 && node.start_time != 0 && pe.start_time != node.start_time) {
            // pid 复用：重置为新进程
            node.start_time = pe.start_time;
            node.exited = false;
            node.exit_time_ms = 0;
        }
        node.uid = pe.uid;
        node.gid = pe.gid;
        record_set_str(node.comm, sizeof(node.comm), pe.comm, strnlen(pe.comm, sizeof(pe.comm)));
        std::string exe = exe_path_of(static_cast<int>(pe.pid));
        if (!exe.empty())
            record_set_str(node.exe, sizeof(node.exe), exe.c_str(), exe.size());
        else if (strnlen(pe.exe, sizeof(pe.exe)) > 0)
            record_set_str(node.exe, sizeof(node.exe), pe.exe, strnlen(pe.exe, sizeof(pe.exe)));
        // exec 统一刷新容器归属：有容器填短 ID，回到宿主机则清空
        const std::string cid = container_id_of(static_cast<int>(pe.pid));
        if (!cid.empty())
            record_set_str(node.container_id, sizeof(node.container_id),
                           cid.c_str(), cid.size());
        else
            node.container_id[0] = '\0';
        if (pe.start_time != 0)
            node.start_time = pe.start_time;
        node.exited = false;
        touch_lru(pe.pid);
        break;
    }
    case PROC_KIND_EXIT: {
        auto it = nodes_.find(pe.pid);
        if (it != nodes_.end()) {
            it->second.exited = true;
            it->second.exit_time_ms = static_cast<unsigned long long>(now_ms());
            touch_lru(pe.pid);
        } else {
            // 未见过的进程退出：补一条 tombstone，供迟到的引用查到“已退出”
            ProcNode node;
            node.pid = pe.pid;
            node.ppid = pe.ppid;
            node.uid = pe.uid;
            node.gid = pe.gid;
            node.start_time = pe.start_time;
            record_set_str(node.comm, sizeof(node.comm), pe.comm,
                           strnlen(pe.comm, sizeof(pe.comm)));
            node.exited = true;
            node.exit_time_ms = static_cast<unsigned long long>(now_ms());
            upsert(std::move(node));
        }
        break;
    }
    default:
        break;
    }
}

const ProcNode* ProcessTree::find(unsigned int pid) const {
    auto it = nodes_.find(pid);
    return it == nodes_.end() ? nullptr : &it->second;
}

const ProcNode* ProcessTree::find(unsigned int pid, unsigned long long start_time) const {
    const ProcNode* node = find(pid);
    if (node == nullptr)
        return nullptr;
    // start_time 非 0 且与节点不一致：视为 pid 复用后的旧进程节点，返回空。
    // 注：bootstrap/fork 节点的 start_time 来自 /proc stat（USER_HZ 滴答粒度），
    // 与事件内 task->start_time 精确值可能相差一个滴答，属已知限制。
    if (start_time != 0 && node->start_time != start_time)
        return nullptr;
    return node;
}

void ProcessTree::sweep_tombstones() {
    const unsigned long long deadline = static_cast<unsigned long long>(now_ms()) - kTombstoneMs;
    std::vector<unsigned int> dead;
    dead.reserve(64);
    for (const auto& [pid, node] : nodes_) {
        if (node.exited && node.exit_time_ms <= deadline)
            dead.push_back(pid);
    }
    for (unsigned int pid : dead) {
        nodes_.erase(pid);
        auto lit = lru_pos_.find(pid);
        if (lit != lru_pos_.end()) {
            lru_.erase(lit->second);
            lru_pos_.erase(lit);
        }
    }
    if (!dead.empty())
        spdlog::debug("[process_tree] swept {} tombstones, {} nodes left",
                      dead.size(), nodes_.size());
}

size_t ProcessTree::tombstone_count() const {
    size_t n = 0;
    for (const auto& [pid, node] : nodes_) {
        (void)pid;
        if (node.exited)
            n++;
    }
    return n;
}

void ProcessTree::upsert(ProcNode&& node) {
    const unsigned int pid = node.pid;
    auto it = nodes_.find(pid);
    if (it != nodes_.end()) {
        it->second = std::move(node);
        touch_lru(pid);
        return;
    }
    nodes_.emplace(pid, std::move(node));
    lru_.push_front(pid);
    lru_pos_[pid] = lru_.begin();
    // LRU 上限：淘汰最久未使用节点
    while (nodes_.size() > kMaxNodes) {
        unsigned int victim = lru_.back();
        lru_.pop_back();
        lru_pos_.erase(victim);
        nodes_.erase(victim);
    }
}

void ProcessTree::touch_lru(unsigned int pid) {
    auto it = lru_pos_.find(pid);
    if (it != lru_pos_.end())
        lru_.splice(lru_.begin(), lru_, it->second);
}
