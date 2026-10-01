#pragma once

#include <cstdint>
#include <cstring>
#include <list>
#include <string>
#include <unordered_map>

#include "event_record.hpp"   // record_set_str
#include "proc_event.h"       // PROC_KIND_*（bpf 头，纯数值宏）

// ── 进程树节点 ────────────────────────────────────────────────────
// 进程身份为 (pid, start_time)：pid 为 map 键，start_time 为版本号，
// 用于识别 pid 复用（同 pid 不同 start_time 视为新进程，替换旧节点）。
struct ProcNode {
    unsigned int pid = 0;
    unsigned int ppid = 0;
    unsigned long long start_time = 0;  // 进程启动时间（ns，CLOCK_MONOTONIC 域）
    char comm[16] = {0};
    char exe[256] = {0};
    unsigned int uid = 0;   // real uid（fork/exec 事件值；bootstrap 读 /proc status）
    unsigned int gid = 0;   // real gid
    char container_id[13] = {0};  // 12 位短 ID + NUL；空串 = 宿主机（exec 时填充）
    bool exited = false;                 // tombstone 标记
    unsigned long long exit_time_ms = 0; // 退出时间（steady ms），sweep 依据

    std::string comm_str() const { return std::string(comm, strnlen(comm, sizeof(comm))); }
    std::string exe_str() const { return std::string(exe, strnlen(exe, sizeof(exe))); }
    std::string container_id_str() const {
        return std::string(container_id, strnlen(container_id, sizeof(container_id)));
    }
};

// ── 进程树缓存 ────────────────────────────────────────────────────
// 由消费线程单线程维护，无锁。启动时全量扫 /proc bootstrap（含 uid/gid、
// 容器 ID）；fork 建节点（存事件 uid/gid）、exec 更新 comm/exe/uid/gid/
// container_id（无此 pid 则就地补建）、exit 打 tombstone（60s 后周期 sweep
// 清除）；LRU 上限 100000 节点。
class ProcessTree {
public:
    static constexpr size_t kMaxNodes = 100000;
    static constexpr unsigned long long kTombstoneMs = 60000;  // 60s

    ProcessTree() = default;

    // 启动时全量扫 /proc 建立初始进程树（消费线程初始化时调用一次）
    void bootstrap();

    // 应用一条 fork/exec/exit 事件（消费线程调用，单线程无锁）
    void apply(const proc_event& pe);

    // 按 pid 查节点（供富化器沿祖先链上溯）；不存在返回 nullptr
    const ProcNode* find(unsigned int pid) const;

    // 按 (pid, start_time) 查节点：start_time 非 0 且与节点不一致（pid 复用）
    // 时返回 nullptr；start_time 为 0 退化为 find(pid)
    const ProcNode* find(unsigned int pid, unsigned long long start_time) const;

    // 清除超过 60s 的 tombstone（周期调用）
    void sweep_tombstones();

    size_t size() const { return nodes_.size(); }
    size_t tombstone_count() const;

private:
    void upsert(ProcNode&& node);
    void touch_lru(unsigned int pid);

    std::unordered_map<unsigned int, ProcNode> nodes_;       // pid -> 节点（含 tombstone）
    std::list<unsigned int> lru_;                            // front=最近使用
    std::unordered_map<unsigned int, std::list<unsigned int>::iterator> lru_pos_;  // pid -> LRU 位置
};
