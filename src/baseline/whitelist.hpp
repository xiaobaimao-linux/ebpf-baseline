#pragma once

#include <sys/types.h>

#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "config.hpp"

// 进程白名单匹配器（M0-2）：
// WhitelistTable 为不可变快照，Build() 后只读；热加载以 std::shared_ptr
// 原子替换，匹配线程持 const 副本无锁读表。
// WhitelistMatcher 持有 LRU 缓存与抑制计数（内部小 mutex，与表数据无关）。
//
// 语义：条目内 AND（exe 精确相等 且（无 parent_chain 或 任一祖先 exe ∈ parent_chain）），
// 条目间 OR。exe 一律 readlink /proc/<pid>/exe 精确匹配，失败 fail-closed（不豁免）。

class WhitelistTable {
public:
    // 从配置构建不可变白名单快照（仅收录带 whitelist 的规则）
    static std::shared_ptr<const WhitelistTable> Build(const Config& config);

    // 规则命中白名单判定（exe 为 /proc/<pid>/exe 解析结果，ancestors 自近及远）
    bool Match(const Rule& rule, const std::string& exe,
               const std::vector<std::string>& ancestors) const;

    bool empty() const { return by_rule_.empty(); }

private:
    struct CompiledEntry {
        std::string exe;
        std::vector<std::string> parent_chain;
    };
    // 以 rule.id 为键；id 为空的规则共享空 id 键（v0.1 约定，配置中应避免）
    std::unordered_map<std::string, std::vector<CompiledEntry>> by_rule_;
};

class WhitelistMatcher {
public:
    // 白名单判定：/proc 全解析路径。/proc/<pid>/exe readlink 失败 → false（fail-closed）；
    // 祖先链沿 /proc/<pid>/stat 的 ppid 上溯 ≤8 层（环路检测，断链有几层算几层）。
    // 命中时内部抑制计数 +1。out_exe 非空时回填解析出的进程 exe 路径（留痕用）。
    bool Match(const WhitelistTable& table, const Rule& rule, pid_t pid,
               std::string* out_exe = nullptr);

    // 事件上下文直通：exe/祖先由进程树在 exec 时捕获（短寿进程 /proc 已回收场景，
    // 与 /proc 解析等价且更及时）。known_exe 为空 → fail-closed（同 readlink 失败）。
    // start_time 作缓存键防 PID 复用，传 0 表示本次不缓存。
    bool Match(const WhitelistTable& table, const Rule& rule,
               pid_t pid, unsigned long long start_time,
               const std::string& known_exe,
               const std::vector<std::string>& known_ancestors,
               std::string* out_exe = nullptr);

    void ClearCache();

    // 取并清零各 rule 抑制计数（供 60s 周期日志打增量）
    std::vector<std::pair<std::string, uint64_t>> GetAndResetSuppressed();

    // LRU 缓存当前条数（单测用）
    size_t CacheSize() const;

private:
    // 共享收尾：缓存读写 + 表匹配 + 抑制计数。cacheable=false（start_time=0）时不走缓存
    bool match_resolved(const WhitelistTable& table, const Rule& rule,
                        pid_t pid, unsigned long long start_time,
                        const std::string& exe,
                        const std::vector<std::string>& ancestors,
                        bool cacheable, std::string* out_exe);

private:
    struct CacheKey {
        pid_t pid;
        unsigned long long start_time;   // stat 字段 22，防 PID 复用误判
        bool operator==(const CacheKey& o) const {
            return pid == o.pid && start_time == o.start_time;
        }
    };
    struct CacheKeyHash {
        size_t operator()(const CacheKey& k) const {
            return std::hash<pid_t>()(k.pid) ^
                   (std::hash<unsigned long long>()(k.start_time) << 1);
        }
    };

    static constexpr size_t kMaxCacheSize = 1024;

    mutable std::mutex mu_;
    // LRU：list 头部为最近使用
    std::list<std::pair<CacheKey, bool>> lru_;
    std::unordered_map<CacheKey, std::list<std::pair<CacheKey, bool>>::iterator,
                       CacheKeyHash> cache_;
    std::unordered_map<std::string, uint64_t> suppressed_;
};
