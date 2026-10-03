#include "whitelist.hpp"

#include <cstdio>
#include <cstring>
#include <unordered_set>

#include "container.hpp"

// ── /proc 解析 ─────────────────────────────────────────────────

namespace {

struct ProcStatInfo {
    pid_t ppid = 0;
    unsigned long long start_time = 0;
};

// 解析 /proc/<pid>/stat：comm 可能含空格或 ')'，先找最后一个 ')' 再切字段；
// ')' 之后字段依次为 state(3) ppid(4) ... starttime(22)，即 token[0]=state、
// token[1]=ppid、token[19]=starttime。解析失败返回 false。
bool parse_proc_stat(pid_t pid, ProcStatInfo* out) {
    char path[64];
    char buf[4096];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE* f = fopen(path, "r");
    if (!f)
        return false;
    const size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0)
        return false;
    buf[n] = '\0';

    const char* rp = strrchr(buf, ')');
    if (!rp)
        return false;
    ++rp;  // 跳过 ')'，其后为 " S ppid pgrp ..." 序列

    bool have_ppid = false;
    bool have_start = false;
    int idx = 0;
    const char* p = rp;
    while (idx <= 19) {
        while (*p == ' ' || *p == '\t')
            ++p;
        if (*p == '\0' || *p == '\n')
            break;
        const char* tok = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n')
            ++p;
        // token 未以 '\0' 结尾，但其后必为空白；strtol/strtoull 遇空白即止
        if (idx == 1) {
            out->ppid = static_cast<pid_t>(strtol(tok, nullptr, 10));
            have_ppid = true;
        } else if (idx == 19) {
            out->start_time = strtoull(tok, nullptr, 10);
            have_start = true;
        }
        ++idx;
    }
    return have_ppid && have_start;
}

// 沿 ppid 上溯 ≤8 层收集每层祖先 exe（自近及远）；
// visited 做环路检测；某层 exe 解析失败（短寿/内核线程）即断链，有几层算几层
std::vector<std::string> collect_ancestors(pid_t pid, pid_t ppid) {
    std::vector<std::string> ancestors;
    std::unordered_set<pid_t> visited;
    visited.insert(pid);
    pid_t cur = ppid;
    for (int depth = 0; depth < 8 && cur > 0; ++depth) {
        if (!visited.insert(cur).second)
            break;  // 环路防御
        std::string aexe = exe_path_of(static_cast<int>(cur));
        if (aexe.empty())
            break;  // 断链：已收集层数有效
        ancestors.push_back(aexe);
        ProcStatInfo psi;
        if (!parse_proc_stat(cur, &psi))
            break;
        cur = psi.ppid;
    }
    return ancestors;
}

}  // namespace

// ── WhitelistTable（不可变快照）─────────────────────────────────

std::shared_ptr<const WhitelistTable> WhitelistTable::Build(const Config& config) {
    auto t = std::make_shared<WhitelistTable>();
    for (const auto& rule : config.rules) {
        if (rule.whitelist.empty())
            continue;
        auto& entries = t->by_rule_[rule.id];
        for (const auto& we : rule.whitelist) {
            entries.push_back(CompiledEntry{we.exe, we.parent_chain});
        }
    }
    return t;
}

bool WhitelistTable::Match(const Rule& rule, const std::string& exe,
                           const std::vector<std::string>& ancestors) const {
    auto it = by_rule_.find(rule.id);
    if (it == by_rule_.end())
        return false;
    for (const auto& e : it->second) {
        if (e.exe != exe)
            continue;  // 条目内 AND：exe 精确相等
        if (e.parent_chain.empty())
            return true;
        for (const auto& anc : ancestors) {
            for (const auto& pc : e.parent_chain) {
                if (anc == pc)
                    return true;  // 任一祖先 exe 命中即可
            }
        }
    }
    return false;
}

// ── WhitelistMatcher（LRU 缓存 + 抑制计数）─────────────────────

// /proc 全解析路径：stat 取 (ppid, start_time) 与缓存键，失败（进程已退出）→ fail-closed
bool WhitelistMatcher::Match(const WhitelistTable& table, const Rule& rule, pid_t pid,
                             std::string* out_exe) {
    if (pid <= 0)
        return false;

    ProcStatInfo psi;
    if (!parse_proc_stat(pid, &psi))
        return false;

    // exe 精确路径：readlink 失败（短寿进程 /proc 回收等）→ fail-closed，不豁免
    const std::string exe = exe_path_of(static_cast<int>(pid));
    if (exe.empty())
        return false;

    return match_resolved(table, rule, pid, psi.start_time, exe,
                          collect_ancestors(pid, psi.ppid), true, out_exe);
}

// 事件上下文直通（进程树捕获的 exe/祖先）
bool WhitelistMatcher::Match(const WhitelistTable& table, const Rule& rule,
                             pid_t pid, unsigned long long start_time,
                             const std::string& known_exe,
                             const std::vector<std::string>& known_ancestors,
                             std::string* out_exe) {
    if (pid <= 0 || known_exe.empty())
        return false;  // 上下文无 exe：同 readlink 失败，fail-closed

    return match_resolved(table, rule, pid, start_time, known_exe, known_ancestors,
                          start_time != 0, out_exe);
}

bool WhitelistMatcher::match_resolved(const WhitelistTable& table, const Rule& rule,
                                      pid_t pid, unsigned long long start_time,
                                      const std::string& exe,
                                      const std::vector<std::string>& ancestors,
                                      bool cacheable, std::string* out_exe) {
    const CacheKey key{pid, start_time};
    if (cacheable) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = cache_.find(key);
        if (it != cache_.end()) {
            const bool hit = it->second->second;
            lru_.splice(lru_.begin(), lru_, it->second);
            if (hit)
                ++suppressed_[rule.id];   // 命中也要计数：每次抑制都是一条被拦截的告警
            if (out_exe)
                *out_exe = exe;
            return hit;
        }
    }

    const bool hit = table.Match(rule, exe, ancestors);
    if (out_exe)
        *out_exe = exe;

    std::lock_guard<std::mutex> lk(mu_);
    if (cacheable) {
        auto it = cache_.find(key);
        if (it != cache_.end()) {
            it->second->second = hit;
            lru_.splice(lru_.begin(), lru_, it->second);
        } else {
            lru_.emplace_front(key, hit);
            cache_[key] = lru_.begin();
            while (cache_.size() > kMaxCacheSize) {
                cache_.erase(lru_.back().first);
                lru_.pop_back();
            }
        }
    }
    if (hit)
        ++suppressed_[rule.id];
    return hit;
}

void WhitelistMatcher::ClearCache() {
    std::lock_guard<std::mutex> lk(mu_);
    cache_.clear();
    lru_.clear();
}

std::vector<std::pair<std::string, uint64_t>> WhitelistMatcher::GetAndResetSuppressed() {
    std::vector<std::pair<std::string, uint64_t>> out;
    std::lock_guard<std::mutex> lk(mu_);
    out.assign(suppressed_.begin(), suppressed_.end());
    suppressed_.clear();
    return out;
}

size_t WhitelistMatcher::CacheSize() const {
    std::lock_guard<std::mutex> lk(mu_);
    return cache_.size();
}
