#include "monitor.hpp"
#include "bpf/event.h"
#include "monitor_baseline.hpp"
#include "monitor_network.hpp"
#include "monitor_privilege.hpp"
#include "monitor_process.hpp"
#include "watermark_backpressure.hpp"
#include "utils.hpp"
#include "config.hpp"
#include "commonfun.hpp"
#include "container.hpp"
#include "baseline_db.hpp"
#include "event_bus.hpp"
#include "event_record.hpp"
#include "event_store.hpp"
#include "process_tree.hpp"
#include "enricher.hpp"
#include "rule_engine.hpp"
#include "rule_loader.hpp"
#include "net_event.h"
#include "priv_event.h"
#include "proc_event.h"
#include "whitelist.hpp"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <csignal>
#include <malloc.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <linux/types.h>
#include <nlohmann/json.hpp>
#include <pwd.h>
#include <shared_mutex>
#include <spdlog/spdlog.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <thread>
#include <unistd.h>
#include <map>
#include <unordered_map>
#include <vector>
#include <sstream>

using json = nlohmann::json;

// 包含生成的skeleton头文件（经 -I. 从仓库根目录引用 bpf/）
#include "bpf/lsm_file.skel.h"        // 5.8+ ring buffer
#include "bpf/lsm_file_perf.skel.h"   // 5.7 perf buffer
#include "bpf/lsm_kprobe.skel.h"      // 5.4 kprobe

static volatile bool running = true;

// ── 内核版本检测 ────────────────────────────────────────────────
struct KernelVersion { unsigned int major, minor; };

static KernelVersion get_kernel_version() {
    static KernelVersion cached = {0, 0};
    static bool initialized = false;
    if (initialized) return cached;

    struct utsname uts;
    if (uname(&uts) == 0) {
        sscanf(uts.release, "%u.%u", &cached.major, &cached.minor);
    }
    initialized = true;
    return cached;
}

static bool kernel_at_least(unsigned int major, unsigned int minor) {
    auto kv = get_kernel_version();
    return kv.major > major || (kv.major == major && kv.minor >= minor);
}

void signal_handler(int sig) {
    running = false;
    if (sig == SIGTERM) {
        spdlog::info("[service_stop] received SIGTERM, shutting down gracefully");
    }
}

static std::string ResolveUserInfoByPid(int pid, std::string& uid) {
    uid.clear();
    std::string user_name;

    if (pid <= 0) {
        return user_name;
    }

    // /proc/<pid>/status 读取与进程退出存在竞态：libstdc++ 的
    // basic_filebuf::underflow 遇 ESRCH 会直接抛 ios_failure，
    // 必须兜底，否则异常穿透导致 monitor 进程 terminate
    try {
        const std::string proc_status = "/proc/" + std::to_string(pid) + "/status";
        std::ifstream in(proc_status);
        if (!in.is_open()) {
            return user_name;
        }

        std::string line;
        while (std::getline(in, line)) {
            if (line.rfind("Uid:", 0) == 0) {
                std::istringstream iss(line);
                std::string key;
                iss >> key;
                int raw_uid = 0;
                iss >> raw_uid;
                if (raw_uid > 0) {
                    uid = std::to_string(raw_uid);
                    struct passwd* pw = getpwuid(static_cast<uid_t>(raw_uid));
                    if (pw != nullptr) {
                        user_name = pw->pw_name;
                    }
                }
                break;
            }
        }
    } catch (const std::ios_base::failure&) {
        // 进程在打开 /proc/<pid>/status 后退出：按未知用户处理
    }

    return user_name;
}

// ── 规则表快照与热加载（M0-2）────────────────────────────────────
// FileRuleTable 为整代不可变快照：SIGHUP 热加载在写锁内整体替换；
// 事件处理（消费线程 / perf 主循环）持读锁访问，锁内 Rule 引用恒有效。
// R13：inode_to_rules 一对多——同一文件配置多条规则时各自独立告警
//（原先 unordered_map<ino, Rule> 后写覆盖先写，仅最后一条生效）。
struct FileRuleTable {
    std::unordered_map<unsigned long, std::vector<Rule>> inode_to_rules;
    std::unordered_map<unsigned long, std::string> inode_to_path;
    std::unordered_map<unsigned long, std::vector<std::string>> inode_to_hashes;

    static std::shared_ptr<FileRuleTable> Build(const Config& config) {
        auto t = std::make_shared<FileRuleTable>();
        for (const auto& rule : config.rules) {
            if (!rule.has_monitor)
                continue;
            if (rule.monitor_path.empty())
                continue;
            if (rule.ino == 0)
                continue;
            t->inode_to_rules[rule.ino].push_back(rule);
            t->inode_to_path[rule.ino] = rule.monitor_path;
            if (!rule.check_hash.empty())
                t->inode_to_hashes[rule.ino].push_back(rule.check_hash);
        }
        return t;
    }
};

static std::shared_ptr<FileRuleTable> g_file_rules = std::make_shared<FileRuleTable>();
// 白名单不可变快照，与规则表同锁替换：读侧持锁取 const 引用，匹配无锁读表
static std::shared_ptr<const WhitelistTable> g_whitelist_table =
    std::make_shared<const WhitelistTable>();
// DSL 规则引擎快照（W4）：与 FileRuleTable 同锁整代替换；空引擎求值一次分支即返回
static std::shared_ptr<const detect::RuleEngine> g_rule_engine =
    std::make_shared<const detect::RuleEngine>();
static std::shared_mutex g_file_rules_mtx;
static WhitelistMatcher g_whitelist_matcher;

// 消费线程取引擎快照（shared_ptr 拷贝，锁内一次原子增减）
static std::shared_ptr<const detect::RuleEngine> rule_engine_snapshot() {
    std::shared_lock<std::shared_mutex> lk(g_file_rules_mtx);
    return g_rule_engine;
}

// 启动/热加载共用：严格加载 rules_dir 并编译引擎；失败返回 nullptr（调用方保留旧快照）
static std::shared_ptr<const detect::RuleEngine> build_rule_engine(const RuleEngineConfig& cfg) {
    if (!cfg.enabled)
        return std::make_shared<const detect::RuleEngine>();
    std::vector<detect::Rule> rules;
    std::string err;
    if (!detect::LoadRulesDir(cfg.rules_dir, rules, err)) {
        spdlog::error("[rule_engine] 规则加载失败: {}", err);
        return nullptr;
    }
    auto engine = std::make_shared<detect::RuleEngine>();
    if (!engine->Build(std::move(rules), err)) {
        spdlog::error("[rule_engine] 规则编译失败: {}", err);
        return nullptr;
    }
    return engine;
}

// 基线实时监控映射：inode -> CheckEntry（仅当 --db 模式下非空；启动时构建，热加载不变更）
std::unordered_map<unsigned long, CheckEntry> g_inode_to_baseline;

// ── SIGHUP 热加载 ─────────────────────────────────────────────
// handler 只置标志；主事件循环每轮检查发现置位即重解析配置：
// 成功原子替换规则表与白名单快照并清缓存，失败保留旧配置
static volatile sig_atomic_t g_sighup_pending = 0;

static void monitor_sighup_handler(int) {
    g_sighup_pending = 1;
}

static void reload_monitor_config(const std::string& config_path) {
    Config new_config;
    std::string err;
    if (!tryParseYamlFile(config_path, new_config, err)) {
        spdlog::error("[config_reload] 失败，保留旧配置: {}", err);
        return;
    }
    compute_inodes(new_config);
    auto new_rules = FileRuleTable::Build(new_config);
    auto new_wl = WhitelistTable::Build(new_config);
    // 规则引擎同步整代替换：加载失败整体保留旧快照（文件规则表也不换）
    auto new_engine = build_rule_engine(new_config.rule_engine);
    if (new_engine == nullptr) {
        spdlog::error("[config_reload] 规则引擎加载失败，保留旧配置");
        return;
    }
    {
        std::unique_lock<std::shared_mutex> lk(g_file_rules_mtx);
        g_file_rules = std::move(new_rules);
        g_whitelist_table = std::move(new_wl);
        g_rule_engine = std::move(new_engine);
    }
    g_whitelist_matcher.ClearCache();
    spdlog::info("config reloaded ({} rules)", new_config.rules.size());
}

// 60s 周期：各 rule 白名单抑制计数增量打一行 info（无增量不打）；
// 附告警节流抑制累计（M5-3 "已抑制 N 条" 对账口径，自进程启动累计不重置）。
static void log_suppressed_stats(const AlertManager* alert_mgr = nullptr) {
    for (const auto& [rule_id, n] : g_whitelist_matcher.GetAndResetSuppressed()) {
        if (n > 0)
            spdlog::info("[whitelist] suppressed: rule={} count={}", rule_id, n);
    }
    if (alert_mgr != nullptr && alert_mgr->ThrottledTotal() > 0) {
        spdlog::info("[alerts] throttled: total={}", alert_mgr->ThrottledTotal());
        for (const auto& [rule_id, n] : alert_mgr->ThrottledByRule())
            spdlog::info("[alerts] throttled: rule={} count={}", rule_id, n);
    }
}


void on_violation_detected(const Rule& rule,
                           const std::string& file_path,
                           const std::string& actual_mode,
                           const std::string& proc_name,
                           int pid,
                           AlertManager& alert_mgr,
                           const FileActorContext* actor)
{
    // actor 非空（进程树命中）：user_name/uid 直接用 actor 值，跳过 /proc 读取；
    // actor 为空走现有 /proc 兜底（行为与现状一致）
    std::string uid;
    std::string user_name;
    if (actor != nullptr) {
        uid = std::to_string(actor->uid);
        user_name = actor->user_name;
    } else {
        user_name = ResolveUserInfoByPid(pid, uid);
    }

    // 1. 写日志
    spdlog::warn("VIOLATION: {} mode {} -> {} by {}/{} user={} uid={}",
                 file_path, mode_to_string(rule.check_expected), actual_mode, proc_name, pid,
                 user_name.empty() ? "unknown" : user_name,
                 uid.empty() ? "-" : uid);

    // 2. 节流窗口内不构建 AlertEvent：SendDingTalk 本来就不发不存，
    //    构建（含 ancestors JSON dump / NowString）纯属浪费（高频事件路径实测热点）；
    //    抑制计数在此入口记（不经 SendDingTalk，不会双计）
    if (alert_mgr.ThrottledNow(rule.id)) {
        alert_mgr.NoteThrottled(rule.id);
        return;
    }

    // 3. 发钉钉 + 自动落库（AlertManager 内部统一处理）
    AlertEvent evt;
    evt.rule_id      = rule.id;
    evt.rule_name    = rule.name;
    evt.severity     = severityToString(rule.severity);
    evt.file_path    = file_path;
    evt.expected     = mode_to_string(rule.check_expected);
    evt.actual       = actual_mode;
    evt.process_name = proc_name;
    evt.pid          = pid;
    evt.user_name    = user_name;
    evt.uid          = uid;
    evt.timestamp    = NowString();
    evt.event_type   = actual_mode;  // read / write
    evt.action_taken = actionToString(rule.monitor_action);
    if (actor != nullptr) {
        evt.exe          = actor->exe;
        evt.container_id = actor->container_id;
        evt.ancestors    = actor->ancestors_json;
    }

    alert_mgr.SendDingTalk(evt);
}

void on_check_mismatch_detected(const Rule& rule,
                                const std::string& file_path,
                                const std::string& proc_name,
                                int pid,
                                AlertManager& alert_mgr,
                                const FileActorContext* actor)
{
    if (!rule.has_check || rule.check_path.empty() || rule.check_path != file_path) {
        return;
    }

    struct stat st;
    if (stat(file_path.c_str(), &st) != 0) {
        return;
    }

    const mode_t actual_mode = st.st_mode & 0777;
    const bool expected_hash = !rule.check_hash.empty();
    const bool expected_perm = rule.check_expected != 0;

    // 文件可能在 stat 后读取前被删除，compute_sha256 抛异常时跳过本次比对
    std::string actual_hash;
    try {
        actual_hash = compute_sha256(const_cast<std::string&>(file_path));
    } catch (const std::exception &ex) {
        spdlog::debug("check mismatch skipped for {}: {}", file_path, ex.what());
        return;
    }

    bool permission_match = true;
    bool hash_match = true;

    if (expected_perm) {
        permission_match = (actual_mode == rule.check_expected);
    }
    if (expected_hash) {
        hash_match = (actual_hash == rule.check_hash);
    }

    if (permission_match && hash_match) {
        return;
    }

    std::string uid;
    std::string user_name;
    if (actor != nullptr) {
        uid = std::to_string(actor->uid);
        user_name = actor->user_name;
    } else {
        user_name = ResolveUserInfoByPid(pid, uid);
    }

    std::ostringstream msg;
    msg << "check mismatch detected by monitor";
    if (!permission_match) {
        msg << " permission=" << mode_to_string(actual_mode) << " expected=" << mode_to_string(rule.check_expected);
    }
    if (!hash_match) {
        msg << " hash=" << actual_hash << " expected=" << rule.check_hash;
    }

    spdlog::warn("[monitor_check_mismatch] {} process={} pid={} user={} uid={} file={}",
                 msg.str(), proc_name, pid,
                 user_name.empty() ? "unknown" : user_name,
                 uid.empty() ? "-" : uid,
                 file_path);

    AlertEvent evt;
    evt.rule_id      = rule.id;
    evt.rule_name    = rule.name;
    evt.severity     = severityToString(rule.severity);
    evt.file_path    = file_path;
    evt.expected     = (expected_perm ? mode_to_string(rule.check_expected) : "-");
    evt.actual       = (expected_perm ? mode_to_string(actual_mode) : "-");
    evt.process_name = proc_name;
    evt.pid          = pid;
    evt.user_name    = user_name;
    evt.uid          = uid;
    evt.timestamp    = NowString();
    evt.event_type   = "check_mismatch";
    evt.action_taken = actionToString(rule.monitor_action);

    if (!rule.check_hash.empty()) {
        evt.expected += "|hash=" + rule.check_hash;
        evt.actual += "|hash=" + actual_hash;
    }
    if (actor != nullptr) {
        evt.exe          = actor->exe;
        evt.container_id = actor->container_id;
        evt.ancestors    = actor->ancestors_json;
    }

    alert_mgr.SendDingTalk(evt);
}

// ── chmod/chown 事件处理（--db 模式下）──────────────────────────────
// eBPF 拦截到 chmod/chown 后，直接用事件中的新值与基线比对
// 无需 stat 磁盘文件（LSM hook 在操作前触发，磁盘上仍是旧值）
static void handle_chmod_chown_event(const struct event *e,
                                      AlertManager& alert_mgr,
                                      const FileActorContext* actor) {
    auto it_bl = g_inode_to_baseline.find(e->ino);
    if (it_bl == g_inode_to_baseline.end())
        return;

    const CheckEntry& baseline = it_bl->second;
    const std::string& file_path = baseline.file_path;
    std::string proc_name(reinterpret_cast<const char*>(e->comm), 16);
    // 去除尾部 \0
    auto null_pos = proc_name.find('\0');
    if (null_pos != std::string::npos) proc_name.resize(null_pos);

    if (e->event_type == EVENT_CHMOD) {
        std::string actual_perm = mode_to_string(e->new_mode & 0777);
        if (actual_perm != baseline.permission) {
            BaselineDeviation dev;
            dev.event_type = "perm_changed";
            dev.severity   = "medium";
            dev.expected   = "mode=" + baseline.permission;
            dev.actual     = "mode=" + actual_perm;
            HandleBaselineDeviation(dev, file_path, proc_name, e->pid, alert_mgr,
                                    kBaselineRuleId, actor);
        }
    } else if (e->event_type == EVENT_CHOWN) {
        bool uid_diff = (static_cast<int64_t>(e->new_uid) != baseline.uid);
        bool gid_diff = (static_cast<int64_t>(e->new_gid) != baseline.gid);
        if (uid_diff || gid_diff) {
            BaselineDeviation dev;
            dev.event_type = "own_changed";
            dev.severity   = "medium";
            std::string exp_parts, act_parts;
            if (uid_diff) {
                exp_parts += "uid=" + std::to_string(baseline.uid);
                act_parts += "uid=" + std::to_string(e->new_uid);
            }
            if (gid_diff) {
                if (!exp_parts.empty()) exp_parts += ", ";
                exp_parts += "gid=" + std::to_string(baseline.gid);
                if (!act_parts.empty()) act_parts += ", ";
                act_parts += "gid=" + std::to_string(e->new_gid);
            }
            dev.expected = exp_parts;
            dev.actual   = act_parts;
            HandleBaselineDeviation(dev, file_path, proc_name, e->pid, alert_mgr,
                                    kBaselineRuleId, actor);
        }
    }
}

// ── 监控上下文：聚合 AlertManager + 水位背压控制器 + 事件批量缓冲 ──
static constexpr size_t kMaxBatchSize = 1024;

struct MonitorContext {
    AlertManager*            alert_mgr    = nullptr;
    WatermarkBackpressure*   backpressure = nullptr;
    std::vector<struct event> event_batch;
    size_t                   dropped_count = 0;
    int                      user_stats_fd = -1;   // pinned user_stats map（批溢出计数暴露）
};

// ── 用户态计数器 → pinned user_stats map（stats --drop 读取）─────────
// 槽位定义见 bpf/stats_slots.h；bus/store 为空时对应槽写 0。
static void sync_user_stats(int fd, const EventBus* bus, const EventStore* store,
                            const MonitorContext* mctx) {
    if (fd < 0)
        return;
    __u64 vals[USER_STATS_SLOTS] = {};
    if (bus) {
        for (int p = 0; p < 4; p++) {
            vals[USTAT_BUS_DROP_HI_P0 + p] = bus->drop_count(true, p);
            vals[USTAT_BUS_DROP_LO_P0 + p] = bus->drop_count(false, p);
        }
        vals[USTAT_BUS_PUSHED]   = bus->pushed_count();
        vals[USTAT_BUS_HI_DEPTH] = bus->hi_depth();
        vals[USTAT_BUS_LO_DEPTH] = bus->lo_depth();
    }
    if (mctx)
        vals[USTAT_BATCH_OVERFLOW] = mctx->dropped_count;
    if (store) {
        vals[USTAT_STORE_FAILED] = store->failed_count();
        vals[USTAT_STORE_STORED] = store->stored_count();
    }
    for (__u32 i = 0; i < USER_STATS_SLOTS; i++)
        bpf_map_update_elem(fd, &i, &vals[i], BPF_ANY);
}

// pin 辅助：先 unlink 陈旧 pin（上次异常退出残留）再 pin，失败仅告警
static void pin_map_best_effort(struct bpf_map* map, const char* path) {
    unlink(path);
    if (int err = bpf_map__pin(map, path))
        spdlog::warn("[bpf_map_pin] failed to pin {}: {}", path, strerror(-err));
}

// ── 白名单匹配：从 FileActorContext.ancestors JSON 还原祖先 exe 链 ──
// ancestors 为 [{pid,comm,exe}] 自近及远 ≤8 层（Enricher::ancestors_of 产物）
static std::vector<std::string> actor_ancestor_exes(const json& ancestors) {
    std::vector<std::string> out;
    if (ancestors.is_array()) {
        for (const auto& a : ancestors) {
            if (a.contains("exe") && a["exe"].is_string())
                out.push_back(a["exe"].get<std::string>());
        }
    }
    return out;
}

// ── 核心事件处理逻辑（前向声明）─────────────────────────────────────
// actor 非空时为消费线程按 (pid, start_time) 查进程树组装的进程上下文，
// 用于告警富化（user_name/uid/exe/container_id/ancestors）；为空走原兜底。
static void process_event_core(struct event* e, MonitorContext* mctx,
                               const FileActorContext* actor = nullptr);

// ── 事件回调（ring buffer 路径）：struct event 归一化为 EventRecord 入事件总线 ──
// 只做归一化 + try_push（禁 malloc / 阻塞 / /proc IO），由消费线程路由回
// 原文件处理函数 process_event_core（行为零变化）。
static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)data_sz;

    auto* bus = static_cast<EventBus*>(ctx);
    if (!bus)
        return 0;
    auto* e = static_cast<struct event *>(data);

    EventRecord rec{};   // 定长 POD，零初始化
    rec.ts_ns         = now_monotonic_ns();  // 文件事件无内核 ts，以入队时间计
    rec.enqueue_ts_ns = rec.ts_ns;
    rec.pid           = e->pid;
    memcpy(rec.comm, e->comm, sizeof(rec.comm));
    rec.category = CAT_FILE;
    rec.priority = PRIO_FILE;
    rec.action   = e->event_type;
    static_assert(sizeof(*e) <= sizeof(rec.payload_raw), "struct event 超出 payload_raw 容量");
    memcpy(rec.payload_raw, e, sizeof(*e));  // struct event 原始字节，供消费线程还原

    bus->try_push(rec);
    return 0;
}

// perf event buffer 回调签名（5.7 / 5.4 路径复用）
static void perf_event_cb(void *ctx, int cpu, void *data, __u32 size) {
    (void)cpu;
    auto* mctx = static_cast<MonitorContext*>(ctx);
    auto* e    = static_cast<struct event *>(data);

    if (size < sizeof(struct event))
        return;

    if (mctx->event_batch.size() < kMaxBatchSize) {
        mctx->event_batch.push_back(*e);
    } else {
        mctx->dropped_count++;
    }
}

// ── 核心事件处理逻辑 ────────────────────────────────────────────────
static void process_event_core(struct event* e, MonitorContext* mctx,
                               const FileActorContext* actor) {
    AlertManager* alert_mgr = mctx->alert_mgr;

    // ── chmod/chown/unlink 实时检测（--db 模式下，eBPF 直接拦截）────────
    if (!g_inode_to_baseline.empty() && alert_mgr != nullptr) {
        if (e->event_type == EVENT_CHMOD || e->event_type == EVENT_CHOWN) {
            handle_chmod_chown_event(e, *alert_mgr, actor);
            return;
        }
        if (e->event_type == EVENT_UNLINK) {
            auto it_bl = g_inode_to_baseline.find(e->ino);
            if (it_bl != g_inode_to_baseline.end()) {
                const std::string& file_path = it_bl->second.file_path;
                std::string proc_name(reinterpret_cast<const char*>(e->comm), 16);
                auto null_pos = proc_name.find('\0');
                if (null_pos != std::string::npos) proc_name.resize(null_pos);
                BaselineDeviation dev;
                dev.event_type = "missing";
                dev.severity   = "high";
                dev.expected   = "file exists";
                dev.actual     = "file deleted (unlink detected by eBPF)";
                HandleBaselineDeviation(dev, file_path, proc_name, e->pid, *alert_mgr,
                                        kBaselineRuleId, actor);
            }
            return;
        }
    }

    // ── 原有 YAML 规则匹配逻辑（R13：同 inode 多规则逐条独立告警；M0-2 加白名单抑制决策点）
    // 持读锁保证热加载（写锁整体替换快照）期间 Rule/路径引用恒有效
    {
    std::shared_lock<std::shared_mutex> rules_lock(g_file_rules_mtx);
    const auto file_rules = g_file_rules;
    auto it_rules = file_rules->inode_to_rules.find(e->ino);
    if (it_rules != file_rules->inode_to_rules.end()) {
        auto it_path = file_rules->inode_to_path.find(e->ino);

        for (const Rule& rule : it_rules->second) {
        // 白名单抑制（M0-2）：命中则计数 + debug 留痕（rule/pid/exe/path），
        // 跳过本规则全部告警；未命中及 fail-closed 场景走原有告警流程，行为零变化。
        // exe/祖先优先用进程树 exec 时捕获的 actor（短寿进程 /proc 已回收，树数据
        // 更及时且与 /proc 等价）；actor 无 exe 退回 /proc 解析（fail-closed）
        if (!g_whitelist_table->empty()) {
            std::string exe;
            bool suppressed;
            if (actor != nullptr && !actor->exe.empty()) {
                static const json kNoAncestors = json::array();
                suppressed = g_whitelist_matcher.Match(*g_whitelist_table, rule,
                                                       e->pid, e->start_time, actor->exe,
                                                       actor_ancestor_exes(
                                                           actor->ancestors != nullptr
                                                               ? *actor->ancestors
                                                               : kNoAncestors),
                                                       &exe);
            } else {
                suppressed = g_whitelist_matcher.Match(*g_whitelist_table, rule, e->pid,
                                                       &exe);
            }
            if (suppressed) {
                spdlog::debug("[whitelist] suppressed: rule={} pid={} exe={} path={}",
                              rule.id, e->pid, exe,
                              it_path != file_rules->inode_to_path.end() ? it_path->second
                                                                         : std::string("?"));
                continue;
            }
        }

        if (it_path != file_rules->inode_to_path.end()) {
            const std::string &path = it_path->second;

            const std::string actual_event = ((e->mask & EVENT_READ) != 0) ? "read" : "write";
            if (alert_mgr != nullptr) {
                on_violation_detected(rule, path, actual_event, e->comm, e->pid, *alert_mgr,
                                      actor);
            }

            if (alert_mgr != nullptr && (e->mask & EVENT_WRITE) != 0) {
                on_check_mismatch_detected(rule, path, e->comm, e->pid, *alert_mgr, actor);
            }
        }
        }  // for rule

        auto it_hash = file_rules->inode_to_hashes.find(e->ino);
        if (it_hash != file_rules->inode_to_hashes.end() && !it_hash->second.empty()) {
            // 文件可能在读取瞬间被删除（如 unlink 事件后），compute_sha256
            // 抛异常时跳过本次哈希检查，避免异常穿透终止 monitor
            std::string current_hash;
            try {
                current_hash = compute_sha256(it_path->second);
            } catch (const std::exception &ex) {
                spdlog::debug("hash check skipped for {}: {}", it_path->second, ex.what());
                current_hash.clear();  // 视为一致，不告警
            }

            for (const std::string &expected_hash : it_hash->second) {
            if (!current_hash.empty() && current_hash != expected_hash) {
                std::ostringstream oss;
                oss << "[" << actionToString(static_cast<Action>(e->action)) << "] File modified! hash mismatch\n"
                    << "  path: " << it_path->second << "\n"
                    << "  pid: " << e->pid << "\n"
                    << "  comm: " << e->comm << "\n"
                    << "  expected_hash: " << expected_hash << "\n"
                    << "  current_hash:  " << current_hash << std::endl;
                spdlog::warn(oss.str());
            }
            }
        } else {
            // 无哈希基线的访问提示与 VIOLATION 行重复（同事件已告警），
            // 高频下 warn+flush 是消费线程热点，降为 debug 且不再逐条 flush
            std::ostringstream oss;
            oss << "[" << actionToString(static_cast<Action>(e->action)) << "] File access detected (no hash baseline)\n"
                << "  path: " << (it_path != file_rules->inode_to_path.end() ? it_path->second : "unknown") << "\n"
                << "  pid: " << e->pid << "\n"
                << "  comm: " << e->comm << std::endl;
            spdlog::debug(oss.str());
        }
    }
    }

    // ── 基线实时比对（--db 模式下）────────────────────────────────
    // 仅写/属性变更类事件触发：read 不改变文件完整性，且比对动作会读文件
    // 产生新 read 事件导致自激告警风暴；另加 2s 去抖防高频写重复比对。
    const bool is_attr_change = (e->event_type != 0);
    const bool is_write = ((e->mask & EVENT_WRITE) != 0);
    if (!g_inode_to_baseline.empty() && alert_mgr != nullptr && (is_attr_change || is_write)) {
        auto it_bl = g_inode_to_baseline.find(e->ino);
        if (it_bl != g_inode_to_baseline.end()) {
            static std::unordered_map<unsigned long, std::chrono::steady_clock::time_point> last_baseline_check;
            const auto now = std::chrono::steady_clock::now();
            auto it_t = last_baseline_check.find(e->ino);
            if (it_t != last_baseline_check.end() &&
                std::chrono::duration_cast<std::chrono::seconds>(now - it_t->second).count() < 2) {
                return;
            }
            last_baseline_check[e->ino] = now;

            const CheckEntry& baseline = it_bl->second;
            // 使用基线中存储的完整路径（不跟随 symlink）
            const std::string& full_path = baseline.file_path;

            std::vector<BaselineDeviation> devs = CompareWithBaseline(baseline, full_path);
            for (const auto& dev : devs) {
                HandleBaselineDeviation(dev, full_path, e->comm, e->pid, *alert_mgr,
                                        kBaselineRuleId, actor);
            }
        }
    }
}

// ── perf 降级路径（5.7/5.4）操作者上下文：无进程树/消费线程，按事件 uid/gid +
// /proc 尽力组装（exe/container 依赖 /proc/<pid>，进程已退出则留空、字段省略），
// 使降级路径告警同样携带操作者上下文；不报错不崩溃。
static FileActorContext build_file_actor_fallback(const struct event& e) {
    FileActorContext actor;
    actor.uid = e.uid;
    actor.gid = e.gid;
    if (struct passwd* pw = getpwuid(static_cast<uid_t>(e.uid)))
        actor.user_name = pw->pw_name;
    actor.exe = exe_path_of(static_cast<int>(e.pid));
    actor.container_id = container_id_of(static_cast<int>(e.pid));
    return actor;
}

// ── 批量处理：遍历缓冲区中的所有事件，逐条调用核心处理逻辑 ────────
// perf buffer 路径（5.7 / 5.4）无进程树：按事件 uid/gid + /proc 尽力组装
// 操作者上下文（build_file_actor_fallback），告警同样富化。
static void FlushEventBatch(MonitorContext* mctx) {
    for (auto& e : mctx->event_batch) {
        FileActorContext actor = build_file_actor_fallback(e);
        process_event_core(&e, mctx, &actor);
    }
    mctx->event_batch.clear();
}

// ── 降级路径遥测可用性提示（perf / kprobe，内核 < 5.8）────────────
// 遥测事件通道依赖 ring buffer（5.8+），降级路径不初始化遥测；
// 配置开关开着却无任何加载痕迹属静默缺失，此处补一行警告并列出被忽略的开关。
static void warn_telemetry_unavailable(const Config& config) {
    std::vector<const char*> enabled;
    if (config.telemetry.network)   enabled.push_back("network");
    if (config.telemetry.dns)       enabled.push_back("dns");
    if (config.telemetry.privilege) enabled.push_back("privilege");
    if (config.telemetry.store)     enabled.push_back("store");
    if (enabled.empty())
        return;

    std::string names;
    for (size_t i = 0; i < enabled.size(); ++i) {
        if (i > 0) names += ' ';
        names += enabled[i];
    }
    spdlog::warn("[telemetry] kernel <5.8 无 ring buffer，遥测不可用（perf 降级版待开发），已忽略配置: {}",
                 names);
}

// ── 公共初始化：写入规则到 eBPF map + 基线加载 ─────────────────
static int common_monitor_init(int fd_actions,
                               const Config& config,
                               const std::string& baseline_db_path,
                               bool skip_boot_check,
                               AlertManager& alert_mgr,
                               BaselineDB*& baseline_db_out) {
    // 写入 monitor_actions：同 inode 的多条规则合并为一个 monitor_rule_set
    // 一次写入（R13 缺陷修复：原先逐条 BPF_ANY 更新同 key，后写覆盖先写）。
    // 超过 MAX_RULES_PER_INO 时保留 action/severity 最强者并 warn 留痕。
    std::unordered_map<unsigned long, monitor_rule_set> rule_sets;
    for (const auto &rule : config.rules) {
        if (!rule.has_monitor)
            continue;
        if (rule.monitor_path.empty() || rule.ino == 0)
            continue;

        struct monitor_rule value{};
        value.action = (rule.monitor_action == Action::BLOCK) ? ACTION_BLOCK : ACTION_ALERT;
        value.events_mask = 0;
        if (rule.monitor_read)
            value.events_mask |= EVENT_READ;
        if (rule.monitor_write)
            value.events_mask |= EVENT_WRITE;
        if (rule.monitor_delete)
            value.events_mask |= EVENT_MASK_BIT(EVENT_UNLINK);
        if (rule.monitor_chmod)
            value.events_mask |= EVENT_MASK_BIT(EVENT_CHMOD);
        if (rule.monitor_chown)
            value.events_mask |= EVENT_MASK_BIT(EVENT_CHOWN);
        value.severity = rule.severity;

        auto &set = rule_sets[rule.ino];
        if (set.count < MAX_RULES_PER_INO) {
            set.rules[set.count++] = value;
        } else {
            // 已满：仅当新规则严格强于最弱条目时替换之
            int weakest = 0;
            for (int i = 1; i < MAX_RULES_PER_INO; i++) {
                if (set.rules[i].action < set.rules[weakest].action ||
                    (set.rules[i].action == set.rules[weakest].action &&
                     set.rules[i].severity < set.rules[weakest].severity))
                    weakest = i;
            }
            if (value.action > set.rules[weakest].action ||
                (value.action == set.rules[weakest].action &&
                 value.severity > set.rules[weakest].severity)) {
                set.rules[weakest] = value;
            }
            spdlog::warn("[rules] inode {} 规则数超过 {}，已保留最强的 {} 条（rule {} 被合并丢弃）",
                         rule.ino, MAX_RULES_PER_INO, MAX_RULES_PER_INO, rule.id);
        }
    }

    // 安装规则表 + 白名单快照（启动代；SIGHUP 热加载时整代替换）
    {
        std::unique_lock<std::shared_mutex> lk(g_file_rules_mtx);
        g_file_rules = FileRuleTable::Build(config);
        g_whitelist_table = WhitelistTable::Build(config);
    }
    g_whitelist_matcher.ClearCache();

    // ── 基线实时监控初始化（仅当 --db 模式下）────────────────
    baseline_db_out = nullptr;
    if (!baseline_db_path.empty()) {
        try {
            baseline_db_out = new BaselineDB(baseline_db_path);

            g_inode_to_baseline.clear();
            auto entries = baseline_db_out->GetAllBaselineEntries();
            for (auto& e : entries) {
                struct stat st;
                if (lstat(e.file_path.c_str(), &st) == 0 && st.st_ino != 0) {
                    g_inode_to_baseline[st.st_ino] = e;
                }
            }
            spdlog::info("[baseline_monitor] loaded {} baseline entries from {}",
                         g_inode_to_baseline.size(), baseline_db_path);

            int baseline_registered = 0;
            for (const auto& [ino, entry] : g_inode_to_baseline) {
                // 语义保持：YAML 规则已覆盖的 inode 不再注册基线伪规则
                //（原 BPF_NOEXIST + 显式跳过的行为）
                if (rule_sets.find(ino) != rule_sets.end())
                    continue;
                auto &set = rule_sets[ino];
                struct monitor_rule value{};
                value.action = ACTION_ALERT;
                // 基线完整性关注内容读写 + 权限/属主变更（perm_changed 风险类型）
                value.events_mask = EVENT_READ | EVENT_WRITE |
                                    EVENT_MASK_BIT(EVENT_CHMOD) |
                                    EVENT_MASK_BIT(EVENT_CHOWN);
                value.severity = SEVERITY_HIGH;
                set.rules[set.count++] = value;
                ++baseline_registered;
            }
            spdlog::info("[baseline_monitor] registered {} baseline inodes to eBPF map",
                         baseline_registered);

            if (!skip_boot_check) {
                int boot_devs = 0;
                for (const auto& [ino, entry] : g_inode_to_baseline) {
                    std::vector<BaselineDeviation> devs = CompareWithBaseline(entry, entry.file_path);
                    for (const auto& dev : devs) {
                        // boot check 无进程上下文（启动时无事件关联），actor 传 nullptr
                        HandleBaselineDeviation(dev, entry.file_path, "-", 0, alert_mgr,
                                                kBaselineCheckRuleId, nullptr);
                        ++boot_devs;
                    }
                }
                spdlog::info("[baseline_boot_check] completed, {} deviations found", boot_devs);
            } else {
                spdlog::info("[baseline_boot_check] skipped (--skip-boot-baseline-check)");
            }
        } catch (const std::exception& ex) {
            spdlog::error("[baseline_monitor] failed to open baseline DB: {}", ex.what());
            delete baseline_db_out;
            baseline_db_out = nullptr;
            g_inode_to_baseline.clear();
        }
    }

    // 统一下刷：每个 inode 一条 rule_set 记录（含 YAML 规则与基线伪规则）
    int rules_written = 0;
    for (auto &[ino, set] : rule_sets) {
        if (bpf_map_update_elem(fd_actions, &ino, &set, BPF_ANY) == 0)
            ++rules_written;
    }
    spdlog::info("[rules] monitor_actions: {} inodes written", rules_written);
    return 0;
}

// ── 公共监控循环（perf buffer 路径，5.7 和 5.4 共用）──────────
static int run_perf_buffer_loop(struct perf_buffer *pb,
                                MonitorContext& mctx,
                                AlertManager& alert_mgr,
                                const std::string& config_path) {
    int count = 0;
    const int RETENTION_INTERVAL = 36000;
    const int WL_STATS_INTERVAL = 600;   // 100ms 轮询 × 600 = 60s 抑制计数日志
    const int USTATS_INTERVAL = 10;      // 100ms 轮询 × 10 = 1s 用户态计数器同步

    while (running) {
        count++;
        int err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            spdlog::error("[bpf_program_error] Error polling perf buffer: {}", err);
            break;
        }

        // SIGHUP 热加载：handler 只置标志，此处每轮检查（成功替换快照，失败保留旧配置）
        if (g_sighup_pending) {
            g_sighup_pending = 0;
            reload_monitor_config(config_path);
        }

        FlushEventBatch(&mctx);

        // 用户态计数器暴露（perf 降级路径无消费线程，此处周期同步批溢出计数）
        if (count % USTATS_INTERVAL == 0)
            sync_user_stats(mctx.user_stats_fd, nullptr, nullptr, &mctx);

        if (count % RETENTION_INTERVAL == 0) {
            int deleted = alert_mgr.RunRetention();
            (void)deleted;
        }
        if (count % WL_STATS_INTERVAL == 0) {
            log_suppressed_stats(&alert_mgr);
        }
    }

    FlushEventBatch(&mctx);
    sync_user_stats(mctx.user_stats_fd, nullptr, nullptr, &mctx);

    if (mctx.dropped_count > 0) {
        spdlog::warn("[batch] {} events dropped (batch overflow, max_batch_size={})",
                     mctx.dropped_count, kMaxBatchSize);
    }
    return 0;
}

// ══════════════════════════════════════════════════════════════════
// 遥测消费线程：从事件总线拉取事件并路由
// ══════════════════════════════════════════════════════════════════

// 消费线程运行时上下文（聚合总线 / 进程树 / 富化器 / 落库 / 文件处理）
struct TelemetryRuntime {
    EventBus*              bus       = nullptr;
    MonitorContext*        mctx      = nullptr;   // 文件事件路由回 process_event_core
    ProcessTree*           tree      = nullptr;
    Enricher*              enricher  = nullptr;
    EventStore*            store     = nullptr;   // store 关闭时为 nullptr
    bool                   store_on  = false;
    bool                   proc_tree_on = false;  // proc_watch 启动成功为 true（文件事件富化）
    volatile bool*         running   = nullptr;   // 全局退出标志
    AlertManager*          alert_mgr = nullptr;   // retention（已移至消费线程）
    int                    user_stats_fd = -1;    // pinned user_stats map（计数器暴露）
};

// ── 文件事件进程上下文组装（仅消费线程调用）────────────────────────
// 按 (pid, start_time) 查进程树：命中填节点 uid/gid/ppid/exe/container_id
// （valid=true）；miss 时 uid/gid 用事件值、user_name 用 getpwuid(uid) 兜底，
// 其余留空（valid=false）。祖先链复用 Enricher 逻辑，自近及远 ≤8 层。
// getpwuid 每次调都走 NSS 读 /etc/passwd（无 nscd 时约几十 µs），高频事件
// 路径下是消费线程热点；uid→用户名运行期内不变，进程内缓存（仅消费线程访问）。
static std::string cached_user_name(unsigned int uid) {
    static std::unordered_map<unsigned int, std::string> cache;
    auto it = cache.find(uid);
    if (it != cache.end())
        return it->second;
    std::string name;
    if (struct passwd* pw = getpwuid(static_cast<uid_t>(uid)))
        name = pw->pw_name;
    cache.emplace(uid, name);
    return name;
}

// 祖先链按 (pid, start_time) 缓存：同一进程实例的祖先链在其生命周期内不变
// （祖先 exec 造成的短暂 staleness 与 WhitelistMatcher 既有 (pid,start_time)
// 缓存语义一致）；map 有界防膨胀。start_time=0 不可键控时直接计算。
// dumped 为 a.dump() 的预计算串（空链为 ""，对应原 empty()?"":dump() 语义），
// 消费线程每事件引用一次，省去重复 dump。
struct AncestorsCached {
    json        a;
    std::string dumped;   // a.empty() 时为 ""
};
static const AncestorsCached& cached_ancestors_of(Enricher* enr, unsigned int pid,
                                                  unsigned long long start_time,
                                                  unsigned int ppid) {
    using Key = std::pair<unsigned int, unsigned long long>;
    static std::map<Key, AncestorsCached> cache;   // 仅消费线程访问
    if (start_time == 0) {
        thread_local AncestorsCached tmp;
        tmp.a = enr->ancestors_of(pid, ppid);
        tmp.dumped = tmp.a.empty() ? "" : tmp.a.dump();
        return tmp;
    }
    const Key k{pid, start_time};
    auto it = cache.find(k);
    if (it != cache.end())
        return it->second;
    if (cache.size() >= 4096)
        cache.clear();
    AncestorsCached e;
    e.a = enr->ancestors_of(pid, ppid);
    e.dumped = e.a.empty() ? "" : e.a.dump();
    return cache.emplace(k, std::move(e)).first->second;
}

static FileActorContext build_file_actor(const struct event& e, TelemetryRuntime* rt) {
    FileActorContext actor;
    unsigned int ppid = 0;
    if (const ProcNode* node = rt->tree->find(e.pid, e.start_time)) {
        actor.uid = node->uid;
        actor.gid = node->gid;
        actor.ppid = node->ppid;
        actor.exe = node->exe_str();
        actor.container_id = node->container_id_str();
        actor.user_name = cached_user_name(node->uid);
        actor.valid = true;
        ppid = node->ppid;
    } else {
        actor.uid = e.uid;
        actor.gid = e.gid;
        actor.user_name = cached_user_name(e.uid);
    }
    const auto& anc = cached_ancestors_of(rt->enricher, e.pid, e.start_time, ppid);
    actor.ancestors      = anc.a.empty() ? nullptr : &anc.a;
    actor.ancestors_json = anc.dumped;
    return actor;
}

// ── 文件事件落库渲染（M0-1：CAT_FILE 对齐标准路径）────────────────
static const char* file_event_kind(const struct event& e) {
    switch (e.event_type) {
    case EVENT_CHMOD:  return "file.chmod";
    case EVENT_CHOWN:  return "file.chown";
    case EVENT_UNLINK: return "file.unlink";
    case EVENT_RENAME: return "file.rename";
    case EVENT_MMAP:   return "file.mmap";
    default:
        if ((e.mask & EVENT_WRITE) != 0) return "file.write";
        if ((e.mask & EVENT_READ)  != 0) return "file.read";
        return "file.access";
    }
}

// 文件事件路径解析：优先基线完整路径（--db 模式，不跟随 symlink），
// 其次 YAML 规则路径；均无退回事件自带文件名（仅 basename）。
static std::string file_event_path(const struct event& e) {
    auto it_bl = g_inode_to_baseline.find(e.ino);
    if (it_bl != g_inode_to_baseline.end())
        return it_bl->second.file_path;
    std::shared_lock<std::shared_mutex> rules_lock(g_file_rules_mtx);
    auto it_path = g_file_rules->inode_to_path.find(e.ino);
    if (it_path != g_file_rules->inode_to_path.end())
        return it_path->second;
    return std::string(e.path);
}

// ── R10：CAT_FILE payload 直写 JSON 序列化 ─────────────────────────
// 输出与 nlohmann::json::dump() 逐字节一致（map 序键 / ensure_ascii=false /
// 无效 UTF-8 替换 U+FFFD），但跳过 json DOM 的 std::map 节点分配与销毁
// （压测下约占消费线程 40-50% CPU，是吞吐瓶颈的主因）。
namespace {

// Höhrmann UTF-8 DFA（与 nlohmann detail::serializer::decode 同一状态表，
// 逐字节行为一致：ACCEPT=0 / REJECT=1，其余为中间态）
inline std::uint8_t utf8_dfa_decode(std::uint8_t& state, std::uint32_t& codep,
                                    std::uint8_t byte) noexcept {
    static const std::uint8_t utf8d[400] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 00..1F
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 20..3F
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 40..5F
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // 60..7F
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9, // 80..9F
        7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7, // A0..BF
        8,8,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, // C0..DF
        0xA,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x3,0x4,0x3,0x3, // E0..EF
        0xB,0x6,0x6,0x6,0x5,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8,0x8, // F0..FF
        0x0,0x1,0x2,0x3,0x5,0x8,0x7,0x1,0x1,0x1,0x4,0x6,0x1,0x1,0x1,0x1, // s0
        1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,1, // s1..s2
        1,2,1,1,1,1,1,2,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,1, // s3..s4
        1,2,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,1,1,1,1,1,1,3,1,3,1,1,1,1,1,1, // s5..s6
        1,3,1,1,1,1,1,3,1,3,1,1,1,1,1,1,1,3,1,1,1,1,1,1,1,1,1,1,1,1,1,1, // s7..s8
    };
    const std::uint8_t type = utf8d[byte];
    codep = (state != 0) ? static_cast<std::uint32_t>((byte & 0x3Fu) | (codep << 6u))
                         : static_cast<std::uint32_t>((0xFFu >> type) & byte);
    state = utf8d[256u + state * 16u + type];
    return state;
}

// 追加 JSON 字符串字面量（含引号与转义），语义同 nlohmann dump_escaped
void append_json_string(std::string& out, const char* s, size_t n) {
    out.push_back('"');
    std::uint32_t codepoint = 0;
    std::uint8_t state = 0;
    size_t undumped = 0;   // 自上次 ACCEPT 以来追加的字节数
    for (size_t i = 0; i < n; ++i) {
        const auto byte = static_cast<std::uint8_t>(s[i]);
        const std::uint8_t st = utf8_dfa_decode(state, codepoint, byte);
        if (st == 1) {   // REJECT：丢弃半成品序列，替换 U+FFFD，当前字节重来
            out.resize(out.size() - undumped);
            if (undumped > 0)
                --i;
            out += "\xEF\xBF\xBD";
            undumped = 0;
            state = 0;
            continue;
        }
        if (st != 0) {   // 中间态：暂存原始字节
            out.push_back(static_cast<char>(byte));
            ++undumped;
            continue;
        }
        switch (codepoint) {
        case 0x08: out += "\\b"; break;
        case 0x09: out += "\\t"; break;
        case 0x0A: out += "\\n"; break;
        case 0x0C: out += "\\f"; break;
        case 0x0D: out += "\\r"; break;
        case 0x22: out += "\\\""; break;
        case 0x5C: out += "\\\\"; break;
        default:
            if (codepoint <= 0x1F) {
                char buf[7];
                std::snprintf(buf, sizeof(buf), "\\u%04x",
                              static_cast<unsigned>(codepoint));
                out.append(buf, 6);
            } else {
                out.push_back(static_cast<char>(byte));
            }
        }
        undumped = 0;
    }
    out.push_back('"');
}

inline void append_json_string(std::string& out, const std::string& s) {
    append_json_string(out, s.data(), s.size());
}

inline void append_u64(std::string& out, unsigned long long v) {
    char buf[20];
    int len = std::snprintf(buf, sizeof(buf), "%llu", v);
    out.append(buf, static_cast<size_t>(len));
}

}  // namespace

// 文件事件落库 payload 直写（键序同 nlohmann map 序），同时回填 rec 索引列；
// actor 为空（proc_watch 未启动）时 uid/gid 退回事件值、exe/container 省略、
// ancestors 退回 Enricher 兜底（与 R10 前 enrich 路径一致）。
static void render_file_payload(const struct event& e, struct EventRecord& rec,
                                const FileActorContext* actor, Enricher* enr,
                                std::string& out) {
    out.clear();
    out.reserve(512);
    out.push_back('{');
    if (actor != nullptr && !actor->container_id.empty()) {
        out += "\"container\":{\"container_id\":";
        append_json_string(out, actor->container_id);
        out += "},";
    }
    out += "\"event_type\":";
    append_json_string(out, file_event_kind(e), std::strlen(file_event_kind(e)));

    out += ",\"file\":{\"action\":";
    append_json_string(out, actionToString(static_cast<Action>(e.action)));
    out += ",\"ino\":";
    append_u64(out, e.ino);
    out += ",\"mask\":";
    append_u64(out, static_cast<unsigned long long>(e.mask));
    if (e.event_type == EVENT_CHOWN) {
        out += ",\"new_gid\":";
        append_u64(out, e.new_gid);
    }
    if (e.event_type == EVENT_CHMOD) {
        out += ",\"new_mode\":";
        append_json_string(out, mode_to_string(e.new_mode & 0777));
    }
    if (e.event_type == EVENT_CHOWN) {
        out += ",\"new_uid\":";
        append_u64(out, e.new_uid);
    }
    out += ",\"path\":";
    append_json_string(out, file_event_path(e));

    out += "},\"process\":{\"ancestors\":";
    if (actor != nullptr)
        out += actor->ancestors_json.empty() ? "[]" : actor->ancestors_json;
    else if (enr != nullptr)
        out += enr->ancestors_of(rec.pid, rec.ppid).dump();
    else
        out += "[]";
    out += ",\"comm\":";
    {
        std::string comm(reinterpret_cast<const char*>(e.comm), sizeof(e.comm));
        auto comm_end = comm.find('\0');
        if (comm_end != std::string::npos)
            comm.resize(comm_end);
        append_json_string(out, comm);
    }
    if (actor != nullptr && !actor->exe.empty()) {
        out += ",\"exe\":";
        append_json_string(out, actor->exe);
    }
    out += ",\"gid\":";
    append_u64(out, (actor != nullptr) ? actor->gid : e.gid);
    out += ",\"pid\":";
    append_u64(out, e.pid);
    if (actor != nullptr && actor->ppid > 0) {
        out += ",\"ppid\":";
        append_u64(out, actor->ppid);
    }
    out += ",\"uid\":";
    append_u64(out, (actor != nullptr) ? actor->uid : e.uid);
    out += "},\"ts\":";
    append_u64(out, rec.ts_ns);
    out.push_back('}');

    rec.uid  = (actor != nullptr) ? actor->uid : e.uid;
    rec.ppid = (actor != nullptr) ? actor->ppid : 0;
    if (actor != nullptr) {
        record_set_str(rec.exe, sizeof(rec.exe), actor->exe.c_str(), actor->exe.size());
        record_set_str(rec.container_id, sizeof(rec.container_id),
                       actor->container_id.c_str(), actor->container_id.size());
    }
}

// ── DSL 规则引擎接入（W4 D4）：仅消费线程调用，引擎快照只读 ─────────
// rule_id = "dsl." + slug（小写字母数字保留，其余折叠为单个 '_'）
static std::string dsl_rule_id(const std::string& name) {
    std::string id = "dsl.";
    bool last_us = false;
    for (const unsigned char c : name) {
        if (std::isalnum(c)) {
            id += static_cast<char>(std::tolower(c));
            last_us = false;
        } else if (!last_us) {
            id += '_';
            last_us = true;
        }
    }
    while (!id.empty() && id.back() == '_')
        id.pop_back();
    return id;
}

// 祖先链 json [{pid,comm,exe}] → EventView 视图（string_view 引用 json 内部
// 存储，事件处理期内有效）
static void fill_ancestors_view(const json& anc, std::vector<detect::AncestorView>& out) {
    out.clear();
    if (!anc.is_array())
        return;
    for (const auto& a : anc) {
        detect::AncestorView av;
        if (a.contains("pid") && a["pid"].is_number())
            av.pid = a["pid"].get<long long>();
        if (a.contains("comm") && a["comm"].is_string()) {
            const auto& s = a["comm"].get_ref<const std::string&>();
            av.comm = std::string_view(s.data(), s.size());
        }
        if (a.contains("exe") && a["exe"].is_string()) {
            const auto& s = a["exe"].get_ref<const std::string&>();
            av.exe = std::string_view(s.data(), s.size());
        }
        out.push_back(av);
    }
}

// 命中后构造 AlertEvent 走 AlertManager 统一入口（节流/落库/钉钉与 FIM 一致）
static void send_dsl_alert(const detect::Rule& rule, const std::string& output,
                           const detect::EventView& view, const std::string& file_path,
                           const std::string& user_name, const std::string& ancestors_json,
                           AlertManager* alert_mgr) {
    const std::string rule_id = dsl_rule_id(rule.name);
    // 节流窗口内跳过 AlertEvent 构建（与 on_violation_detected 同一考量）；
    // 抑制计数在此入口记（不经 SendDingTalk，不会双计）
    if (alert_mgr->ThrottledNow(rule_id)) {
        alert_mgr->NoteThrottled(rule_id);
        return;
    }

    AlertEvent evt;
    evt.rule_id      = rule_id;
    evt.rule_name    = rule.name;
    evt.severity     = rule.priority;
    evt.file_path    = file_path;    // alerts.file_path 列 NOT NULL：file 事件取路径，exec 取 exe
    evt.actual       = output;
    evt.process_name = std::string(view.comm);
    evt.pid          = static_cast<int>(view.pid);
    evt.user_name    = user_name;
    evt.uid          = std::to_string(view.uid);
    evt.timestamp    = NowString();
    evt.event_type   = std::string(view.event_type);
    evt.action_taken = "alert";
    evt.exe          = std::string(view.exe);
    evt.container_id = std::string(view.container_id);
    evt.ancestors    = ancestors_json;
    for (size_t i = 0; i < rule.attack.size(); ++i) {
        if (i > 0)
            evt.attack += ',';
        evt.attack += rule.attack[i];
    }
    alert_mgr->SendDingTalk(evt);
}

// 文件事件求值：CAT_FILE 分支 build_file_actor 之后、store->Append 之前调用
static void eval_rules_on_file_event(const struct event& fe, const FileActorContext* actor,
                                     TelemetryRuntime* rt) {
    const auto engine = rule_engine_snapshot();
    if (engine->rule_count() == 0 || rt->alert_mgr == nullptr)
        return;

    const std::string path = file_event_path(fe);
    const std::string action = actionToString(static_cast<Action>(fe.action));
    std::string new_mode;
    if (fe.event_type == EVENT_CHMOD)
        new_mode = mode_to_string(fe.new_mode & 0777);

    detect::EventView view;
    view.event_type = file_event_kind(fe);
    view.pid  = fe.pid;
    view.ppid = (actor != nullptr) ? actor->ppid : 0;
    view.uid  = (actor != nullptr) ? actor->uid : fe.uid;
    view.gid  = (actor != nullptr) ? actor->gid : fe.gid;
    view.comm = std::string_view(fe.comm, strnlen(fe.comm, sizeof(fe.comm)));
    if (actor != nullptr) {
        view.exe = actor->exe;
        view.container_id = actor->container_id;
    }
    view.has_file = true;
    view.file_path   = path;
    view.file_action = action;
    view.file_new_mode = new_mode;
    view.file_ino     = static_cast<long long>(fe.ino);
    view.file_mask    = fe.mask;
    view.file_new_uid = fe.new_uid;
    view.file_new_gid = fe.new_gid;
    if (actor != nullptr && actor->ancestors != nullptr)
        fill_ancestors_view(*actor->ancestors, view.ancestors);

    detect::MatchResult m;
    if (!engine->Evaluate(view, m))
        return;

    std::string user_name;
    if (actor != nullptr) {
        user_name = actor->user_name;
    } else {
        std::string uid_str;
        user_name = ResolveUserInfoByPid(static_cast<int>(fe.pid), uid_str);
    }
    send_dsl_alert(*m.rule, m.output, view, path, user_name,
                   (actor != nullptr) ? actor->ancestors_json : std::string(),
                   rt->alert_mgr);
}

// exec 事件求值：CAT_PROCESS 分支 tree->apply 之后调用（不依赖 store 开关）
static void eval_rules_on_exec_event(const struct proc_event& pe, TelemetryRuntime* rt) {
    const auto engine = rule_engine_snapshot();
    if (engine->rule_count() == 0 || rt->alert_mgr == nullptr)
        return;

    std::string exe;
    std::string container_id;
    unsigned int uid = pe.uid;
    if (const ProcNode* node = rt->tree->find(pe.pid, pe.start_time)) {
        exe = node->exe_str();
        container_id = node->container_id_str();
        uid = node->uid;
    }
    if (exe.empty())
        exe.assign(pe.exe, strnlen(pe.exe, sizeof(pe.exe)));

    detect::EventView view;
    view.event_type = "process.exec";
    view.pid  = pe.pid;
    view.ppid = pe.ppid;
    view.uid  = uid;
    view.gid  = pe.gid;
    view.comm = std::string_view(pe.comm, strnlen(pe.comm, sizeof(pe.comm)));
    view.exe  = exe;
    view.container_id = container_id;
    const json anc = rt->enricher->ancestors_of(pe.pid, pe.ppid);
    fill_ancestors_view(anc, view.ancestors);

    detect::MatchResult m;
    if (!engine->Evaluate(view, m))
        return;

    send_dsl_alert(*m.rule, m.output, view, exe, cached_user_name(uid),
                   anc.empty() ? std::string() : anc.dump(), rt->alert_mgr);
}

// 路由单条事件：file→查进程树拼进程上下文后回原处理函数（告警富化 exe/
// container_id/ancestors，树关闭时行为与现状一致；store 开启时渲染 JSON、
// 富化祖先链并落库）、process→先更新进程树（exec 另落库）、
// network/dns/priv/ns→渲染 JSON 走原日志输出（行为零变化），
// store 开启时富化祖先链并落库。
static void route_event(EventRecord& rec, TelemetryRuntime* rt) {
    // 排队延迟：dequeue 时间 - 入队时间
    const unsigned long long now = now_monotonic_ns();
    if (now >= rec.enqueue_ts_ns)
        rt->bus->record_queue_latency(now - rec.enqueue_ts_ns);

    switch (rec.category) {
    case CAT_FILE: {
        struct event fe;
        memcpy(&fe, rec.payload_raw, sizeof(fe));
        // 进程树开启时按 (pid, start_time) 查树拼进程上下文再处理（告警富化）；
        // 树关闭（proc_watch 启动失败/旧内核路径）传 nullptr，行为与现状一致。
        FileActorContext actor;
        const FileActorContext* actor_ptr = nullptr;
        if (rt->proc_tree_on) {
            actor = build_file_actor(fe, rt);
            actor_ptr = &actor;
        }
        process_event_core(&fe, rt->mctx, actor_ptr);
        eval_rules_on_file_event(fe, actor_ptr, rt);
        if (rt->store_on) {
            // 读/写（file_permission）事件 event_type=0，按 mask 归一 action 便于检索
            if (fe.event_type == 0)
                rec.action = (fe.mask & EVENT_WRITE) ? EVENT_WRITE : EVENT_READ;
            // R10：payload 直写 JSON（与 nlohmann dump 逐字节一致），
            // 祖先链用 build_file_actor 预序列化串；actor 为空退回 Enricher 兜底
            // R13：渲染 JSON 不再写回槽位，随 Append() 直接传给 EventStore
            thread_local std::string payload;   // 仅消费线程，复用缓冲
            render_file_payload(fe, rec, actor_ptr, rt->enricher, payload);
            rt->store->Append(rec, payload.c_str(), payload.size());
        }
        break;
    }
    case CAT_PROCESS: {
        struct proc_event pe;
        memcpy(&pe, rec.payload_raw, sizeof(pe));
        rt->tree->apply(pe);   // fork/exec/exit 维护进程树（单线程无锁）
        if (pe.kind == PROC_KIND_EXEC) {
            eval_rules_on_exec_event(pe, rt);   // 规则引擎求值不依赖 store 开关
            if (rt->store_on) {
                json j;
                render_process_exec_event(pe, rec, j);
                rt->enricher->enrich(rec, j);
                const std::string payload = j.dump();
                rt->store->Append(rec, payload.c_str(), payload.size());
            }
        }
        break;
    }
    case CAT_NETWORK:
    case CAT_DNS: {
        struct net_event ne;
        memcpy(&ne, rec.payload_raw, sizeof(ne));
        json j;
        render_network_event(ne, rec, j);
        spdlog::info("{}", j.dump());   // 与迁移前逐字节一致
        if (rt->store_on) {
            rt->enricher->enrich(rec, j);
            const std::string payload = j.dump();
            rt->store->Append(rec, payload.c_str(), payload.size());
        }
        break;
    }
    case CAT_PRIV:
    case CAT_NS: {
        struct priv_event pe;
        memcpy(&pe, rec.payload_raw, sizeof(pe));
        json j;
        render_privilege_event(pe, rec, j);
        spdlog::info("{}", j.dump());   // 与迁移前逐字节一致
        if (rt->store_on) {
            rt->enricher->enrich(rec, j);
            const std::string payload = j.dump();
            rt->store->Append(rec, payload.c_str(), payload.size());
        }
        break;
    }
    default:
        break;
    }
}

// 消费线程主循环：严格先拉 hi 再拉 lo；驱动落库批量刷新、延迟统计（60s）、
// drop 计数日志（30s）、tombstone sweep（60s）、告警 retention（3600s）。
static void telemetry_consumer_main(TelemetryRuntime* rt) {
    // 进程树恒启用（store 关闭也需要：文件事件告警进程上下文富化依赖），
    // bootstrap 扫 /proc 建初始树（含 uid/gid、容器 ID）
    rt->tree->bootstrap();

    unsigned long long last_stats     = now_monotonic_ns();
    unsigned long long last_drop      = now_monotonic_ns();
    unsigned long long last_sweep     = now_monotonic_ns();
    unsigned long long last_retention = now_monotonic_ns();
    unsigned long long last_wl_stats  = now_monotonic_ns();
    unsigned long long last_drop_total = rt->bus->drop_count_total();
    // R13：空闲自适应退避——连续空转时 200us→2ms 指数退避，有事件即复位。
    // 压测下循环从不空转，吞吐路径零影响；空闲唤醒 5000/s→~500/s（CPU 优化）。
    long idle_backoff_ns = 200000;

    while (*rt->running) {
        bool did_work = false;
        EventRecord rec;
        while (rt->bus->try_pop_hi(rec)) {
            route_event(rec, rt);
            did_work = true;
        }
        while (rt->bus->try_pop_lo(rec)) {
            route_event(rec, rt);
            did_work = true;
        }
        if (did_work)
            idle_backoff_ns = 200000;

        if (rt->store)
            rt->store->FlushIfDue();

        const unsigned long long now = now_monotonic_ns();

        // 延迟统计：每 60s 有流量时打一行
        if (now - last_stats >= 60000000000ULL) {
            const auto q = rt->bus->queue_latency_summary();
            if (q.valid) {
                if (rt->store) {
                    const auto e = rt->store->e2e_latency_summary();
                    spdlog::info("[event_bus] stats: queue avg={:.1f}us p95={}us | e2e avg={:.1f}us p95={}us (samples={})",
                                 q.avg_us, q.p95_us, e.avg_us, e.p95_us, q.count);
                } else {
                    spdlog::info("[event_bus] stats: queue avg={:.1f}us p95={}us (samples={})",
                                 q.avg_us, q.p95_us, q.count);
                }
            }
            last_stats = now;
        }

        // 白名单抑制计数 + 告警节流抑制累计：每 60s 打一行
        if (now - last_wl_stats >= 60000000000ULL) {
            log_suppressed_stats(rt->alert_mgr);
            last_wl_stats = now;
        }

        // drop 计数：每 30s 有增量打一行
        if (now - last_drop >= 30000000000ULL) {
            const unsigned long long total = rt->bus->drop_count_total();
            if (total > last_drop_total) {
                spdlog::warn("[event_store] drops: hi(file={} ctrl={}) lo(net={} dns={}) total={}",
                             rt->bus->drop_count(true, PRIO_FILE),
                             rt->bus->drop_count(true, PRIO_CTRL),
                             rt->bus->drop_count(false, PRIO_NETWORK),
                             rt->bus->drop_count(false, PRIO_DNS),
                             total);
                last_drop_total = total;
            }
            last_drop = now;
        }

        // 用户态计数器的周期同步在主循环做（本线程内层 pop 循环在高压下
        // 不退出，周期任务会被饿死）；此处只保留退出后的最终同步。

        // tombstone sweep：每 60s；顺带 malloc_trim 归还压测峰值后
        // glibc arena 持有的空闲堆页（R13 内存收敛，best effort）
        if (now - last_sweep >= 60000000000ULL) {
            rt->tree->sweep_tombstones();
            malloc_trim(0);
            last_sweep = now;
        }

        // 告警 retention：每 3600s（自消费线程执行，避免与文件处理并发）
        if (now - last_retention >= 3600000000000ULL) {
            if (rt->alert_mgr)
                rt->alert_mgr->RunRetention();
            last_retention = now;
        }

        if (!did_work) {
            struct timespec ts {0, idle_backoff_ns};   // 空闲退避（自适应 200us~2ms）
            nanosleep(&ts, nullptr);
            if (idle_backoff_ns < 2000000)
                idle_backoff_ns *= 2;
        }
    }

    // 退出前 drain 残余事件并落库收尾
    EventRecord rec;
    while (rt->bus->try_pop_hi(rec))
        route_event(rec, rt);
    while (rt->bus->try_pop_lo(rec))
        route_event(rec, rt);
    if (rt->store)
        rt->store->Flush();
    // drain + 落库收尾后最终同步一次计数器（对账读取的最终状态）
    sync_user_stats(rt->user_stats_fd, rt->bus, rt->store, rt->mctx);
}

// ══════════════════════════════════════════════════════════════════
// 路径 A：内核 5.8+ — BPF LSM + ring buffer
// ══════════════════════════════════════════════════════════════════
static int do_monitor_ringbuf(const Config& config, AlertManager &alert_mgr,
                              const std::string& config_path,
                              const std::string& baseline_db_path, bool skip_boot_check) {
    struct lsm_file_bpf *skel;
    int err;

    skel = lsm_file_bpf__open();
    if (!skel) {
        spdlog::error("[bpf_program_error] Failed to open BPF skeleton");
        return 1;
    }

    // 兼容内核 5.8：mmap_file LSM hook 在 5.9 才引入
    if (skel->progs.file_mmap_hook && !kernel_at_least(5, 9)) {
        bpf_program__set_autoload(skel->progs.file_mmap_hook, false);
        auto kv = get_kernel_version();
        spdlog::info("[bpf_compat] mmap_file hook disabled (kernel {}.{}, requires 5.9+)",
                     kv.major, kv.minor);
    }

    err = lsm_file_bpf__load(skel);
    if (err) {
        spdlog::error("[bpf_program_error] Failed to load BPF skeleton: {}", err);
        lsm_file_bpf__destroy(skel);
        return 1;
    }

    err = lsm_file_bpf__attach(skel);
    if (err) {
        spdlog::error("[bpf_program_error] Failed to attach BPF program: {}", err);
        lsm_file_bpf__destroy(skel);
        return 1;
    }
    spdlog::info("[bpf_program_loaded] BPF LSM (ring buffer) attached, kernel 5.8+, {} rules",
                 config.rules.size());

    // Pin maps
    (void)mkdir("/sys/fs/bpf/baseline-guard", 0755);
    pin_map_best_effort(skel->maps.drop_stats, DROP_STATS_PIN_PATH);
    pin_map_best_effort(skel->maps.watermark_level, "/sys/fs/bpf/baseline-guard/watermark_level");
    pin_map_best_effort(skel->maps.user_stats, USER_STATS_PIN_PATH);

    int fd_actions   = bpf_map__fd(skel->maps.monitor_actions);
    int fd_watermark = bpf_map__fd(skel->maps.watermark_level);
    int fd_ustats    = bpf_map__fd(skel->maps.user_stats);

    BaselineDB* baseline_db = nullptr;
    common_monitor_init(fd_actions, config, baseline_db_path, skip_boot_check, alert_mgr, baseline_db);

    // 水位背压控制器
    WatermarkBackpressure backpressure;
    MonitorContext mctx;
    mctx.alert_mgr    = &alert_mgr;
    mctx.backpressure = &backpressure;

    // ── 事件总线 + 落库管道 + 消费线程 ──────────────────────────
    EventBus bus(static_cast<size_t>(config.telemetry.queue_hi),
                 static_cast<size_t>(config.telemetry.queue_lo));
    ProcessTree proc_tree;
    Enricher enricher(proc_tree);
    EventStore* store = nullptr;
    if (config.telemetry.store) {
        store = new EventStore(config.telemetry.events_db, config.telemetry.batch_size,
                               config.telemetry.batch_ms);
        if (!store->ok()) {
            spdlog::warn("[event_store] 打开 {} 失败，降级为不落库", config.telemetry.events_db);
            delete store;
            store = nullptr;
        } else {
            spdlog::info("[event_store] telemetry store enabled, db={} batch_size={} batch_ms={} host_id={}",
                         config.telemetry.events_db, config.telemetry.batch_size,
                         config.telemetry.batch_ms, store->host_id());
        }
    }

    // ── 进程生命周期遥测（恒启动，供进程树 / 文件事件富化；失败降级）──
    // 须在消费线程创建前启动：消费线程 bootstrap 依赖 fork/exec/exit 事件流
    // 尽快就位，且 rt.proc_tree_on 需在线程启动前定型
    struct proc_watch_bpf *proc_skel = nullptr;
    struct ring_buffer *proc_rb = nullptr;
    proc_skel = process_monitor_start(&proc_rb, &bus);
    if (!proc_skel)
        spdlog::warn("[telemetry.process] proc_watch 启动失败，降级为无进程树富化");

    // ── DSL 规则引擎启动加载（W4）：失败降级为空引擎，监控继续 ──
    if (config.rule_engine.enabled) {
        auto engine = build_rule_engine(config.rule_engine);
        if (engine != nullptr) {
            {
                std::unique_lock<std::shared_mutex> lk(g_file_rules_mtx);
                g_rule_engine = std::move(engine);
            }
            spdlog::info("[rule_engine] loaded {} DSL rules from {}",
                         rule_engine_snapshot()->rule_count(), config.rule_engine.rules_dir);
        } else {
            spdlog::warn("[rule_engine] 启动加载失败，降级为空引擎（不产生 DSL 告警）");
        }
    } else {
        spdlog::info("[rule_engine] disabled by config");
    }

    TelemetryRuntime rt;
    rt.bus       = &bus;
    rt.mctx      = &mctx;
    rt.tree      = &proc_tree;
    rt.enricher  = &enricher;
    rt.store     = store;
    rt.store_on  = (store != nullptr);
    rt.proc_tree_on = (proc_skel != nullptr);
    rt.running   = &running;
    rt.alert_mgr = &alert_mgr;
    rt.user_stats_fd = fd_ustats;
    std::thread consumer_thread(telemetry_consumer_main, &rt);

    spdlog::info("Monitoring started (ring buffer mode). Press Ctrl+C to stop.");

    struct ring_buffer *rb =
        ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, &bus, nullptr);
    if (!rb) {
        spdlog::error("[bpf_program_error] Failed to create ring buffer");
        running = false;
        consumer_thread.join();
        delete store;
        if (baseline_db) delete baseline_db;
        lsm_file_bpf__destroy(skel);
        return 1;
    }

    backpressure.SetRingBuffer(rb);
    backpressure.SetNumCPUs(libbpf_num_possible_cpus());
    spdlog::info("[watermark] backpressure controller initialized (cpus={})",
                 libbpf_num_possible_cpus());

    // ── 网络遥测（telemetry.network / telemetry.dns 任一开启时启动；失败降级）──
    struct net_watch_bpf *net_skel = nullptr;
    struct ring_buffer *net_rb = nullptr;
    if (config.telemetry.network || config.telemetry.dns) {
        net_skel = network_monitor_start(&net_rb, config.telemetry.network,
                                         config.telemetry.dns, &bus);
        if (!net_skel)
            spdlog::warn("[telemetry.network] net_watch 启动失败，降级为仅文件监控");
    }

    // ── 权限遥测（仅 telemetry.privilege: true 时启动；失败降级）──
    struct priv_watch_bpf *priv_skel = nullptr;
    struct ring_buffer *priv_rb = nullptr;
    if (config.telemetry.privilege) {
        priv_skel = privilege_monitor_start(&priv_rb, &bus);
        if (!priv_skel)
            spdlog::warn("[telemetry.privilege] priv_watch 启动失败，降级为无权限遥测");
    }

    // epoll 同时等待文件事件 rb 与各路遥测 rb（任一遥测开启时启用）。
    // 以数组统一登记活跃 rb；同轮就绪时按数组顺序消费：
    // proc 先于 file——进程 exec 先于其文件事件产生，先消费 proc rb 可保证
    // 消费线程路由文件事件时进程树已捕获 exec（短寿进程白名单/富化依赖）；
    // net/priv 仍在 file 之后，保持进程事件先于网络事件入队（进程树时序）。
    struct RbEntry { int fd; struct ring_buffer* rb; };
    RbEntry rbs[4];
    int nrb = 0;
    if (proc_skel && proc_rb)
        rbs[nrb++] = {ring_buffer__epoll_fd(proc_rb), proc_rb};
    rbs[nrb++] = {ring_buffer__epoll_fd(rb), rb};
    if (net_skel && net_rb)
        rbs[nrb++] = {ring_buffer__epoll_fd(net_rb), net_rb};
    if (priv_skel && priv_rb)
        rbs[nrb++] = {ring_buffer__epoll_fd(priv_rb), priv_rb};

    int epollfd = -1;
    if (nrb > 1) {
        epollfd = epoll_create1(0);
        if (epollfd < 0) {
            spdlog::error("[bpf_program_error] epoll_create1 failed: {}", errno);
        } else {
            for (int i = 0; i < nrb; i++) {
                if (rbs[i].fd < 0)
                    continue;
                struct epoll_event ev {};
                ev.events = EPOLLIN;
                ev.data.fd = rbs[i].fd;
                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, rbs[i].fd, &ev) != 0)
                    spdlog::error("[bpf_program_error] epoll add rb fd={} failed: {}",
                                  rbs[i].fd, errno);
            }
        }
    }

    unsigned long long last_watermark_ns = now_monotonic_ns();
    unsigned long long last_ustats_ns    = now_monotonic_ns();
    while (running) {
        if (epollfd >= 0) {
            struct epoll_event evs[8];
            int n = epoll_wait(epollfd, evs, 8, 100);
            if (n < 0 && errno != EINTR) {
                spdlog::error("[bpf_program_error] Error waiting epoll: {}", errno);
                break;
            }
            for (int i = 0; i < n; i++) {
                for (int j = 0; j < nrb; j++) {
                    if (evs[i].data.fd == rbs[j].fd) {
                        ring_buffer__consume(rbs[j].rb);
                        break;
                    }
                }
            }
        } else {
            err = ring_buffer__poll(rb, 100);
            if (err < 0 && err != -EINTR) {
                spdlog::error("[bpf_program_error] Error polling ring buffer: {}", err);
                break;
            }
        }

        // 周期任务按时间触发（原按循环次数：高压下循环极快，触发频率远超设计
        // 语义，水位计算遍历全部 CPU ring + 16 次 map 更新会卡住 ring 消费，
        // 压测窗口 burst 期间导致内核 reserve 失败丢事件）
        const unsigned long long loop_now = now_monotonic_ns();
        if (loop_now - last_watermark_ns >= 1000000000ULL) {   // 1s
            backpressure.UpdateUtilization();
            __u32 wm_key   = 0;
            __u32 wm_value = static_cast<__u32>(backpressure.GetWatermarkLevel());
            bpf_map_update_elem(fd_watermark, &wm_key, &wm_value, BPF_ANY);
            last_watermark_ns = loop_now;
        }

        // 用户态计数器暴露：主循环周期同步（消费线程内层 pop 循环在高压下
        // 不退出，在那里同步会被饿死）。读 store 计数为跨线程近似读，仅用于可观测。
        if (loop_now - last_ustats_ns >= 1000000000ULL) {      // 1s
            sync_user_stats(fd_ustats, &bus, store, &mctx);
            last_ustats_ns = loop_now;
        }

        // SIGHUP 热加载：handler 只置标志，此处每轮检查（成功替换快照，失败保留旧配置）
        if (g_sighup_pending) {
            g_sighup_pending = 0;
            reload_monitor_config(config_path);
        }
        // retention 已移至消费线程（避免与文件处理并发访问 AlertManager）
    }

    // 停机：通知消费线程退出并等待其 drain/落库收尾
    running = false;
    consumer_thread.join();

    spdlog::info("[watermark] final utilization={:.1f}% level={}",
                 backpressure.GetUtilization(),
                 WatermarkBackpressure::LevelToString(backpressure.GetWatermarkLevel()));

    spdlog::info("[service_stop] monitoring loop exited");
    spdlog::info("Monitoring stopped.");
    if (epollfd >= 0)
        close(epollfd);
    if (proc_skel)
        process_monitor_stop(proc_skel, proc_rb);
    if (priv_skel)
        privilege_monitor_stop(priv_skel, priv_rb);
    if (net_skel)
        network_monitor_stop(net_skel, net_rb);
    ring_buffer__free(rb);

    bpf_map__unpin(skel->maps.drop_stats, "/sys/fs/bpf/baseline-guard/drop_stats");
    bpf_map__unpin(skel->maps.watermark_level, "/sys/fs/bpf/baseline-guard/watermark_level");
    bpf_map__unpin(skel->maps.user_stats, "/sys/fs/bpf/baseline-guard/user_stats");
    lsm_file_bpf__destroy(skel);

    delete store;
    if (baseline_db) {
        delete baseline_db;
        g_inode_to_baseline.clear();
    }
    return 0;
}

// ══════════════════════════════════════════════════════════════════
// 路径 B：内核 5.7 — BPF LSM + perf event buffer
// ══════════════════════════════════════════════════════════════════
static int do_monitor_perf(const Config& config, AlertManager &alert_mgr,
                           const std::string& config_path,
                           const std::string& baseline_db_path, bool skip_boot_check) {
    warn_telemetry_unavailable(config);

    struct lsm_file_perf_bpf *skel;
    int err;

    skel = lsm_file_perf_bpf__open();
    if (!skel) {
        spdlog::error("[bpf_program_error] Failed to open perf BPF skeleton");
        return 1;
    }

    // mmap_file hook 在 5.9 才引入
    if (skel->progs.file_mmap_hook && !kernel_at_least(5, 9)) {
        bpf_program__set_autoload(skel->progs.file_mmap_hook, false);
        spdlog::info("[bpf_compat] mmap_file hook disabled (kernel requires 5.9+)");
    }

    err = lsm_file_perf_bpf__load(skel);
    if (err) {
        spdlog::error("[bpf_program_error] Failed to load perf BPF skeleton: {}", err);
        lsm_file_perf_bpf__destroy(skel);
        return 1;
    }

    err = lsm_file_perf_bpf__attach(skel);
    if (err) {
        spdlog::error("[bpf_program_error] Failed to attach perf BPF program: {}", err);
        lsm_file_perf_bpf__destroy(skel);
        return 1;
    }
    spdlog::info("[bpf_program_loaded] BPF LSM (perf buffer) attached, kernel 5.7, {} rules",
                 config.rules.size());

    // Pin drop_stats
    (void)mkdir("/sys/fs/bpf/baseline-guard", 0755);
    pin_map_best_effort(skel->maps.drop_stats, DROP_STATS_PIN_PATH);
    pin_map_best_effort(skel->maps.user_stats, USER_STATS_PIN_PATH);

    int fd_actions = bpf_map__fd(skel->maps.monitor_actions);

    BaselineDB* baseline_db = nullptr;
    common_monitor_init(fd_actions, config, baseline_db_path, skip_boot_check, alert_mgr, baseline_db);

    // 无水位背压（perf buffer 无利用率查询）
    MonitorContext mctx;
    mctx.alert_mgr = &alert_mgr;
    mctx.user_stats_fd = bpf_map__fd(skel->maps.user_stats);

    spdlog::info("Monitoring started (perf buffer mode). Press Ctrl+C to stop.");

    struct perf_buffer *pb =
        perf_buffer__new(bpf_map__fd(skel->maps.events), 64,
                         perf_event_cb, nullptr, &mctx, nullptr);
    if (!pb) {
        spdlog::error("[bpf_program_error] Failed to create perf buffer");
        if (baseline_db) delete baseline_db;
        lsm_file_perf_bpf__destroy(skel);
        return 1;
    }

    run_perf_buffer_loop(pb, mctx, alert_mgr, config_path);

    spdlog::info("[service_stop] monitoring loop exited");
    spdlog::info("Monitoring stopped.");
    perf_buffer__free(pb);

    bpf_map__unpin(skel->maps.drop_stats, "/sys/fs/bpf/baseline-guard/drop_stats");
    bpf_map__unpin(skel->maps.user_stats, "/sys/fs/bpf/baseline-guard/user_stats");
    lsm_file_perf_bpf__destroy(skel);

    if (baseline_db) {
        delete baseline_db;
        g_inode_to_baseline.clear();
    }
    return 0;
}

// ══════════════════════════════════════════════════════════════════
// 路径 C：内核 5.4 — kprobe + perf event buffer（仅告警，无法阻止）
// ══════════════════════════════════════════════════════════════════
static int do_monitor_kprobe(const Config& config, AlertManager &alert_mgr,
                             const std::string& config_path,
                             const std::string& baseline_db_path, bool skip_boot_check) {
    warn_telemetry_unavailable(config);

    struct lsm_kprobe_bpf *skel;
    int err;

    spdlog::warn("[bpf_compat] kernel < 5.7, using kprobe mode — BLOCK actions degraded to ALERT only");

    skel = lsm_kprobe_bpf__open();
    if (!skel) {
        spdlog::error("[bpf_program_error] Failed to open kprobe BPF skeleton");
        return 1;
    }

    err = lsm_kprobe_bpf__load(skel);
    if (err) {
        spdlog::error("[bpf_program_error] Failed to load kprobe BPF skeleton: {}", err);
        lsm_kprobe_bpf__destroy(skel);
        return 1;
    }

    // 手动 attach kprobe 程序到内核函数
    struct bpf_link *link_perm   = bpf_program__attach_kprobe(skel->progs.kprobe_file_permission, false, "security_file_permission");
    struct bpf_link *link_chmod  = bpf_program__attach_kprobe(skel->progs.kprobe_path_chmod,     false, "security_path_chmod");
    struct bpf_link *link_chown  = bpf_program__attach_kprobe(skel->progs.kprobe_path_chown,     false, "security_path_chown");
    struct bpf_link *link_unlink = bpf_program__attach_kprobe(skel->progs.kprobe_inode_unlink,   false, "security_inode_unlink");
    struct bpf_link *link_rename = bpf_program__attach_kprobe(skel->progs.kprobe_inode_rename,   false, "security_inode_rename");

    if (!link_perm || !link_chmod || !link_chown || !link_unlink || !link_rename) {
        spdlog::error("[bpf_program_error] Failed to attach one or more kprobes");
        if (link_perm)   bpf_link__destroy(link_perm);
        if (link_chmod)  bpf_link__destroy(link_chmod);
        if (link_chown)  bpf_link__destroy(link_chown);
        if (link_unlink) bpf_link__destroy(link_unlink);
        if (link_rename) bpf_link__destroy(link_rename);
        lsm_kprobe_bpf__destroy(skel);
        return 1;
    }
    spdlog::info("[bpf_program_loaded] kprobe programs attached (5 kprobes), {} rules",
                 config.rules.size());

    // Pin drop_stats
    (void)mkdir("/sys/fs/bpf/baseline-guard", 0755);
    pin_map_best_effort(skel->maps.drop_stats, DROP_STATS_PIN_PATH);
    pin_map_best_effort(skel->maps.user_stats, USER_STATS_PIN_PATH);

    int fd_actions = bpf_map__fd(skel->maps.monitor_actions);

    BaselineDB* baseline_db = nullptr;
    common_monitor_init(fd_actions, config, baseline_db_path, skip_boot_check, alert_mgr, baseline_db);

    MonitorContext mctx;
    mctx.alert_mgr = &alert_mgr;
    mctx.user_stats_fd = bpf_map__fd(skel->maps.user_stats);

    spdlog::info("Monitoring started (kprobe mode, alert-only). Press Ctrl+C to stop.");

    struct perf_buffer *pb =
        perf_buffer__new(bpf_map__fd(skel->maps.events), 64,
                         perf_event_cb, nullptr, &mctx, nullptr);
    if (!pb) {
        spdlog::error("[bpf_program_error] Failed to create perf buffer for kprobe");
        if (baseline_db) delete baseline_db;
        bpf_link__destroy(link_perm);
        bpf_link__destroy(link_chmod);
        bpf_link__destroy(link_chown);
        bpf_link__destroy(link_unlink);
        bpf_link__destroy(link_rename);
        lsm_kprobe_bpf__destroy(skel);
        return 1;
    }

    run_perf_buffer_loop(pb, mctx, alert_mgr, config_path);

    spdlog::info("[service_stop] monitoring loop exited");
    spdlog::info("Monitoring stopped.");
    perf_buffer__free(pb);

    bpf_map__unpin(skel->maps.drop_stats, "/sys/fs/bpf/baseline-guard/drop_stats");
    bpf_map__unpin(skel->maps.user_stats, "/sys/fs/bpf/baseline-guard/user_stats");
    bpf_link__destroy(link_perm);
    bpf_link__destroy(link_chmod);
    bpf_link__destroy(link_chown);
    bpf_link__destroy(link_unlink);
    bpf_link__destroy(link_rename);
    lsm_kprobe_bpf__destroy(skel);

    if (baseline_db) {
        delete baseline_db;
        g_inode_to_baseline.clear();
    }
    return 0;
}

// ── 入口函数：根据内核版本分派到不同路径 ────────────────────────
int do_monitor(const Config& config, AlertManager &alert_mgr,
               const std::string& config_path,
               const std::string& baseline_db_path, bool skip_boot_check) {

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    // SIGHUP 热加载（M0-2）：handler 只置标志，各路径主循环每轮检查后原子替换快照；
    // 此处注册覆盖 main.cpp 的旧式 g_reload handler（进程不重启，pid 不变）
    signal(SIGHUP, monitor_sighup_handler);

    auto kv = get_kernel_version();
    spdlog::info("[kernel_detect] detected kernel {}.{}", kv.major, kv.minor);

    if (kv.major > 5 || (kv.major == 5 && kv.minor >= 8)) {
        // 5.8+: BPF LSM + ring buffer（完整功能）
        return do_monitor_ringbuf(config, alert_mgr, config_path, baseline_db_path, skip_boot_check);
    } else if (kv.major == 5 && kv.minor >= 7) {
        // 5.7: BPF LSM + perf event buffer（支持 block）
        return do_monitor_perf(config, alert_mgr, config_path, baseline_db_path, skip_boot_check);
    } else if (kv.major == 5 && kv.minor >= 4) {
        // 5.4~5.6: kprobe + perf event buffer（仅告警）
        return do_monitor_kprobe(config, alert_mgr, config_path, baseline_db_path, skip_boot_check);
    } else {
        spdlog::error("[kernel_unsupported] kernel {}.{} not supported, minimum is 5.4",
                     kv.major, kv.minor);
        return 1;
    }
}
