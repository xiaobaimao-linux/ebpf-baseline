#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "rule.hpp"

// ── 规则匹配引擎（docs/rule-dsl-v1.md）──────────────────────────────
// 单线程语义：引擎加载期完成全部编译，求值只读，无内部可变状态，
// 可安全地以 shared_ptr<const RuleEngine> 快照整代替换（SIGHUP 热加载）。
namespace detect {

struct AncestorView {
    long long pid = 0;
    std::string_view comm;
    std::string_view exe;
};

// 求值输入：覆盖 event-schema-v1 全字段族。填充方按事件类别填自己有的
// 字段族并把对应 has_* 置位，其余保持默认即视为缺失（缺失语义：
// string 按空串、number 比较一律为 false）。
// string_view 引用的内存须在 Evaluate 调用期间有效。
// 扩展点：v1 接入方仅 file + process.exec 两类；network/dns/priv/ns
// 字段族访问器已定义全，后续接入方按同样方式填充即可。
struct EventView {
    std::string_view event_type;

    // process.*（所有事件恒有）
    long long pid = 0, ppid = 0, uid = 0, gid = 0;
    std::string_view comm, exe;
    std::string_view container_id;       // 宿主机进程为空
    std::vector<AncestorView> ancestors; // 自近及远 ≤8 层

    // file.*
    bool has_file = false;
    std::string_view file_path, file_action, file_new_mode;
    long long file_ino = 0, file_mask = 0, file_new_uid = 0, file_new_gid = 0;

    // network.*
    bool has_network = false;
    std::string_view net_sip, net_dip;
    long long net_family = 0, net_protocol = 0, net_sport = 0, net_dport = 0;

    // dns.*
    bool has_dns = false;
    std::string_view dns_domain;
    long long dns_qtype = 0;

    // priv.*
    bool has_priv = false;
    std::string_view priv_request, priv_name;
    long long priv_target_id = 0, priv_effective_lo = 0, priv_target_pid = 0,
              priv_request_value = 0;

    // ns.*
    bool has_ns = false;
    std::string_view ns_source, ns_target, ns_fstype, ns_nstype_name, ns_target_ns;
    long long ns_flags = 0, ns_fd = 0, ns_nstype = 0;
    std::vector<std::string_view> ns_names;
};

struct MatchResult {
    const Rule *rule = nullptr; // 指向引擎内部规则存储，快照存活期内有效
    std::string output;         // 渲染后的 output 模板
};

// output 模板编译产物（%字段路径 插值 + %rule.name/%rule.priority 伪字段）
struct TemplateSeg {
    bool is_field = false;
    std::string text; // is_field=false 的字面段
    FieldId field = FieldId::unknown;
    bool pseudo_name = false;     // %rule.name
    bool pseudo_priority = false; // %rule.priority
};

// ── 事件类型字面预过滤（W4 D4 性能优化）─────────────────────────────
// 已知事件类型全集（与 event-schema-v1 §2 一致）映射为小整数，
// 位图 bit = 1u << id；kEtUnknownBit 留给表外类型（未来新增类型）。
// 规则编译期从 condition 提取"命中事件必须满足的事件类型集合"（And 取交、
// Or 取并、Not 放弃约束），求值时每事件一次整数映射 + 每规则一次位测试，
// 不满足直接跳过整条 AST 求值。
enum EventTypeId {
    kEtFileRead = 0, kEtFileWrite, kEtFileAccess, kEtFileChmod, kEtFileChown,
    kEtFileUnlink, kEtFileRename, kEtFileMmap,
    kEtProcessExec,
    kEtNetworkConnect, kEtNetworkAccept, kEtNetworkBind, kEtNetworkDns,
    kEtPrivSetuid, kEtPrivSetgid, kEtPrivCapset, kEtPrivPtrace, kEtPrivModuleLoad,
    kEtNsMount, kEtNsUnshare, kEtNsSetns,
    kEtCount
};
constexpr uint32_t kEtUnknownBit = 1u << kEtCount;
constexpr uint32_t kEtAllMask = (1u << kEtCount) - 1u;

// 事件类型字符串 → ID；表外返回 -1（调用方按 kEtUnknownBit 处理）
int EventTypeIdOf(std::string_view event_type);

// 解析 output 模板为段序列；未知字段/数组字段插值报错（err 不含文件:行号）
bool ParseOutputTemplate(const std::string &tmpl, std::vector<TemplateSeg> &out, std::string &err);

class RuleEngine {
  public:
    RuleEngine() = default;

    // 接管 loader 产出的规则（已校验），编译 output 模板并按事件类别建桶索引。
    // 失败（理论不发生，loader 已校验）返回 false + err。
    bool Build(std::vector<Rule> rules, std::string &err);

    // 逐条求值对应类别桶 + all 桶，首条命中即返回（加载顺序）。
    // 命中返回 true 并填充 out；未命中返回 false（out.rule 置空）。
    bool Evaluate(const EventView &view, MatchResult &out) const;

    size_t rule_count() const {
        return rules_.size();
    }

  private:
    struct CompiledRule {
        const Rule *rule = nullptr;
        std::vector<TemplateSeg> segs;
        // 命中事件必须属于的事件类型位图（见 hpp 顶部注释）；kEtAllMask|kEtUnknownBit = 无约束
        uint32_t et_mask = kEtAllMask | kEtUnknownBit;
    };

    enum Bucket { kFile = 0, kProcess, kNetwork, kDns, kPriv, kNs, kAll, kNumBuckets };

    static Bucket BucketOfEventType(std::string_view event_type);
    static Bucket ExtractBucket(const CondNode &cond);

    std::vector<Rule> rules_; // 规则存储（CompiledRule::rule 指向此处）
    std::vector<CompiledRule> buckets_[kNumBuckets];
};

} // namespace detect
