#pragma once

#include <memory>
#include <string>
#include <vector>

// ── 规则 DSL v1 数据结构（docs/rule-dsl-v1.md）──────────────────────
namespace detect {

enum class CmpOp { Eq, Ne, In, Contains, StartsWith };

// 字段标识：与 docs/event-schema-v1.md 全表一一对应，
// 是条件表达式与 output 模板加载期校验的唯一合法字段集。
enum class FieldId {
    unknown,
    event_type,
    process_pid,
    process_ppid,
    process_uid,
    process_gid,
    process_comm,
    process_exe,
    ancestor_pid,
    ancestor_comm,
    ancestor_exe, // process.ancestors[].*
    container_id, // container.container_id
    file_path,
    file_action,
    file_new_mode,
    file_ino,
    file_mask,
    file_new_uid,
    file_new_gid,
    net_sip,
    net_dip,
    net_family,
    net_protocol,
    net_sport,
    net_dport,
    dns_domain,
    dns_qtype,
    priv_target_id,
    priv_effective_lo,
    priv_target_pid,
    priv_request_value,
    priv_request,
    priv_name,
    ns_source,
    ns_target,
    ns_fstype,
    ns_nstype_name,
    ns_target_ns,
    ns_flags,
    ns_fd,
    ns_nstype,
    ns_names, // ns.names[]
};

bool FieldIsNumber(FieldId id);
bool FieldIsArrayElem(FieldId id); // ancestor_* / ns_names：[] 任一元素语义

// 字段路径（如 process.ancestors[].exe）→ FieldId；不在字段表内返回 false
bool FieldIdFromPath(const std::string &path, FieldId &out);

// 比较操作数：字段引用或字面值（list 仅作 in 的右操作数，元素仅 Str/Num）
struct Operand {
    enum class Kind { Field, Str, Num, List } kind = Kind::Str;
    FieldId field = FieldId::unknown; // kind=Field
    std::string str;           // kind=Str 的文本；kind=Num 时保留原始书写（如 0644）
    long long num = 0;         // kind=Num
    std::vector<Operand> list; // kind=List
};

struct CondNode {
    enum class Kind { Or, And, Not, Compare } kind = Kind::Compare;
    CmpOp op = CmpOp::Eq;                            // kind=Compare
    Operand lhs, rhs;                                // kind=Compare
    std::vector<std::unique_ptr<CondNode>> children; // kind=And/Or
    std::unique_ptr<CondNode> child;                 // kind=Not
};

struct Rule {
    std::string name; // rule（全局唯一）
    std::string desc;
    std::string output_template; // output（%字段路径 插值）
    std::string priority;        // critical/high/medium/low（可选，缺省 medium）
    std::vector<std::string> attack;
    std::string fpr_note;
    std::string response;
    std::string source_file; // 来源文件（日志/排障用）
    std::unique_ptr<CondNode> condition;
};

} // namespace detect
