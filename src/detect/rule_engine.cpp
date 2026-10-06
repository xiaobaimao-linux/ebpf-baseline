#include "rule_engine.hpp"

#include <cctype>

namespace detect {

namespace {

// 字段解析结果：number 字段用 num，string 字段用 str；
// has=false 表示字段缺失（number 比较一律 false，string 按空串）
struct FieldVal {
    bool has = false;
    long long num = 0;
    std::string_view str;
};

bool resolve_scalar(const EventView &ev, FieldId id, FieldVal &out) {
    out = FieldVal{};
    switch (id) {
    case FieldId::event_type:
        out.has = true;
        out.str = ev.event_type;
        return true;
    case FieldId::process_pid:
        out.has = true;
        out.num = ev.pid;
        return true;
    case FieldId::process_ppid:
        out.has = true;
        out.num = ev.ppid;
        return true;
    case FieldId::process_uid:
        out.has = true;
        out.num = ev.uid;
        return true;
    case FieldId::process_gid:
        out.has = true;
        out.num = ev.gid;
        return true;
    case FieldId::process_comm:
        out.has = true;
        out.str = ev.comm;
        return true;
    case FieldId::process_exe:
        out.has = true;
        out.str = ev.exe;
        return true;
    case FieldId::container_id:
        out.has = true;
        out.str = ev.container_id;
        return true;

    case FieldId::file_path:
        out.str = ev.file_path;
        break;
    case FieldId::file_action:
        out.str = ev.file_action;
        break;
    case FieldId::file_new_mode:
        out.str = ev.file_new_mode;
        break;
    case FieldId::file_ino:
        out.num = ev.file_ino;
        break;
    case FieldId::file_mask:
        out.num = ev.file_mask;
        break;
    case FieldId::file_new_uid:
        out.num = ev.file_new_uid;
        break;
    case FieldId::file_new_gid:
        out.num = ev.file_new_gid;
        break;

    case FieldId::net_sip:
        out.str = ev.net_sip;
        break;
    case FieldId::net_dip:
        out.str = ev.net_dip;
        break;
    case FieldId::net_family:
        out.num = ev.net_family;
        break;
    case FieldId::net_protocol:
        out.num = ev.net_protocol;
        break;
    case FieldId::net_sport:
        out.num = ev.net_sport;
        break;
    case FieldId::net_dport:
        out.num = ev.net_dport;
        break;

    case FieldId::dns_domain:
        out.str = ev.dns_domain;
        break;
    case FieldId::dns_qtype:
        out.num = ev.dns_qtype;
        break;

    case FieldId::priv_request:
        out.str = ev.priv_request;
        break;
    case FieldId::priv_name:
        out.str = ev.priv_name;
        break;
    case FieldId::priv_target_id:
        out.num = ev.priv_target_id;
        break;
    case FieldId::priv_effective_lo:
        out.num = ev.priv_effective_lo;
        break;
    case FieldId::priv_target_pid:
        out.num = ev.priv_target_pid;
        break;
    case FieldId::priv_request_value:
        out.num = ev.priv_request_value;
        break;

    case FieldId::ns_source:
        out.str = ev.ns_source;
        break;
    case FieldId::ns_target:
        out.str = ev.ns_target;
        break;
    case FieldId::ns_fstype:
        out.str = ev.ns_fstype;
        break;
    case FieldId::ns_nstype_name:
        out.str = ev.ns_nstype_name;
        break;
    case FieldId::ns_target_ns:
        out.str = ev.ns_target_ns;
        break;
    case FieldId::ns_flags:
        out.num = ev.ns_flags;
        break;
    case FieldId::ns_fd:
        out.num = ev.ns_fd;
        break;
    case FieldId::ns_nstype:
        out.num = ev.ns_nstype;
        break;

    default:
        return false; // 数组元素字段不走标量解析
    }
    // 族级缺失：string 仍按空串（has=true），number 标缺失（has=false）
    bool family_present = true;
    switch (id) {
    case FieldId::file_path:
    case FieldId::file_action:
    case FieldId::file_new_mode:
    case FieldId::file_ino:
    case FieldId::file_mask:
    case FieldId::file_new_uid:
    case FieldId::file_new_gid:
        family_present = ev.has_file;
        break;
    case FieldId::net_sip:
    case FieldId::net_dip:
    case FieldId::net_family:
    case FieldId::net_protocol:
    case FieldId::net_sport:
    case FieldId::net_dport:
        family_present = ev.has_network;
        break;
    case FieldId::dns_domain:
    case FieldId::dns_qtype:
        family_present = ev.has_dns;
        break;
    case FieldId::priv_request:
    case FieldId::priv_name:
    case FieldId::priv_target_id:
    case FieldId::priv_effective_lo:
    case FieldId::priv_target_pid:
    case FieldId::priv_request_value:
        family_present = ev.has_priv;
        break;
    case FieldId::ns_source:
    case FieldId::ns_target:
    case FieldId::ns_fstype:
    case FieldId::ns_nstype_name:
    case FieldId::ns_target_ns:
    case FieldId::ns_flags:
    case FieldId::ns_fd:
    case FieldId::ns_nstype:
        family_present = ev.has_ns;
        break;
    default:
        break;
    }
    if (FieldIsNumber(id)) {
        out.has = family_present;
    } else {
        out.has = true;
        if (!family_present)
            out.str = {};
    }
    return true;
}

// 操作数 → 值（字段引用解析；字段缺失时 valid=false）
struct Value {
    bool valid = true;
    bool is_num = false;
    long long num = 0;
    std::string_view str;
};

Value operand_value(const EventView &ev, const Operand &op) {
    Value v;
    if (op.kind == Operand::Kind::Num) {
        v.is_num = true;
        v.num = op.num;
        v.str = op.str;
        return v;
    }
    if (op.kind == Operand::Kind::Str) {
        v.str = op.str;
        return v;
    }
    // Field
    FieldVal fv;
    if (!resolve_scalar(ev, op.field, fv)) {
        v.valid = false;
        return v;
    }
    if (FieldIsNumber(op.field)) {
        if (!fv.has) {
            v.valid = false;
            return v;
        }
        v.is_num = true;
        v.num = fv.num;
    } else {
        v.str = fv.str;
    }
    return v;
}

// 字段值 vs 字面值单元素比较（eq 语义；contains/startswith 按 op）
bool cmp_field_literal(FieldId fid, const FieldVal &fv, CmpOp op, const Value &lit) {
    if (FieldIsNumber(fid)) {
        if (!fv.has || !lit.valid || !lit.is_num)
            return false; // number 缺失/类型不符一律 false
        switch (op) {
        case CmpOp::Eq:
            return fv.num == lit.num;
        case CmpOp::Ne:
            return fv.num != lit.num;
        default:
            return false;
        }
    }
    // string 字段：缺失按空串
    const std::string_view s = fv.has ? fv.str : std::string_view{};
    const std::string_view l = lit.valid ? lit.str : std::string_view{};
    switch (op) {
    case CmpOp::Eq:
        return s == l;
    case CmpOp::Ne:
        return s != l;
    case CmpOp::Contains:
        return s.find(l) != std::string_view::npos;
    case CmpOp::StartsWith:
        return s.substr(0, l.size()) == l;
    default:
        return false;
    }
}

// 数组字段（ancestors[] / ns.names[]）：任一元素满足即真
bool match_array_any(const EventView &ev, FieldId fid, CmpOp op, const Value &lit) {
    if (fid == FieldId::ns_names) {
        for (const std::string_view name : ev.ns_names) {
            FieldVal fv;
            fv.has = true;
            fv.str = name;
            if (cmp_field_literal(fid, fv, op, lit))
                return true;
        }
        return false;
    }
    for (const AncestorView &a : ev.ancestors) {
        FieldVal fv;
        fv.has = true;
        switch (fid) {
        case FieldId::ancestor_pid:
            fv.num = a.pid;
            break;
        case FieldId::ancestor_comm:
            fv.str = a.comm;
            break;
        case FieldId::ancestor_exe:
            fv.str = a.exe;
            break;
        default:
            return false;
        }
        if (cmp_field_literal(fid, fv, op, lit))
            return true;
    }
    return false;
}

bool eval_compare(const EventView &ev, const CondNode &n) {
    const Operand &lhs = n.lhs;

    // 字段 vs 字段（v1 规则集未使用，按两侧解析值比较）
    if (lhs.kind == Operand::Kind::Field && n.rhs.kind == Operand::Kind::Field) {
        const Value a = operand_value(ev, lhs);
        const Value b = operand_value(ev, n.rhs);
        if (!a.valid || !b.valid)
            return false;
        if (a.is_num != b.is_num)
            return false;
        const bool eq = a.is_num ? (a.num == b.num) : (a.str == b.str);
        switch (n.op) {
        case CmpOp::Eq:
            return eq;
        case CmpOp::Ne:
            return !eq;
        default:
            return false;
        }
    }

    // lhs 必须是字段（literal vs literal 恒真/恒假无检测意义，但按值比较支持）
    if (lhs.kind != Operand::Kind::Field) {
        const Value a = operand_value(ev, lhs);
        const Value b = operand_value(ev, n.rhs);
        if (n.rhs.kind == Operand::Kind::List)
            return false;
        if (!a.valid || !b.valid)
            return false;
        if (a.is_num != b.is_num)
            return false;
        const bool eq = a.is_num ? (a.num == b.num) : (a.str == b.str);
        switch (n.op) {
        case CmpOp::Eq:
            return eq;
        case CmpOp::Ne:
            return !eq;
        default:
            return false;
        }
    }

    const FieldId fid = lhs.field;

    // 数组字段：任一元素满足即真
    if (FieldIsArrayElem(fid)) {
        if (n.rhs.kind == Operand::Kind::List) {
            // in ( ... )：任一祖先元素等于列表任一字面值
            for (const auto &elem : n.rhs.list) {
                Value lit;
                lit.is_num = (elem.kind == Operand::Kind::Num);
                lit.num = elem.num;
                lit.str = elem.str;
                if (match_array_any(ev, fid, n.op == CmpOp::In ? CmpOp::Eq : n.op, lit))
                    return true;
            }
            return false;
        }
        const Value lit = operand_value(ev, n.rhs);
        return match_array_any(ev, fid, n.op, lit);
    }

    FieldVal fv;
    resolve_scalar(ev, fid, fv);
    if (n.rhs.kind == Operand::Kind::List) {
        // in：任一元素相等即真
        for (const auto &elem : n.rhs.list) {
            Value lit;
            lit.is_num = (elem.kind == Operand::Kind::Num);
            lit.num = elem.num;
            lit.str = elem.str;
            if (cmp_field_literal(fid, fv, CmpOp::Eq, lit))
                return true;
        }
        return false;
    }
    const Value lit = operand_value(ev, n.rhs);
    return cmp_field_literal(fid, fv, n.op, lit);
}

bool eval_node(const EventView &ev, const CondNode &n) {
    switch (n.kind) {
    case CondNode::Kind::And:
        for (const auto &c : n.children) {
            if (!eval_node(ev, *c))
                return false; // 短路
        }
        return true;
    case CondNode::Kind::Or:
        for (const auto &c : n.children) {
            if (eval_node(ev, *c))
                return true; // 短路
        }
        return false;
    case CondNode::Kind::Not:
        return !eval_node(ev, *n.child);
    case CondNode::Kind::Compare:
        return eval_compare(ev, n);
    }
    return false;
}

void render_field_value(const EventView &ev, FieldId id, std::string &out) {
    FieldVal fv;
    if (!resolve_scalar(ev, id, fv) || !fv.has)
        return; // 缺失渲染空串
    if (FieldIsNumber(id)) {
        out += std::to_string(fv.num);
    } else {
        out.append(fv.str.data(), fv.str.size());
    }
}

} // namespace

bool ParseOutputTemplate(const std::string &tmpl, std::vector<TemplateSeg> &out, std::string &err) {
    out.clear();
    size_t i = 0;
    while (i < tmpl.size()) {
        const size_t pct = tmpl.find('%', i);
        if (pct == std::string::npos) {
            if (i < tmpl.size())
                out.push_back(TemplateSeg{false, tmpl.substr(i), FieldId::unknown, false, false});
            break;
        }
        if (pct > i)
            out.push_back(
                TemplateSeg{false, tmpl.substr(i, pct - i), FieldId::unknown, false, false});
        // % 后跟字段路径字符 [a-z0-9._]；否则按字面 %
        size_t j = pct + 1;
        while (j < tmpl.size() && (std::isalnum(static_cast<unsigned char>(tmpl[j])) ||
                                   tmpl[j] == '.' || tmpl[j] == '_'))
            ++j;
        if (j == pct + 1) {
            out.push_back(TemplateSeg{false, "%", FieldId::unknown, false, false});
            i = pct + 1;
            continue;
        }
        const std::string path = tmpl.substr(pct + 1, j - pct - 1);
        TemplateSeg seg;
        seg.is_field = true;
        if (path == "rule.name") {
            seg.pseudo_name = true;
        } else if (path == "rule.priority") {
            seg.pseudo_priority = true;
        } else {
            FieldId id;
            if (!FieldIdFromPath(path, id)) {
                err = "output 模板引用了未知字段: " + path;
                return false;
            }
            if (FieldIsArrayElem(id)) {
                err = "output 模板不支持数组字段插值: " + path;
                return false;
            }
            seg.field = id;
        }
        out.push_back(std::move(seg));
        i = j;
    }
    return true;
}

int EventTypeIdOf(std::string_view event_type) {
    static const std::pair<std::string_view, int> kTable[] = {
        {"file.read", kEtFileRead},         {"file.write", kEtFileWrite},
        {"file.access", kEtFileAccess},     {"file.chmod", kEtFileChmod},
        {"file.chown", kEtFileChown},       {"file.unlink", kEtFileUnlink},
        {"file.rename", kEtFileRename},     {"file.mmap", kEtFileMmap},
        {"process.exec", kEtProcessExec},
        {"network.connect", kEtNetworkConnect}, {"network.accept", kEtNetworkAccept},
        {"network.bind", kEtNetworkBind},   {"network.dns", kEtNetworkDns},
        {"priv.setuid", kEtPrivSetuid},     {"priv.setgid", kEtPrivSetgid},
        {"priv.capset", kEtPrivCapset},     {"priv.ptrace", kEtPrivPtrace},
        {"priv.module_load", kEtPrivModuleLoad},
        {"ns.mount", kEtNsMount},           {"ns.unshare", kEtNsUnshare},
        {"ns.setns", kEtNsSetns},
    };
    for (const auto &[name, id] : kTable) {
        if (name == event_type)
            return id;
    }
    return -1;
}

namespace {

// 字面值（Str/Num 操作数）→ 事件类型位；表外字面值给 unknown 位（保守）
uint32_t et_bit_of_literal(const Operand &op) {
    const int id = EventTypeIdOf(op.str);
    return id >= 0 ? (1u << id) : kEtUnknownBit;
}

// "节点为真要求事件类型必须属于"的位图：
//   Compare(event_type Eq/In 正例) → 字面值并集；其余 Compare → 全集
//   Not → 全集（否定不产生正约束）；And → 子节点交集；Or → 子节点并集
uint32_t et_necessary_mask(const CondNode &n) {
    switch (n.kind) {
    case CondNode::Kind::Compare: {
        if (n.lhs.kind != Operand::Kind::Field || n.lhs.field != FieldId::event_type)
            return kEtAllMask | kEtUnknownBit;
        if (n.op == CmpOp::Eq && n.rhs.kind == Operand::Kind::Str)
            return et_bit_of_literal(n.rhs);
        if (n.op == CmpOp::In && n.rhs.kind == Operand::Kind::List) {
            uint32_t m = 0;
            for (const auto &elem : n.rhs.list)
                m |= et_bit_of_literal(elem);
            return m;
        }
        return kEtAllMask | kEtUnknownBit; // Ne/contains/startswith 不产生正约束
    }
    case CondNode::Kind::And: {
        uint32_t m = kEtAllMask | kEtUnknownBit;
        for (const auto &c : n.children)
            m &= et_necessary_mask(*c);
        return m;
    }
    case CondNode::Kind::Or: {
        uint32_t m = 0;
        for (const auto &c : n.children)
            m |= et_necessary_mask(*c);
        return m;
    }
    case CondNode::Kind::Not:
        return kEtAllMask | kEtUnknownBit;
    }
    return kEtAllMask | kEtUnknownBit;
}

} // namespace

RuleEngine::Bucket RuleEngine::BucketOfEventType(std::string_view event_type) {
    const size_t dot = event_type.find('.');
    const std::string_view first = event_type.substr(0, dot);
    if (first == "file")
        return kFile;
    if (first == "process")
        return kProcess;
    if (first == "priv")
        return kPriv;
    if (first == "ns")
        return kNs;
    if (first == "dns")
        return kDns;
    if (first == "network") {
        // network.dns 归 dns 桶，其余 network.* 归 network 桶
        const std::string_view second =
            dot == std::string_view::npos ? std::string_view{} : event_type.substr(dot + 1);
        return second == "dns" ? kDns : kNetwork;
    }
    return kAll;
}

// 从 condition 顶层 and 链提取 event_type = xxx 字面约束的类别桶；
// 提取不出（无约束 / or 顶层 / 跨类别）放 all 桶
RuleEngine::Bucket RuleEngine::ExtractBucket(const CondNode &cond) {
    auto bucket_of_compare = [](const CondNode &n, Bucket &out) -> bool {
        if (n.kind != CondNode::Kind::Compare || n.lhs.kind != Operand::Kind::Field ||
            n.lhs.field != FieldId::event_type)
            return false;
        if (n.op == CmpOp::Eq && n.rhs.kind == Operand::Kind::Str) {
            out = BucketOfEventType(n.rhs.str);
            return out != kAll;
        }
        if (n.op == CmpOp::In && n.rhs.kind == Operand::Kind::List && !n.rhs.list.empty()) {
            Bucket b = BucketOfEventType(n.rhs.list.front().str);
            if (b == kAll)
                return false;
            for (const auto &elem : n.rhs.list) {
                if (BucketOfEventType(elem.str) != b)
                    return false;
            }
            out = b;
            return true;
        }
        return false;
    };

    if (cond.kind == CondNode::Kind::And) {
        Bucket found = kAll;
        for (const auto &c : cond.children) {
            Bucket b;
            if (bucket_of_compare(*c, b)) {
                if (found != kAll && found != b)
                    return kAll; // 跨类别约束（恒假），保守放 all
                found = b;
            }
        }
        return found;
    }
    Bucket b;
    if (bucket_of_compare(cond, b))
        return b;
    return kAll;
}

bool RuleEngine::Build(std::vector<Rule> rules, std::string &err) {
    rules_ = std::move(rules);
    for (auto &bucket : buckets_)
        bucket.clear();
    for (const Rule &r : rules_) {
        CompiledRule cr;
        cr.rule = &r;
        cr.et_mask = et_necessary_mask(*r.condition);
        if (!ParseOutputTemplate(r.output_template, cr.segs, err)) {
            err = r.source_file + ": " + r.name + ": " + err;
            return false;
        }
        buckets_[ExtractBucket(*r.condition)].push_back(std::move(cr));
    }
    return true;
}

bool RuleEngine::Evaluate(const EventView &view, MatchResult &out) const {
    out.rule = nullptr;
    out.output.clear();
    // 事件类型整数映射：每事件一次，预过滤位测试用
    const int et_id = EventTypeIdOf(view.event_type);
    const uint32_t et_bit = et_id >= 0 ? (1u << et_id) : kEtUnknownBit;
    const Bucket b = BucketOfEventType(view.event_type);
    // 对应类别桶 + all 桶（未知类别仅评 all 桶一次）
    const Bucket order[2] = {b, kAll};
    const int nbucket = (b == kAll) ? 1 : 2;
    for (int i = 0; i < nbucket; ++i) {
        for (const CompiledRule &cr : buckets_[order[i]]) {
            if (!(cr.et_mask & et_bit))
                continue; // 事件类型预过滤：整条 AST 跳过
            if (!eval_node(view, *cr.rule->condition))
                continue;
            out.rule = cr.rule;
            for (const TemplateSeg &seg : cr.segs) {
                if (!seg.is_field) {
                    out.output += seg.text;
                } else if (seg.pseudo_name) {
                    out.output += cr.rule->name;
                } else if (seg.pseudo_priority) {
                    out.output += cr.rule->priority;
                } else {
                    render_field_value(view, seg.field, out.output);
                }
            }
            return true;
        }
    }
    return false;
}

} // namespace detect
