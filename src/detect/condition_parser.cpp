#include "condition_parser.hpp"

#include <cctype>

namespace detect {

bool FieldIsNumber(FieldId id) {
    switch (id) {
    case FieldId::process_pid:
    case FieldId::process_ppid:
    case FieldId::process_uid:
    case FieldId::process_gid:
    case FieldId::ancestor_pid:
    case FieldId::file_ino:
    case FieldId::file_mask:
    case FieldId::file_new_uid:
    case FieldId::file_new_gid:
    case FieldId::net_family:
    case FieldId::net_protocol:
    case FieldId::net_sport:
    case FieldId::net_dport:
    case FieldId::dns_qtype:
    case FieldId::priv_target_id:
    case FieldId::priv_effective_lo:
    case FieldId::priv_target_pid:
    case FieldId::priv_request_value:
    case FieldId::ns_flags:
    case FieldId::ns_fd:
    case FieldId::ns_nstype:
        return true;
    default:
        return false;
    }
}

bool FieldIsArrayElem(FieldId id) {
    return id == FieldId::ancestor_pid || id == FieldId::ancestor_comm ||
           id == FieldId::ancestor_exe || id == FieldId::ns_names;
}

bool FieldIdFromPath(const std::string &path, FieldId &out) {
    static const struct {
        const char *path;
        FieldId id;
    } kFields[] = {
        {"event_type", FieldId::event_type},
        {"process.pid", FieldId::process_pid},
        {"process.ppid", FieldId::process_ppid},
        {"process.uid", FieldId::process_uid},
        {"process.gid", FieldId::process_gid},
        {"process.comm", FieldId::process_comm},
        {"process.exe", FieldId::process_exe},
        {"process.ancestors[].pid", FieldId::ancestor_pid},
        {"process.ancestors[].comm", FieldId::ancestor_comm},
        {"process.ancestors[].exe", FieldId::ancestor_exe},
        {"container.container_id", FieldId::container_id},
        {"file.path", FieldId::file_path},
        {"file.action", FieldId::file_action},
        {"file.new_mode", FieldId::file_new_mode},
        {"file.ino", FieldId::file_ino},
        {"file.mask", FieldId::file_mask},
        {"file.new_uid", FieldId::file_new_uid},
        {"file.new_gid", FieldId::file_new_gid},
        {"network.sip", FieldId::net_sip},
        {"network.dip", FieldId::net_dip},
        {"network.family", FieldId::net_family},
        {"network.protocol", FieldId::net_protocol},
        {"network.sport", FieldId::net_sport},
        {"network.dport", FieldId::net_dport},
        {"dns.domain", FieldId::dns_domain},
        {"dns.qtype", FieldId::dns_qtype},
        {"priv.target_id", FieldId::priv_target_id},
        {"priv.effective_lo", FieldId::priv_effective_lo},
        {"priv.target_pid", FieldId::priv_target_pid},
        {"priv.request_value", FieldId::priv_request_value},
        {"priv.request", FieldId::priv_request},
        {"priv.name", FieldId::priv_name},
        {"ns.source", FieldId::ns_source},
        {"ns.target", FieldId::ns_target},
        {"ns.fstype", FieldId::ns_fstype},
        {"ns.nstype_name", FieldId::ns_nstype_name},
        {"ns.target_ns", FieldId::ns_target_ns},
        {"ns.flags", FieldId::ns_flags},
        {"ns.fd", FieldId::ns_fd},
        {"ns.nstype", FieldId::ns_nstype},
        {"ns.names[]", FieldId::ns_names},
    };
    for (const auto &f : kFields) {
        if (path == f.path) {
            out = f.id;
            return true;
        }
    }
    out = FieldId::unknown;
    return false;
}

namespace {

enum class TokKind { End, LParen, RParen, Comma, Eq, Ne, Bare };

struct Token {
    TokKind kind = TokKind::End;
    std::string text;          // kind=Bare
    size_t pos = 0;            // 字节偏移（错误定位）
    bool quoted_empty = false; // "" 空串字面值（v1 唯一支持的引号形式）
};

// 裸字面值字符集：字母数字与 /._-:*+@[]（= != 恒为操作符，遇空白/括号/逗号截止）
bool is_bare_char(char c) {
    const unsigned char u = static_cast<unsigned char>(c);
    if (std::isalnum(u))
        return true;
    switch (c) {
    case '/':
    case '.':
    case '_':
    case '-':
    case ':':
    case '*':
    case '+':
    case '@':
    case '[':
    case ']':
        return true;
    default:
        return false;
    }
}

class Lexer {
  public:
    explicit Lexer(const std::string &text) : text_(text) {
    }

    Token Next() {
        while (pos_ < text_.size() && std::isspace(static_cast<unsigned char>(text_[pos_])))
            ++pos_;
        Token t;
        t.pos = pos_;
        if (pos_ >= text_.size()) {
            t.kind = TokKind::End;
            return t;
        }
        const char c = text_[pos_];
        switch (c) {
        case '(':
            ++pos_;
            t.kind = TokKind::LParen;
            return t;
        case ')':
            ++pos_;
            t.kind = TokKind::RParen;
            return t;
        case ',':
            ++pos_;
            t.kind = TokKind::Comma;
            return t;
        case '=':
            ++pos_;
            t.kind = TokKind::Eq;
            return t;
        case '!':
            if (pos_ + 1 < text_.size() && text_[pos_ + 1] == '=') {
                pos_ += 2;
                t.kind = TokKind::Ne;
                return t;
            }
            t.kind = TokKind::Bare; // 孤立 !：交解析器报错
            t.text = "!";
            ++pos_;
            return t;
        case '"':
            // v1 仅支持 "" 空串字面值（container.container_id != "" 标准写法），
            // 其余引号字符串交解析器报错（留给 v2）
            if (pos_ + 1 < text_.size() && text_[pos_ + 1] == '"') {
                pos_ += 2;
                t.kind = TokKind::Bare;
                t.quoted_empty = true;
                return t;
            }
            t.kind = TokKind::Bare;
            t.text = "\"";
            ++pos_;
            return t;
        default:
            break;
        }
        if (!is_bare_char(c)) {
            t.kind = TokKind::Bare; // 非法字符单字符 token，交解析器报错
            t.text.assign(1, c);
            ++pos_;
            return t;
        }
        const size_t start = pos_;
        while (pos_ < text_.size() && is_bare_char(text_[pos_]))
            ++pos_;
        t.kind = TokKind::Bare;
        t.text = text_.substr(start, pos_ - start);
        return t;
    }

  private:
    const std::string &text_;
    size_t pos_ = 0;
};

bool is_keyword(const std::string &s) {
    return s == "and" || s == "or" || s == "not" || s == "in" || s == "contains" ||
           s == "startswith";
}

// 形似字段路径：event_type 本身或带已知族前缀（用于"未知字段"报错的启发式）
bool looks_like_field(const std::string &s) {
    static const char *kPrefixes[] = {"process.", "container.", "file.", "network.",
                                      "dns.",     "priv.",      "ns."};
    if (s == "event_type")
        return true;
    for (const char *p : kPrefixes) {
        if (s.compare(0, std::string(p).size(), p) == 0)
            return true;
    }
    return false;
}

bool is_number_text(const std::string &s) {
    if (s.empty())
        return false;
    for (char c : s) {
        if (!std::isdigit(static_cast<unsigned char>(c)))
            return false;
    }
    return true;
}

class Parser {
  public:
    explicit Parser(const std::string &text) : lexer_(text) {
        Advance();
    }

    std::unique_ptr<CondNode> Parse() {
        auto node = ParseOr();
        if (!node)
            return nullptr;
        if (tok_.kind != TokKind::End) {
            Fail("表达式末尾存在多余内容: '" + tok_.text + "'");
            return nullptr;
        }
        return node;
    }

    const std::string &err() const {
        return err_;
    }

  private:
    void Advance() {
        tok_ = lexer_.Next();
    }

    void Fail(const std::string &msg) {
        if (err_.empty())
            err_ = msg;
    }

    bool PeekKw(const char *kw) const {
        return tok_.kind == TokKind::Bare && tok_.text == kw;
    }

    std::unique_ptr<CondNode> ParseOr() {
        auto lhs = ParseAnd();
        if (!lhs)
            return nullptr;
        if (!PeekKw("or"))
            return lhs;
        auto node = std::make_unique<CondNode>();
        node->kind = CondNode::Kind::Or;
        node->children.push_back(std::move(lhs));
        while (PeekKw("or")) {
            Advance();
            auto rhs = ParseAnd();
            if (!rhs)
                return nullptr;
            node->children.push_back(std::move(rhs));
        }
        return node;
    }

    std::unique_ptr<CondNode> ParseAnd() {
        auto lhs = ParseNot();
        if (!lhs)
            return nullptr;
        if (!PeekKw("and"))
            return lhs;
        auto node = std::make_unique<CondNode>();
        node->kind = CondNode::Kind::And;
        node->children.push_back(std::move(lhs));
        while (PeekKw("and")) {
            Advance();
            auto rhs = ParseNot();
            if (!rhs)
                return nullptr;
            node->children.push_back(std::move(rhs));
        }
        return node;
    }

    std::unique_ptr<CondNode> ParseNot() {
        if (PeekKw("not")) {
            Advance();
            auto child = ParseNot();
            if (!child)
                return nullptr;
            auto node = std::make_unique<CondNode>();
            node->kind = CondNode::Kind::Not;
            node->child = std::move(child);
            return node;
        }
        if (tok_.kind == TokKind::LParen) {
            Advance();
            auto inner = ParseOr();
            if (!inner)
                return nullptr;
            if (tok_.kind != TokKind::RParen) {
                Fail("括号不配对：缺少 ')'");
                return nullptr;
            }
            Advance();
            return inner;
        }
        return ParseComparison();
    }

    // force_literal：event_type 比较的右操作数强制按字面值（file.read 等
    // 事件类型值形似字段路径，不做未知字段校验）
    bool ParseOperand(Operand &out, bool force_literal) {
        if (tok_.kind != TokKind::Bare) {
            Fail("此处应为字段路径或字面值，得到 '" +
                 (tok_.kind == TokKind::End ? std::string("<结束>") : tok_.text) + "'");
            return false;
        }
        if (is_keyword(tok_.text)) {
            Fail("关键字 '" + tok_.text + "' 不能用作操作数");
            return false;
        }
        if (tok_.quoted_empty) {
            Advance();
            out.kind = Operand::Kind::Str; // "" 空串字面值
            return true;
        }
        if (tok_.text == "\"") {
            Fail("v1 不支持引号字符串（仅支持空串 \"\"）");
            return false;
        }
        const std::string text = tok_.text;
        Advance();
        if (!force_literal) {
            FieldId id;
            if (FieldIdFromPath(text, id)) {
                out.kind = Operand::Kind::Field;
                out.field = id;
                return true;
            }
            if (looks_like_field(text)) {
                Fail("未知字段: " + text);
                return false;
            }
        }
        if (is_number_text(text)) {
            out.kind = Operand::Kind::Num;
            out.str = text; // 保留原始书写（0644 与字符串字段比较时用原文本）
            try {
                out.num = std::stoll(text);
            } catch (...) {
                Fail("数字字面值溢出: " + text);
                return false;
            }
            return true;
        }
        out.kind = Operand::Kind::Str;
        out.str = text;
        return true;
    }

    bool ParseList(Operand &out, bool force_literal) {
        // 当前 token 为 '('
        Advance();
        out.kind = Operand::Kind::List;
        if (tok_.kind == TokKind::RParen) {
            Fail("列表不能为空");
            return false;
        }
        while (true) {
            Operand elem;
            if (!ParseOperand(elem, force_literal))
                return false;
            if (elem.kind == Operand::Kind::Field) {
                Fail("列表元素必须是字面值，不能是字段引用");
                return false;
            }
            out.list.push_back(std::move(elem));
            if (tok_.kind == TokKind::Comma) {
                Advance();
                continue;
            }
            if (tok_.kind == TokKind::RParen) {
                Advance();
                return true;
            }
            Fail("列表中缺少 ',' 或 ')'");
            return false;
        }
    }

    std::unique_ptr<CondNode> ParseComparison() {
        auto node = std::make_unique<CondNode>();
        node->kind = CondNode::Kind::Compare;
        if (!ParseOperand(node->lhs, false))
            return nullptr;

        CmpOp op;
        if (tok_.kind == TokKind::Eq) {
            op = CmpOp::Eq;
        } else if (tok_.kind == TokKind::Ne) {
            op = CmpOp::Ne;
        } else if (tok_.kind == TokKind::Bare && tok_.text == "in") {
            op = CmpOp::In;
        } else if (tok_.kind == TokKind::Bare && tok_.text == "contains") {
            op = CmpOp::Contains;
        } else if (tok_.kind == TokKind::Bare && tok_.text == "startswith") {
            op = CmpOp::StartsWith;
        } else {
            Fail("此处应为比较操作符（= != in contains startswith），得到 '" +
                 (tok_.kind == TokKind::End ? std::string("<结束>") : tok_.text) + "'");
            return nullptr;
        }
        node->op = op;
        Advance();

        // event_type 字段参与的比较：对侧为事件类型字面值（如 file.read），
        // 形似字段路径但不走字段校验
        const bool force_literal =
            node->lhs.kind == Operand::Kind::Field && node->lhs.field == FieldId::event_type;

        if (tok_.kind == TokKind::LParen) {
            if (op != CmpOp::In) {
                Fail("列表仅允许作为 in 的右操作数");
                return nullptr;
            }
            if (!ParseList(node->rhs, force_literal))
                return nullptr;
        } else {
            if (op == CmpOp::In) {
                Fail("in 的右操作数必须是列表 ( ... )");
                return nullptr;
            }
            if (!ParseOperand(node->rhs, force_literal))
                return nullptr;
        }

        // contains/startswith 仅 string：数字字段做左操作数直接判加载期错误
        if ((op == CmpOp::Contains || op == CmpOp::StartsWith) &&
            node->lhs.kind == Operand::Kind::Field && FieldIsNumber(node->lhs.field)) {
            Fail("contains/startswith 仅支持字符串字段");
            return nullptr;
        }
        return node;
    }

    Lexer lexer_;
    Token tok_;
    std::string err_;
};

} // namespace

std::unique_ptr<CondNode> ParseCondition(const std::string &text, std::string &err) {
    err.clear();
    if (text.find_first_not_of(" \t\r\n") == std::string::npos) {
        err = "条件表达式为空";
        return nullptr;
    }
    Parser p(text);
    auto node = p.Parse();
    if (!node)
        err = p.err();
    return node;
}

} // namespace detect
