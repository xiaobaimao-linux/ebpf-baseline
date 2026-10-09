// 单元测试：规则 DSL 解析器 + 匹配引擎（W4 D3/D4）
// 编译: make test_rule_dsl（见 tests/Makefile）

#include <cassert>
#include <cstdio>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <vector>

#include "condition_parser.hpp"
#include "rule_engine.hpp"
#include "rule_loader.hpp"

using detect::CondNode;
using detect::EventView;
using detect::FieldId;
using detect::MatchResult;
using detect::Operand;
using detect::Rule;
using detect::RuleEngine;

// ====== 工具 ======

static void write_file(const std::string &path, const std::string &content) {
    std::ofstream f(path);
    f << content;
}

static std::string make_dir(const std::string &name) {
    const std::string dir = "/tmp/baseline_rdsl_" + name;
    mkdir(dir.c_str(), 0755);
    return dir;
}

// 构造一条最小合法规则 YAML（可覆盖任意字段文本）
static std::string rule_yaml(const std::string &name, const std::string &condition,
                             const std::string &priority = "high",
                             const std::string &output = "hit (rule=%rule.name)") {
    return "- rule: " + name + "\n" + "  desc: test rule\n" + "  condition: " + condition + "\n" +
           "  output: \"" + output + "\"\n" + "  priority: " + priority + "\n" +
           "  attack: [T1000]\n" + "  fpr_note: none\n" + "  response: none\n";
}

static bool load_single(const std::string &dir_name, const std::string &file_name,
                        const std::string &content, std::vector<Rule> &rules, std::string &err) {
    const std::string dir = make_dir(dir_name);
    write_file(dir + "/" + file_name, content);
    return detect::LoadRulesDir(dir, rules, err);
}

static EventView base_view(const char *event_type) {
    EventView v;
    v.event_type = event_type;
    v.pid = 1234;
    v.ppid = 1000;
    v.uid = 0;
    v.gid = 0;
    v.comm = "cat";
    v.exe = "/usr/bin/cat";
    return v;
}

static RuleEngine build_engine(std::vector<Rule> rules) {
    RuleEngine engine;
    std::string err;
    const bool ok = engine.Build(std::move(rules), err);
    assert(ok);
    return engine;
}

// ====== RDSL-001: 3 条示例规则解析成功，五元组齐全 ======
void test_examples_parse() {
    std::vector<Rule> rules;
    std::string err;
    const bool ok = detect::LoadRulesDir("../rules/examples", rules, err);
    assert(ok && err.empty());
    assert(rules.size() == 3);
    for (const auto &r : rules) {
        assert(!r.name.empty());
        assert(!r.desc.empty());
        assert(r.condition != nullptr);
        assert(!r.output_template.empty());
        assert(!r.priority.empty());
        assert(!r.attack.empty());
        assert(!r.fpr_note.empty());
        assert(!r.response.empty());
    }
    // 文件名排序：docker_in_container < read_etc_shadow < reverse_shell
    assert(rules[0].name == "Docker CLI Executed Inside Container");
    assert(rules[1].name == "Read Etc Shadow By Unusual Process");
    assert(rules[2].name == "Reverse Shell From Web Service");
    assert(rules[0].priority == "critical");
    assert(rules[1].priority == "high");
    assert(rules[1].attack.size() == 2);
    assert(rules[1].attack[0] == "T1003");
    printf("[PASS] RDSL-001: 3 条示例规则解析成功，五元组齐全\n");
}

// ====== RDSL-002: 示例规则 AST 结构断言 ======
void test_examples_ast() {
    std::vector<Rule> rules;
    std::string err;
    assert(detect::LoadRulesDir("../rules/examples", rules, err));

    // docker 规则：And(event_type=, container_id!=, exe in (...))
    const Rule &docker = rules[0];
    assert(docker.condition->kind == CondNode::Kind::And);
    assert(docker.condition->children.size() == 3);
    const CondNode &c0 = *docker.condition->children[0];
    assert(c0.kind == CondNode::Kind::Compare);
    assert(c0.lhs.field == FieldId::event_type);
    assert(c0.rhs.kind == Operand::Kind::Str && c0.rhs.str == "process.exec");
    const CondNode &c1 = *docker.condition->children[1];
    assert(c1.lhs.field == FieldId::container_id && c1.op == detect::CmpOp::Ne);
    const CondNode &c2 = *docker.condition->children[2];
    assert(c2.op == detect::CmpOp::In && c2.rhs.kind == Operand::Kind::List);
    assert(c2.rhs.list.size() == 4);

    // shadow 规则：And 第三子节点为 Not(In)
    const Rule &shadow = rules[1];
    assert(shadow.condition->kind == CondNode::Kind::And);
    assert(shadow.condition->children.size() == 3);
    const CondNode &s2 = *shadow.condition->children[2];
    assert(s2.kind == CondNode::Kind::Not);
    assert(s2.child->kind == CondNode::Kind::Compare);
    assert(s2.child->op == detect::CmpOp::In);
    assert(s2.child->lhs.field == FieldId::process_exe);
    assert(s2.child->rhs.list.size() == 7);

    // reverse shell：祖先链数组字段
    const Rule &rshell = rules[2];
    assert(rshell.condition->kind == CondNode::Kind::And);
    const CondNode &r2 = *rshell.condition->children[2];
    assert(r2.lhs.field == FieldId::ancestor_comm);
    assert(r2.op == detect::CmpOp::In);
    assert(r2.rhs.list.size() == 9);
    printf("[PASS] RDSL-002: 示例规则 AST 结构断言\n");
}

// ====== RDSL-003: 未知字段报错（含文件名:行号）======
void test_unknown_field() {
    std::vector<Rule> rules;
    std::string err;
    const bool ok = load_single("bad_field", "bad_field.yaml",
                                rule_yaml("R1", "process.cmdline = /bin/sh"), rules, err);
    assert(!ok);
    assert(err.find("bad_field.yaml:3:") != std::string::npos);
    assert(err.find("未知字段") != std::string::npos);
    printf("[PASS] RDSL-003: 未知字段报错（%s）\n", err.c_str());
}

// ====== RDSL-004: condition 语法错误（括号不配对）======
void test_syntax_error_paren() {
    std::vector<Rule> rules;
    std::string err;
    const bool ok = load_single("bad_paren", "bad_paren.yaml",
                                rule_yaml("R1", "( event_type = file.read"), rules, err);
    assert(!ok);
    assert(err.find("bad_paren.yaml:3:") != std::string::npos);
    printf("[PASS] RDSL-004: 括号不配对报错（%s）\n", err.c_str());
}

// ====== RDSL-005: condition 语法错误（非法操作符）======
void test_syntax_error_op() {
    std::vector<Rule> rules;
    std::string err;
    const bool ok = load_single("bad_op", "bad_op.yaml", rule_yaml("R1", "event_type =~ file.read"),
                                rules, err);
    assert(!ok);
    assert(err.find("bad_op.yaml:3:") != std::string::npos);
    printf("[PASS] RDSL-005: 非法操作符报错（%s）\n", err.c_str());
}

// ====== RDSL-006: priority 缺省补 medium（W5 D3：可选字段，解析不报错）======
void test_priority_default() {
    std::vector<Rule> rules;
    std::string err;
    const std::string content = "- rule: R1\n"
                                "  desc: x\n"
                                "  condition: event_type = file.read\n"
                                "  output: \"x\"\n"
                                "  attack: [T1000]\n"
                                "  fpr_note: x\n"
                                "  response: x\n";
    const bool ok = load_single("noprio", "noprio.yaml", content, rules, err);
    assert(ok && err.empty());
    assert(rules.size() == 1);
    assert(rules[0].priority == "medium");
    printf("[PASS] RDSL-006: priority 缺省补 medium\n");
}

// ====== RDSL-006b: 缺其他必填字段（output）仍报错 ======
void test_missing_required() {
    std::vector<Rule> rules;
    std::string err;
    const std::string content = "- rule: R1\n"
                                "  desc: x\n"
                                "  condition: event_type = file.read\n"
                                "  priority: high\n"
                                "  attack: [T1000]\n"
                                "  fpr_note: x\n"
                                "  response: x\n";
    const bool ok = load_single("missing", "missing.yaml", content, rules, err);
    assert(!ok);
    assert(err.find("missing.yaml:1:") != std::string::npos);
    assert(err.find("output") != std::string::npos);
    printf("[PASS] RDSL-006b: 缺必填字段报错（%s）\n", err.c_str());
}

// ====== RDSL-007: priority 非法值报错 ======
void test_bad_priority() {
    std::vector<Rule> rules;
    std::string err;
    const bool ok = load_single("badprio", "badprio.yaml",
                                rule_yaml("R1", "event_type = file.read", "urgent"), rules, err);
    assert(!ok);
    assert(err.find("badprio.yaml:5:") != std::string::npos);
    assert(err.find("priority") != std::string::npos);
    printf("[PASS] RDSL-007: priority 非法值报错（%s）\n", err.c_str());
}

// ====== RDSL-008: 规则名全局查重 ======
void test_dup_name() {
    const std::string dir = make_dir("dup");
    write_file(dir + "/a.yaml", rule_yaml("Same Name", "event_type = file.read"));
    write_file(dir + "/b.yaml", rule_yaml("Same Name", "event_type = process.exec"));
    std::vector<Rule> rules;
    std::string err;
    assert(!detect::LoadRulesDir(dir, rules, err));
    assert(err.find("b.yaml:1:") != std::string::npos);
    assert(err.find("重复") != std::string::npos);
    printf("[PASS] RDSL-008: 规则名全局查重（%s）\n", err.c_str());
}

// ====== RDSL-009: shadow 规则命中/不命中（含 not in 白名单）======
void test_shadow_eval() {
    std::vector<Rule> rules;
    std::string err;
    assert(detect::LoadRulesDir("../rules/examples", rules, err));
    auto engine = build_engine(std::move(rules));
    MatchResult m;

    // 命中：非白名单进程读 /etc/shadow
    EventView v = base_view("file.read");
    v.has_file = true;
    v.file_path = "/etc/shadow";
    v.file_ino = 123;
    assert(engine.Evaluate(v, m));
    assert(m.rule->name == "Read Etc Shadow By Unusual Process");
    assert(m.output.find("/usr/bin/cat") != std::string::npos);

    // 白名单进程：not process.exe in (...) 为假 → 不命中
    v.exe = "/usr/bin/passwd";
    assert(!engine.Evaluate(v, m));

    // 事件类型不符 → 不命中
    v.exe = "/usr/bin/cat";
    v.event_type = "file.write";
    assert(!engine.Evaluate(v, m));

    // 路径不符 → 不命中
    v.event_type = "file.read";
    v.file_path = "/etc/passwd";
    assert(!engine.Evaluate(v, m));
    printf("[PASS] RDSL-009: shadow 规则命中/白名单/类别/路径断言\n");
}

// ====== RDSL-010: docker 规则（container_id 缺失不命中）======
void test_docker_eval() {
    std::vector<Rule> rules;
    std::string err;
    assert(detect::LoadRulesDir("../rules/examples", rules, err));
    auto engine = build_engine(std::move(rules));
    MatchResult m;

    // 容器内 docker → 命中
    EventView v = base_view("process.exec");
    v.exe = "/usr/bin/docker";
    v.container_id = "abcdef123456";
    assert(engine.Evaluate(v, m));
    assert(m.rule->name == "Docker CLI Executed Inside Container");
    assert(m.output.find("abcdef123456") != std::string::npos);

    // 宿主机（container_id 缺失按空串，!= "" 为假）→ 不命中
    v.container_id = "";
    assert(!engine.Evaluate(v, m));
    printf("[PASS] RDSL-010: docker 规则容器归属断言（缺失不命中）\n");
}

// ====== RDSL-011: reverse shell 规则（祖先链任意深度匹配）======
void test_reverse_shell_eval() {
    std::vector<Rule> rules;
    std::string err;
    assert(detect::LoadRulesDir("../rules/examples", rules, err));
    auto engine = build_engine(std::move(rules));
    MatchResult m;

    EventView v = base_view("process.exec");
    v.exe = "/bin/bash";
    // ancestors[3] 命中 nginx（≤8 层任意深度任一元素语义）
    v.ancestors = {{1000, "sshd", "/usr/sbin/sshd"},
                   {900, "bash", "/bin/bash"},
                   {800, "php-fpm", "/usr/sbin/php-fpm"},
                   {700, "nginx", "/usr/sbin/nginx"}};
    assert(engine.Evaluate(v, m));
    assert(m.rule->name == "Reverse Shell From Web Service");

    // 祖先链无 Web 服务 → 不命中
    v.ancestors = {{1000, "sshd", "/usr/sbin/sshd"}, {900, "bash", "/bin/bash"}};
    assert(!engine.Evaluate(v, m));

    // exe 非 shell → 不命中
    v.exe = "/usr/bin/curl";
    v.ancestors = {{700, "nginx", "/usr/sbin/nginx"}};
    assert(!engine.Evaluate(v, m));
    printf("[PASS] RDSL-011: reverse shell 祖先链任意深度匹配断言\n");
}

// ====== RDSL-012: output 模板插值（缺失字段渲染空串 + 伪字段）======
void test_output_template() {
    std::vector<Rule> rules;
    std::string err;
    assert(load_single("tmpl", "tmpl.yaml",
                       rule_yaml("T1", "event_type = file.read and file.path = /x", "low",
                                 "exe=%process.exe uid=%process.uid c=%container.container_id "
                                 "p=%rule.priority n=%rule.name end"),
                       rules, err));
    auto engine = build_engine(std::move(rules));
    MatchResult m;
    EventView v = base_view("file.read");
    v.has_file = true;
    v.file_path = "/x";
    // 宿主机：container_id 缺失 → 空串
    assert(engine.Evaluate(v, m));
    assert(m.output == "exe=/usr/bin/cat uid=0 c= p=low n=T1 end");

    v.container_id = "cid123";
    assert(engine.Evaluate(v, m));
    assert(m.output == "exe=/usr/bin/cat uid=0 c=cid123 p=low n=T1 end");
    printf("[PASS] RDSL-012: output 模板插值（缺失字段空串 + 伪字段）\n");
}

// ====== RDSL-013: and/or 短路与优先级 ======
void test_short_circuit() {
    std::vector<Rule> rules;
    std::string err;
    // or 左真即停：右操作数涉及缺失 number 字段也不影响结果
    assert(load_single("or", "or.yaml", rule_yaml("Or1", "event_type = file.read or file.ino = 1"),
                       rules, err));
    auto engine = build_engine(std::move(rules));
    MatchResult m;
    EventView v = base_view("file.read"); // has_file=false：file.ino 缺失
    assert(engine.Evaluate(v, m));        // 左真短路 → 命中

    // and 左假即停
    v.event_type = "file.write";
    assert(!engine.Evaluate(v, m));

    // and 优先级高于 or：a and b or c ≡ (a and b) or c
    std::vector<Rule> rules2;
    assert(load_single("prec", "prec.yaml",
                       rule_yaml("P1", "event_type = process.exec and process.exe = /bin/sh or "
                                       "event_type = file.read"),
                       rules2, err));
    auto engine2 = build_engine(std::move(rules2));
    v.event_type = "file.read";
    assert(engine2.Evaluate(v, m)); // or 右侧命中
    printf("[PASS] RDSL-013: and/or 短路与优先级断言\n");
}

// ====== RDSL-014: 缺失字段语义（number 比较一律 false）======
void test_missing_number_field() {
    std::vector<Rule> rules;
    std::string err;
    assert(load_single("missnum", "missnum.yaml",
                       rule_yaml("N1", "event_type = file.read and file.ino != 5"), rules, err));
    auto engine = build_engine(std::move(rules));
    MatchResult m;
    EventView v = base_view("file.read"); // has_file=false
    assert(!engine.Evaluate(v, m));       // number 缺失：!= 也为 false
    v.has_file = true;
    v.file_ino = 7;
    assert(engine.Evaluate(v, m));
    printf("[PASS] RDSL-014: 缺失 number 字段比较一律 false\n");
}

// ====== RDSL-015: startswith / contains / ns.names[] ======
void test_string_ops() {
    std::vector<Rule> rules;
    std::string err;
    assert(load_single("strops", "strops.yaml",
                       rule_yaml("S1", "event_type = file.write and file.path startswith /etc/ and "
                                       "file.path contains shadow"),
                       rules, err));
    auto engine = build_engine(std::move(rules));
    MatchResult m;
    EventView v = base_view("file.write");
    v.has_file = true;
    v.file_path = "/etc/shadow";
    assert(engine.Evaluate(v, m));
    v.file_path = "/tmp/shadow";
    assert(!engine.Evaluate(v, m));

    // ns.names[] 任一元素
    std::vector<Rule> rules2;
    assert(load_single("nsnames", "nsnames.yaml",
                       rule_yaml("NS1", "event_type = ns.unshare and ns.names[] = CLONE_NEWNS"),
                       rules2, err));
    auto engine2 = build_engine(std::move(rules2));
    v = base_view("ns.unshare");
    v.has_ns = true;
    v.ns_names = {"CLONE_NEWNS", "CLONE_NEWNET"};
    assert(engine2.Evaluate(v, m));
    v.ns_names = {"CLONE_NEWNET"};
    assert(!engine2.Evaluate(v, m));
    printf("[PASS] RDSL-015: startswith/contains/ns.names[] 断言\n");
}

// ====== RDSL-016: output 模板未知字段报错 ======
void test_template_unknown_field() {
    std::vector<Rule> rules;
    std::string err;
    const bool ok = load_single(
        "badtmpl", "badtmpl.yaml",
        rule_yaml("T1", "event_type = file.read", "high", "x=%process.cmdline"), rules, err);
    assert(!ok);
    assert(err.find("badtmpl.yaml:4:") != std::string::npos);
    assert(err.find("未知字段") != std::string::npos);
    printf("[PASS] RDSL-016: output 模板未知字段报错（%s）\n", err.c_str());
}

// ====== RDSL-017: 事件类型预过滤不得改变语义（Or 取并/Not 放弃约束）======
void test_et_prefilter_semantics() {
    std::vector<Rule> rules;
    std::string err;
    MatchResult m;

    // 关键陷阱：or 另一支无 event_type 约束 → 并集退化为全集，预过滤不得排除
    assert(load_single("etor", "etor.yaml",
                       rule_yaml("ETOR", "event_type = file.read or file.path = /etc/shadow"),
                       rules, err));
    auto engine = build_engine(std::move(rules));
    EventView v = base_view("file.write"); // file.write 不满足第一支，但路径命中第二支
    v.has_file = true;
    v.file_path = "/etc/shadow";
    assert(engine.Evaluate(v, m));
    v.file_path = "/tmp/other";
    assert(!engine.Evaluate(v, m));

    // not 之下的 event_type 不产生正约束：file.write 仍须被求值并命中
    std::vector<Rule> rules2;
    assert(load_single("etnot", "etnot.yaml",
                       rule_yaml("ETNOT", "not event_type = file.read and file.path = /etc/shadow"),
                       rules2, err));
    auto engine2 = build_engine(std::move(rules2));
    v.file_path = "/etc/shadow";
    assert(engine2.Evaluate(v, m)); // file.write + 路径命中
    v = base_view("file.read");
    v.has_file = true;
    v.file_path = "/etc/shadow";
    assert(!engine2.Evaluate(v, m)); // file.read 被 not 排除

    // 交集收敛：两个冲突 event_type 约束的规则永不命中（死规则，预过滤放空）
    std::vector<Rule> rules3;
    assert(load_single("etdead", "etdead.yaml",
                       rule_yaml("ETDEAD", "event_type = file.read and event_type = file.write"),
                       rules3, err));
    auto engine3 = build_engine(std::move(rules3));
    v = base_view("file.read");
    assert(!engine3.Evaluate(v, m));

    // 表外事件类型：只评无约束规则，带字面约束的规则不得命中
    std::vector<Rule> rules4;
    assert(load_single("etunk", "etunk.yaml",
                       rule_yaml("ETUNK", "event_type = file.read"), rules4, err));
    auto engine4 = build_engine(std::move(rules4));
    v = base_view("future.newtype");
    assert(!engine4.Evaluate(v, m));
    printf("[PASS] RDSL-017: 事件类型预过滤语义（Or 并集/Not 放弃/死规则/表外类型）\n");
}

int main() {
    test_examples_parse();
    test_examples_ast();
    test_unknown_field();
    test_syntax_error_paren();
    test_syntax_error_op();
    test_priority_default();
    test_missing_required();
    test_bad_priority();
    test_dup_name();
    test_shadow_eval();
    test_docker_eval();
    test_reverse_shell_eval();
    test_output_template();
    test_short_circuit();
    test_missing_number_field();
    test_string_ops();
    test_template_unknown_field();
    test_et_prefilter_semantics();
    printf("[PASS] ALL test_rule_dsl done\n");
    return 0;
}
