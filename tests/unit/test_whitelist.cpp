// 单元测试：进程白名单匹配器 + whitelist 配置解析
// 编译: make test_whitelist（见 tests/Makefile）

#include <cassert>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <unistd.h>
#include <vector>

#include "config.hpp"
#include "container.hpp"
#include "whitelist.hpp"

// 当前进程 exe 路径（readlink /proc/self/exe，与匹配器同一取法）
static std::string self_exe() {
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return "";
    buf[n] = '\0';
    return std::string(buf);
}

static std::string parent_exe() {
    char path[64];
    char buf[4096];
    snprintf(path, sizeof(path), "/proc/%d/exe", static_cast<int>(getppid()));
    ssize_t n = readlink(path, buf, sizeof(buf) - 1);
    if (n <= 0) return "";
    buf[n] = '\0';
    return std::string(buf);
}

// 构造仅含一条白名单规则的配置
static Config make_config(const std::vector<WhitelistEntry>& wl, const std::string& id = "WL-TEST-001") {
    Config c;
    Rule r;
    r.id = id;
    r.name = id;
    r.whitelist = wl;
    c.rules.push_back(r);
    return c;
}

static Rule make_rule(const std::string& id = "WL-TEST-001") {
    Rule r;
    r.id = id;
    r.name = id;
    return r;
}

// ====== WLU-001: exe 精确匹配命中 / 不命中 ======
void test_exe_exact_match() {
    const std::string me = self_exe();
    assert(!me.empty());
    auto table = WhitelistTable::Build(make_config({{me, {}}}));
    Rule rule = make_rule();

    WhitelistMatcher m;
    std::string exe;
    assert(m.Match(*table, rule, getpid(), &exe) == true);
    assert(exe == me);

    auto table2 = WhitelistTable::Build(make_config({{"/usr/bin/not-this-binary", {}}}));
    WhitelistMatcher m2;
    assert(m2.Match(*table2, rule, getpid(), &exe) == false);
    printf("  [PASS] WLU-001: exe 精确匹配命中/不命中\n");
}

// ====== WLU-002: parent_chain 任一祖先命中 / 全部未命中 ======
void test_parent_chain_any_ancestor() {
    const std::string me = self_exe();
    const std::string parent = parent_exe();
    assert(!parent.empty());
    Rule rule = make_rule();

    // 任一祖先命中即可（第一个 bogus、第二个真实父进程）
    auto table = WhitelistTable::Build(make_config({{me, {"/no/such/ancestor", parent}}}));
    WhitelistMatcher m;
    assert(m.Match(*table, rule, getpid()) == true);

    // 全部祖先未命中
    auto table2 = WhitelistTable::Build(make_config({{me, {"/no/such/ancestor", "/also/no"}}}));
    WhitelistMatcher m2;
    assert(m2.Match(*table2, rule, getpid()) == false);
    printf("  [PASS] WLU-002: parent_chain 任一祖先命中/全部未命中\n");
}

// ====== WLU-003: 条目内 AND 语义 ======
void test_entry_and_semantics() {
    const std::string me = self_exe();
    const std::string parent = parent_exe();
    Rule rule = make_rule();

    // exe 不匹配：即使祖先命中也不豁免（AND）
    auto table = WhitelistTable::Build(make_config({{"/no/such/exe", {parent}}}));
    WhitelistMatcher m;
    assert(m.Match(*table, rule, getpid()) == false);

    // exe 匹配但祖先条件未满足：不豁免（AND）
    auto table2 = WhitelistTable::Build(make_config({{me, {"/no/such/ancestor"}}}));
    WhitelistMatcher m2;
    assert(m2.Match(*table2, rule, getpid()) == false);
    printf("  [PASS] WLU-003: 条目内 AND 语义\n");
}

// ====== WLU-004: 条目间 OR 语义 ======
void test_entry_or_semantics() {
    const std::string me = self_exe();
    Rule rule = make_rule();

    auto table = WhitelistTable::Build(make_config({{"/no/such/exe", {}}, {me, {}}}));
    WhitelistMatcher m;
    assert(m.Match(*table, rule, getpid()) == true);
    printf("  [PASS] WLU-004: 条目间 OR 语义\n");
}

// ====== WLU-005: fail-closed（不存在的 pid 不豁免）======
void test_fail_closed() {
    const std::string me = self_exe();
    auto table = WhitelistTable::Build(make_config({{me, {}}}));
    Rule rule = make_rule();

    WhitelistMatcher m;
    // 不存在 pid：/proc/<pid>/stat 打不开 → false（不给豁免）
    assert(m.Match(*table, rule, 4194303) == false);
    assert(m.Match(*table, rule, 0) == false);
    assert(m.Match(*table, rule, -1) == false);
    printf("  [PASS] WLU-005: fail-closed（不存在 pid 不豁免）\n");
}

// ====== WLU-006: 快照替换后新配置生效、旧副本仍可读 ======
void test_snapshot_replace() {
    const std::string me = self_exe();
    Rule rule = make_rule();

    auto t1 = WhitelistTable::Build(make_config({{me, {}}}));    // 旧配置：命中
    auto t2 = WhitelistTable::Build(make_config({}));            // 新配置：无白名单

    assert(t1->Match(rule, me, {}) == true);    // 旧快照判定不变
    assert(t2->Match(rule, me, {}) == false);   // 新快照生效（不命中）
    assert(t1->Match(rule, me, {}) == true);    // 旧副本仍可读
    assert(t1->Match(rule, "/other", {}) == false);
    printf("  [PASS] WLU-006: 快照替换后新配置生效、旧副本仍可读\n");
}

// ====== WLU-007: ClearCache 后按新表重新判定 ======
void test_clear_cache() {
    const std::string me = self_exe();
    Rule rule = make_rule();

    auto t1 = WhitelistTable::Build(make_config({{me, {}}}));
    auto t2 = WhitelistTable::Build(make_config({}));

    WhitelistMatcher m;
    assert(m.Match(*t1, rule, getpid()) == true);
    assert(m.CacheSize() == 1);

    // 模拟热加载：换表 + ClearCache（与 monitor.cpp reload_monitor_config 同序）。
    // 缓存键为 (pid,start_time) 不含表代次，换表必须伴随 ClearCache（生产同此约定）
    m.ClearCache();
    assert(m.CacheSize() == 0);
    assert(m.Match(*t2, rule, getpid()) == false);   // 重新判定：新表生效
    m.ClearCache();
    assert(m.Match(*t1, rule, getpid()) == true);    // 重新判定：旧表结果仍正确
    assert(m.CacheSize() == 1);
    printf("  [PASS] WLU-007: ClearCache 后重新判定\n");
}

// ====== WLU-008: 缓存按 (pid,start_time) 去重，重复匹配不膨胀 ======
void test_cache_dedup() {
    const std::string me = self_exe();
    auto table = WhitelistTable::Build(make_config({{me, {}}}));
    Rule rule = make_rule();

    WhitelistMatcher m;
    for (int i = 0; i < 5; ++i)
        assert(m.Match(*table, rule, getpid()) == true);
    assert(m.CacheSize() == 1);   // 同一进程仅一条缓存

    // 抑制计数累计 5
    auto deltas = m.GetAndResetSuppressed();
    uint64_t total = 0;
    for (const auto& [id, n] : deltas) {
        assert(id == "WL-TEST-001");
        total += n;
    }
    assert(total == 5);
    assert(m.GetAndResetSuppressed().empty());   // 取后已清零
    printf("  [PASS] WLU-008: 缓存 (pid,start_time) 去重 + 抑制计数累计/清零\n");
}

// ====== 配置解析：临时 yaml 工具 ======
static std::string write_temp(const std::string& content, const std::string& suffix = ".yaml") {
    std::string path = "/tmp/wl_test_" + std::to_string(getpid()) + suffix;
    std::ofstream f(path);
    f << content;
    return path;
}

// ====== WLCFG-001: whitelist 配置正确解析进 Rule ======
void test_config_parse_ok() {
    std::string yaml = R"(rules:
  - id: "WL-001"
    name: "白名单规则"
    severity: "medium"
    monitor:
      path: "/tmp/wl_f"
      events:
        - "write"
      action: "alert"
    whitelist:
      - exe: "/usr/bin/tee"
      - exe: "/opt/wl_writer"
        parent_chain:
          - "/opt/wl_parent"
          - "/usr/bin/bash"
)";
    std::string path = write_temp(yaml);
    Config cfg;
    std::string err;
    bool ok = tryParseYamlFile(path, cfg, err);
    std::remove(path.c_str());
    assert(ok);
    assert(cfg.rules.size() == 1);
    assert(cfg.rules[0].whitelist.size() == 2);
    assert(cfg.rules[0].whitelist[0].exe == "/usr/bin/tee");
    assert(cfg.rules[0].whitelist[0].parent_chain.empty());
    assert(cfg.rules[0].whitelist[1].exe == "/opt/wl_writer");
    assert(cfg.rules[0].whitelist[1].parent_chain.size() == 2);
    printf("  [PASS] WLCFG-001: whitelist 配置正确解析进 Rule\n");
}

// ====== WLCFG-002: whitelist 非列表 → 整体失败 + 行号 ======
void test_config_whitelist_not_list() {
    std::string yaml = R"(rules:
  - id: "WL-001"
    name: "白名单规则"
    monitor:
      path: "/tmp/wl_f"
      events:
        - "write"
      action: "alert"
    whitelist: "/usr/bin/tee"
)";
    std::string path = write_temp(yaml);
    Config cfg;
    std::string err;
    bool ok = tryParseYamlFile(path, cfg, err);
    std::remove(path.c_str());
    assert(!ok);
    assert(err.find(":9:") != std::string::npos);   // whitelist 在第 9 行
    printf("  [PASS] WLCFG-002: whitelist 非列表整体失败并给行号 (%s)\n", err.c_str());
}

// ====== WLCFG-003: 条目缺 exe → 整体失败 + 行号 ======
void test_config_entry_missing_exe() {
    std::string yaml = R"(rules:
  - id: "WL-001"
    name: "白名单规则"
    monitor:
      path: "/tmp/wl_f"
      events:
        - "write"
      action: "alert"
    whitelist:
      - parent_chain:
          - "/usr/bin/bash"
)";
    std::string path = write_temp(yaml);
    Config cfg;
    std::string err;
    bool ok = tryParseYamlFile(path, cfg, err);
    std::remove(path.c_str());
    assert(!ok);
    assert(err.find(":10:") != std::string::npos);   // 条目在第 10 行
    printf("  [PASS] WLCFG-003: 条目缺 exe 整体失败并给行号 (%s)\n", err.c_str());
}

// ====== WLCFG-004: parent_chain 类型错 → 整体失败 + 行号 ======
void test_config_parent_chain_bad_type() {
    std::string yaml = R"(rules:
  - id: "WL-001"
    name: "白名单规则"
    monitor:
      path: "/tmp/wl_f"
      events:
        - "write"
      action: "alert"
    whitelist:
      - exe: "/usr/bin/tee"
        parent_chain: "/usr/bin/bash"
)";
    std::string path = write_temp(yaml);
    Config cfg;
    std::string err;
    bool ok = tryParseYamlFile(path, cfg, err);
    std::remove(path.c_str());
    assert(!ok);
    assert(err.find(":11:") != std::string::npos);   // parent_chain 在第 11 行
    printf("  [PASS] WLCFG-004: parent_chain 类型错整体失败并给行号 (%s)\n", err.c_str());
}

// ====== WLCFG-005: 规则其它字段类型错同样整体失败（对齐热加载保留旧配置语义）======
void test_config_other_field_bad_type() {
    std::string yaml = R"(rules:
  - id: "WL-001"
    name: "白名单规则"
    monitor:
      path: "/tmp/wl_f"
      events:
        - "write"
      action: "alert"
    severity:
      - "high"
)";
    std::string path = write_temp(yaml);
    Config cfg;
    std::string err;
    bool ok = tryParseYamlFile(path, cfg, err);
    std::remove(path.c_str());
    assert(!ok);
    assert(!err.empty());   // yaml-cpp 转换异常的 mark 行号（9/10 行）不作强约束
    printf("  [PASS] WLCFG-005: 规则字段类型错整体失败并给行号 (%s)\n", err.c_str());
}

// ====== WLU-009: 事件上下文直通（进程树捕获的 exe/祖先）======
void test_event_context_match() {
    const std::string me = self_exe();
    const std::string parent = parent_exe();
    Rule rule = make_rule();

    auto table = WhitelistTable::Build(make_config({{me, {}}}));
    WhitelistMatcher m;
    // known_exe 命中（直通不查 /proc，等价判定）
    assert(m.Match(*table, rule, getpid(), 12345ULL, me, {}, nullptr) == true);
    assert(m.CacheSize() == 1);
    // start_time=0：本次不缓存
    assert(m.Match(*table, rule, getpid(), 0, me, {}, nullptr) == true);
    assert(m.CacheSize() == 1);
    // known_exe 为空：fail-closed（同 readlink 失败）
    assert(m.Match(*table, rule, getpid(), 12346ULL, "", {}, nullptr) == false);

    // 祖先直通：parent_chain 维度
    auto table2 = WhitelistTable::Build(make_config({{me, {parent}}}));
    assert(m.Match(*table2, rule, getpid(), 12347ULL, me, {parent}, nullptr) == true);
    assert(m.Match(*table2, rule, getpid(), 12348ULL, me, {"/no/such"}, nullptr) == false);
    printf("  [PASS] WLU-009: 事件上下文直通 + known_exe 空 fail-closed\n");
}

int main() {
    test_exe_exact_match();
    test_parent_chain_any_ancestor();
    test_entry_and_semantics();
    test_entry_or_semantics();
    test_fail_closed();
    test_snapshot_replace();
    test_clear_cache();
    test_cache_dedup();
    test_config_parse_ok();
    test_config_whitelist_not_list();
    test_config_entry_missing_exe();
    test_config_parent_chain_bad_type();
    test_config_other_field_bad_type();
    test_event_context_match();
    printf("test_whitelist: all tests passed\n");
    return 0;
}
