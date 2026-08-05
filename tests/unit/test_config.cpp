// 单元测试：配置解析
// 编译: g++ -std=c++17 -I../../include -I../../src -o test_config test_config.cpp ../../src/config.cpp $(pkg-config --libs yaml-cpp) -lfmt

#include <cassert>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <unistd.h>
#include <vector>
#include "config.hpp"

// 创建临时文件并返回路径
std::string write_temp(const std::string &content, const std::string &suffix = ".yaml") {
    std::string path = "/tmp/test_" + std::to_string(getpid()) + suffix;
    std::ofstream f(path);
    f << content;
    return path;
}

void cleanup(const std::string &path) { std::remove(path.c_str()); }

// ====== CFG-005: YAML正常解析 ======
void test_yaml_normal() {
    std::string yaml = R"(rules:
  - id: "SYS-COMBO-001"
    name: "综合监控 - 用户配置文件 /home/sf/combo.txt.12345678901234567890"
    severity: "medium"
    check:
      type:
        - "file_permission"
        - "file_hash"
      path: "/home/sf/combo.txt.12345678901234567890"
      mode: "0420"
      hash: "d9cd8155764c3543f10fad8a480d743137466f8d55213c8eaefcd12f06d43a80"
      on_failure: "report_only"
    monitor:
      path: "/home/sf/combo.txt.12345678901234567890"
      events:
        - "write"
      action: "block"
  - id: SYS-002
    name: "测试规则2"
    check:
      type: file_hash
      path: /etc/shadow
      hash: "sha256:deadbeef"
)";
    std::string path = write_temp(yaml, ".yaml");
    auto rules = parseYamlFile(path);
    cleanup(path);

    assert(rules.size() == 2);
    assert(rules[0].name == "SYS-COMBO-001: 综合监控 - 用户配置文件 /home/sf/combo.txt.12345678901234567890");
    assert(rules[0].has_check == true);
    assert(rules[0].check_path == "/home/sf/combo.txt.12345678901234567890");
    assert(rules[0].check_mode == 0420);
    assert(rules[0].has_check_hash == true);
    assert(rules[0].check_on_failure == "report_only");
    assert(rules[0].monitor_path == "/home/sf/combo.txt.12345678901234567890");
    assert(rules[0].monitor_action == Action::BLOCK);
    assert(rules[1].has_check_hash == true);
    printf("  [PASS] CFG-005: YAML正常解析\n");
}

// ====== CFG-006: YAML缺少rules根节点 ======
void test_yaml_no_rules() {
    std::string yaml = "{}";
    std::string path = write_temp(yaml, ".yaml");
    auto rules = parseYamlFile(path);
    cleanup(path);
    assert(rules.empty());
    printf("  [PASS] CFG-006: YAML缺少rules根节点\n");
}

// ====== CFG-008: YAML支持纯 monitor 和组合规则 ======
void test_yaml_monitor_and_combo() {
    std::string yaml = R"(rules:
- id: SYS-001
  name: "纯 monitor 规则"
  severity: critical
  monitor:
    path: /home/sf/abc.txt
    events:
      - read
      - write
    action: block
- id: SYS-002
  name: "组合规则"
  severity: high
  check:
    type: file_permission
    path: /etc/passwd
    mode: "0644"
    on_failure: report_only
  monitor:
    path: /home/sf/combo.txt
    events:
      - write
    action: alert
)";
    std::string path = write_temp(yaml, ".yaml");
    auto rules = parseYamlFile(path);
    cleanup(path);

    assert(rules.size() == 2);
    assert(rules[0].has_monitor == true);
    assert(rules[0].monitor_path == "/home/sf/abc.txt");
    assert(rules[0].monitor_action == Action::BLOCK);
    assert(rules[1].has_check == true);
    assert(rules[1].has_monitor == true);
    assert(rules[1].check_path == "/etc/passwd");
    assert(rules[1].monitor_path == "/home/sf/combo.txt");
    printf("  [PASS] CFG-008: YAML支持纯 monitor 和组合规则\n");
}

// ====== CFG-009: 空 YAML 文件 ======
void test_empty_file() {
    std::string path = write_temp("");
    auto rules = parseYamlFile(path);
    cleanup(path);
    assert(rules.empty());
    printf("  [PASS] CFG-009: 空YAML文件\n");
}

int main() {
    printf("=== test_config ===\n");
    test_yaml_normal();
    test_yaml_no_rules();
    test_yaml_monitor_and_combo();
    test_empty_file();
    printf("=== all config tests passed ===\n");
    return 0;
}
