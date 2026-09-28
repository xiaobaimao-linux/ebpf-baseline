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

// ====== CFG-001: 文件权限检查规则解析 ======
void test_file_permission_rule() {
    std::string yaml = R"(rules:
  - id: "SYS-PERM-001"
    name: "passwd权限检查"
    severity: "critical"
    check:
      type: "file_permission"
      path: "/etc/passwd"
      expected: "0644"
      on_failure: "report_only"
)";
    std::string path = write_temp(yaml);
    Config config = parseYamlFile(path);
    cleanup(path);

    assert(config.rules.size() == 1);
    assert(config.rules[0].id == "SYS-PERM-001");
    assert(config.rules[0].severity == SEVERITY_CRITICAL);
    assert(config.rules[0].check_types.size() == 1);
    assert(config.rules[0].check_types[0] == "file_permission");
    assert(config.rules[0].check_path == "/etc/passwd");
    assert(config.rules[0].check_expected == 0644);
    assert(config.rules[0].check_on_failure == "report_only");
    printf("  [PASS] CFG-001: 文件权限检查规则解析\n");
}

// ====== CFG-002: 文件哈希检查规则解析 ======
void test_file_hash_rule() {
    std::string yaml = R"(rules:
  - id: "SYS-HASH-001"
    name: "sshd完整性检查"
    severity: "high"
    check:
      type: "file_hash"
      path: "/usr/bin/sshd"
      expected: "0644"
      hash: "sha256:a1b2c3d4e5f6"
      on_failure: "report_only"
)";
    std::string path = write_temp(yaml);
    Config config = parseYamlFile(path);
    cleanup(path);

    assert(config.rules.size() == 1);
    assert(config.rules[0].has_check_hash == true);
    assert(config.rules[0].check_hash == "sha256:a1b2c3d4e5f6");
    assert(config.rules[0].check_expected == 0644);
    printf("  [PASS] CFG-002: 文件哈希检查规则解析\n");
}

// ====== CFG-003: 多类型组合规则解析 ======
void test_combo_rule() {
    std::string yaml = R"(rules:
  - id: "SYS-COMBO-001"
    name: "综合监控"
    severity: "medium"
    check:
      type:
        - "file_permission"
        - "file_hash"
      path: "/home/sf/combo.txt"
      expected: "0420"
      hash: "d9cd8155764c3543f10fad8a480d743137466f8d55213c8eaefcd12f06d43a80"
      on_failure: "report_only"
    monitor:
      path: "/home/sf/combo.txt"
      events:
        - "write"
      action: "block"
)";
    std::string path = write_temp(yaml);
    Config config = parseYamlFile(path);
    cleanup(path);

    assert(config.rules.size() == 1);
    assert(config.rules[0].check_types.size() == 2);
    assert(config.rules[0].check_types[0] == "file_permission");
    assert(config.rules[0].check_types[1] == "file_hash");
    assert(config.rules[0].check_expected == 0420);
    assert(config.rules[0].has_check_hash == true);
    assert(config.rules[0].has_monitor == true);
    assert(config.rules[0].monitor_path == "/home/sf/combo.txt");
    assert(config.rules[0].monitor_action == Action::BLOCK);
    assert(config.rules[0].monitor_write == true);
    printf("  [PASS] CFG-003: 多类型组合规则解析\n");
}

// ====== CFG-004: 纯监控规则解析 ======
void test_monitor_only_rule() {
    std::string yaml = R"(rules:
  - id: "SYS-MONITOR-001"
    name: "敏感文件监控"
    severity: "critical"
    monitor:
      path: "/home/sf/secret.txt"
      events:
        - "read"
        - "write"
      action: "alert"
)";
    std::string path = write_temp(yaml);
    Config config = parseYamlFile(path);
    cleanup(path);

    assert(config.rules.size() == 1);
    assert(config.rules[0].has_check == false);
    assert(config.rules[0].has_monitor == true);
    assert(config.rules[0].monitor_path == "/home/sf/secret.txt");
    assert(config.rules[0].monitor_read == true);
    assert(config.rules[0].monitor_write == true);
    assert(config.rules[0].monitor_action == Action::ALERT);
    printf("  [PASS] CFG-004: 纯监控规则解析\n");
}

// ====== CFG-005: 内核参数检查规则解析 ======
void test_kernel_param_rule() {
    std::string yaml = R"(rules:
  - id: "SYS-KERNEL-001"
    name: "KASLR检查"
    severity: "high"
    check:
      type: "kernel_param"
      param: "kernel.randomize_va_space"
      operator: "="
      expected: 2
)";
    std::string path = write_temp(yaml);
    Config config = parseYamlFile(path);
    cleanup(path);

    assert(config.rules.size() == 1);
    assert(config.rules[0].check_types.size() == 1);
    assert(config.rules[0].check_types[0] == "kernel_param");
    assert(config.rules[0].check_param == "kernel.randomize_va_space");
    assert(config.rules[0].check_operator == "=");
    assert(config.rules[0].check_expected_value == 2);
    // 内核参数检查不应解析 expected 为文件权限模式
    assert(config.rules[0].check_expected == 0);
    printf("  [PASS] CFG-005: 内核参数检查规则解析\n");
}

// ====== CFG-006: 内核参数不等于运算符 ======
void test_kernel_param_not_equal() {
    std::string yaml = R"(rules:
  - id: "SYS-KERNEL-002"
    name: "禁用IP源路由"
    severity: "medium"
    check:
      type: "kernel_param"
      param: "net.ipv4.conf.all.accept_source_route"
      operator: "!="
      expected: 1
)";
    std::string path = write_temp(yaml);
    Config config = parseYamlFile(path);
    cleanup(path);

    assert(config.rules.size() == 1);
    assert(config.rules[0].check_operator == "!=");
    assert(config.rules[0].check_expected_value == 1);
    printf("  [PASS] CFG-006: 内核参数不等于运算符\n");
}

// ====== CFG-007: YAML缺少rules根节点 ======
void test_yaml_no_rules() {
    std::string yaml = "{}";
    std::string path = write_temp(yaml);
    Config config = parseYamlFile(path);
    cleanup(path);
    assert(config.rules.empty());
    printf("  [PASS] CFG-007: YAML缺少rules根节点\n");
}

// ====== CFG-008: 空YAML文件 ======
void test_empty_file() {
    std::string path = write_temp("");
    Config config = parseYamlFile(path);
    cleanup(path);
    assert(config.rules.empty());
    printf("  [PASS] CFG-008: 空YAML文件\n");
}

// ====== CFG-009: 缺少check和monitor的规则被跳过 ======
void test_skip_invalid_rule() {
    std::string yaml = R"(rules:
  - id: "INVALID-001"
    name: "无效规则"
    severity: "low"
)";
    std::string path = write_temp(yaml);
    Config config = parseYamlFile(path);
    cleanup(path);

    assert(config.rules.empty());
    printf("  [PASS] CFG-009: 缺少check和monitor的规则被跳过\n");
}

// ====== CFG-010: 告警配置解析 ======
void test_alert_config() {
    std::string yaml = R"(rules:
  - id: "TEST-001"
    name: "测试规则"
    severity: "low"
    check:
      type: "file_permission"
      path: "/tmp/test"
      expected: "0644"
alert:
  dingtalk:
    webhook: "https://oapi.dingtalk.com/robot/send?access_token=abc123"
    secret: "SECsecret123"
  throttle: 600
)";
    std::string path = write_temp(yaml);
    Config config = parseYamlFile(path);
    cleanup(path);

    assert(config.rules.size() == 1);
    assert(config.alert.dingtalk_webhook == "https://oapi.dingtalk.com/robot/send?access_token=abc123");
    assert(config.alert.dingtalk_secret == "SECsecret123");
    assert(config.alert.throttle_seconds == 600);
    printf("  [PASS] CFG-010: 告警配置解析\n");
}

// ====== CFG-011: 多规则混合解析 ======
void test_multiple_rules() {
    std::string yaml = R"(rules:
  - id: "SYS-PERM-001"
    name: "权限检查"
    severity: "critical"
    check:
      type: "file_permission"
      path: "/etc/passwd"
      expected: "0644"
  - id: "SYS-KERNEL-001"
    name: "内核检查"
    severity: "high"
    check:
      type: "kernel_param"
      param: "kernel.randomize_va_space"
      operator: "="
      expected: 2
  - id: "SYS-MONITOR-001"
    name: "监控规则"
    severity: "medium"
    monitor:
      path: "/tmp/secret"
      events:
        - "write"
      action: "block"
)";
    std::string path = write_temp(yaml);
    Config config = parseYamlFile(path);
    cleanup(path);

    assert(config.rules.size() == 3);
    // 规则1: 文件权限
    assert(config.rules[0].check_types[0] == "file_permission");
    assert(config.rules[0].check_expected == 0644);
    // 规则2: 内核参数
    assert(config.rules[1].check_types[0] == "kernel_param");
    assert(config.rules[1].check_expected_value == 2);
    // 规则3: 监控
    assert(config.rules[2].has_monitor == true);
    assert(config.rules[2].monitor_action == Action::BLOCK);
    printf("  [PASS] CFG-011: 多规则混合解析\n");
}

// ====== CFG-012: 无id和name的匿名规则 ======
void test_anonymous_rule() {
    std::string yaml = R"(rules:
  - check:
      type: "file_permission"
      path: "/etc/passwd"
      expected: "0644"
)";
    std::string path = write_temp(yaml);
    Config config = parseYamlFile(path);
    cleanup(path);

    assert(config.rules.size() == 1);
    assert(config.rules[0].name == "(unnamed)");
    printf("  [PASS] CFG-012: 无id和name的匿名规则\n");
}

// ====== CFG-013: 字符串severity解析 ======
void test_severity_parsing() {
    std::string yaml = R"(rules:
  - id: "TEST-001"
    name: "低危规则"
    severity: "low"
    check:
      type: "file_permission"
      path: "/tmp/a"
      expected: "0644"
  - id: "TEST-002"
    name: "高危规则"
    severity: "critical"
    check:
      type: "file_permission"
      path: "/tmp/b"
      expected: "0644"
)";
    std::string path = write_temp(yaml);
    Config config = parseYamlFile(path);
    cleanup(path);

    assert(config.rules[0].severity == SEVERITY_LOW);
    assert(config.rules[1].severity == SEVERITY_CRITICAL);
    printf("  [PASS] CFG-013: 字符串severity解析\n");
}

// ====== CFG-014: expected数值类型(权限用字符串八进制) ======
void test_expected_string_vs_int() {
    // 文件权限: expected 是带引号的字符串八进制
    std::string yaml1 = R"(rules:
  - id: "TEST-001"
    name: "权限字符串"
    check:
      type: "file_permission"
      path: "/tmp/test"
      expected: "0755"
)";
    std::string path1 = write_temp(yaml1);
    Config config1 = parseYamlFile(path1);
    cleanup(path1);
    assert(config1.rules[0].check_expected == 0755);

    // 内核参数: expected 是数值
    std::string yaml2 = R"(rules:
  - id: "TEST-002"
    name: "内核数值"
    check:
      type: "kernel_param"
      param: "vm.swappiness"
      operator: "<="
      expected: 60
)";
    std::string path2 = write_temp(yaml2);
    Config config2 = parseYamlFile(path2);
    cleanup(path2);
    assert(config2.rules[0].check_expected_value == 60);

    printf("  [PASS] CFG-014: expected数值类型区分\n");
}

int main() {
    printf("=== test_config ===\n");
    test_file_permission_rule();
    test_file_hash_rule();
    test_combo_rule();
    test_monitor_only_rule();
    test_kernel_param_rule();
    test_kernel_param_not_equal();
    test_yaml_no_rules();
    test_empty_file();
    test_skip_invalid_rule();
    test_alert_config();
    test_multiple_rules();
    test_anonymous_rule();
    test_severity_parsing();
    test_expected_string_vs_int();
    printf("=== all config tests passed ===\n");
    return 0;
}
