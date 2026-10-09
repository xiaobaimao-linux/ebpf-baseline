#pragma once
#include <string>

// 告警事件全字段（落库 alerts 表与外发 notify 共用同一份数据）
struct AlertEvent {
    std::string rule_id;
    std::string rule_name;
    std::string severity;
    std::string file_path;
    std::string expected;   // 预期值（如 0644）
    std::string actual;     // 实际值（如 0777）
    std::string process_name;
    int pid = 0;
    std::string user_name;  // 触发该告警的 Linux 用户名
    std::string uid;        // 触发该告警的 uid（字符串）
    std::string timestamp;
    std::string event_type;     // 事件类型: read / write / check_fail
    std::string action_taken;   // alert / block / report_only
    std::string exe;            // 触发进程可执行文件路径（进程树命中时非空）
    std::string container_id;   // 12 位容器短 ID（容器内触发时非空）
    std::string ancestors;      // 祖先链 JSON 数组串（可为空）
    std::string attack;         // ATT&CK 技术 ID 逗号分隔（W4 DSL 规则；FIM/基线告警为空串）
};
