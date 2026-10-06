#pragma once

#include <string>
#include <vector>

#include "rule.hpp"

// ── 规则目录加载器（docs/rule-dsl-v1.md §2/§6）──────────────────────
namespace detect {

// 严格模式：加载 dir 下全部 *.yaml/*.yml（文件名排序，稳定顺序），
// 任一文件/任一规则出错整体失败。成功返回 true 并填充 out；
// 失败返回 false，err 格式 "文件名:行号: 原因"（行号取 yaml 节点行，
// condition 语法错误取 condition 节点行）。
// 校验：必填八字段（rule/desc/condition/output/priority/attack/
// fpr_note/response）、priority 枚举、字段路径对照 schema 字段表
// （含 output 模板插值字段）、规则名全局查重。
bool LoadRulesDir(const std::string &dir, std::vector<Rule> &out, std::string &err);

} // namespace detect
