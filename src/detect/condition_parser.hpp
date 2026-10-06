#pragma once

#include <memory>
#include <string>

#include "rule.hpp"

// ── 条件表达式递归下降解析器（docs/rule-dsl-v1.md §4 EBNF）───────────
namespace detect {

// 解析条件表达式为 AST。成功返回非空；失败返回 nullptr，err 为原因
// （不含文件名/行号，由加载方按 condition 节点行号补前缀）。
// 字段路径在此即对照 schema 字段表校验：形似字段（event_type 或
// process./container./file./network./dns./priv./ns. 前缀）但不在表内
// 报"未知字段"；event_type 比较的右操作数强制按字面值处理。
std::unique_ptr<CondNode> ParseCondition(const std::string &text, std::string &err);

} // namespace detect
