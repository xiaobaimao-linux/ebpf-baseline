#pragma once

#include <nlohmann/json.hpp>

#include "event_record.hpp"
#include "process_tree.hpp"

// ── 祖先链富化器 ──────────────────────────────────────────────────
// 消费线程内对每条落库事件沿进程树拼祖先链，自近及远 ≤8 层
// [{pid,comm,exe}] 写入 payload.process.ancestors；环路检测；
// 链断（节点已清除）有几层算几层，不报错。
class Enricher {
public:
    explicit Enricher(const ProcessTree& tree) : tree_(tree) {}

    // 沿进程树自事件进程向父链上溯，把祖先链写入 j["process"]["ancestors"]
    void enrich(const EventRecord& rec, nlohmann::json& j) const;

    // 拼祖先链 [{pid,comm,exe}]（自近及远 ≤8 层）；供文件事件告警富化复用
    nlohmann::json ancestors_of(unsigned int pid, unsigned int fallback_ppid) const;

private:
    const ProcessTree& tree_;
};
