#include "enricher.hpp"

// 自近及远最多上溯的祖先层数
static constexpr int kMaxAncestors = 8;

void Enricher::enrich(const EventRecord& rec, nlohmann::json& j) const {
    nlohmann::json ancestors = nlohmann::json::array();

    // 起点：事件进程的父进程。优先用树中该进程节点的 ppid（更可靠），
    // 树中查不到（短寿进程已清除）则退回事件自带的 ppid。
    unsigned int parent = rec.ppid;
    if (const ProcNode* self = tree_.find(rec.pid))
        parent = self->ppid;

    // 环路检测：记录本链已访问的 pid（含事件进程自身）
    unsigned int visited[kMaxAncestors + 1];
    int nvisited = 0;
    visited[nvisited++] = rec.pid;

    for (int level = 0; level < kMaxAncestors && parent > 0; level++) {
        bool seen = false;
        for (int i = 0; i < nvisited; i++) {
            if (visited[i] == parent) {
                seen = true;
                break;
            }
        }
        if (seen)
            break;  // 环路

        const ProcNode* node = tree_.find(parent);
        if (!node)
            break;  // 链断（节点已清除）：有几层算几层，不报错

        nlohmann::json a;
        a["pid"] = node->pid;
        a["comm"] = node->comm_str();
        a["exe"] = node->exe_str();
        ancestors.push_back(a);

        if (nvisited <= kMaxAncestors)
            visited[nvisited++] = parent;
        parent = node->ppid;
    }

    // 确保 process 对象存在后写入祖先链
    if (!j.contains("process") || !j["process"].is_object())
        j["process"] = nlohmann::json::object();
    j["process"]["ancestors"] = ancestors;
}
