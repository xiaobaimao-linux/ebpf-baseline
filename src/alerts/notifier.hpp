#pragma once
#include <string>
#include "alert_event.hpp"

// 外发渠道抽象（W5 D4）：webhook 为首个实现，邮件/钉钉/企业微信后续版本加实现。
// Send 由 NotifyDispatcher 的工作线程同步调用（含 HTTP 超时），实现方只管发一次，
// 重试与失败计数由 dispatcher 统一负责。
class INotifier {
public:
    virtual ~INotifier() = default;
    // 发送一条告警；返回是否成功（不成功由 dispatcher 重试）
    virtual bool Send(const AlertEvent& alert) = 0;
    virtual std::string Name() const = 0;
};
