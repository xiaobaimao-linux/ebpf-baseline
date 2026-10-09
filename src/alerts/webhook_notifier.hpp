#pragma once
#include <string>
#include "notifier.hpp"

// Webhook 渠道（W5 D4）：HTTP POST JSON（告警全字段 + host），libcurl 实现。
// 单次发送总超时 ≤3s（连接 ≤1.5s），由 NotifyDispatcher 工作线程调用，可重试。
class WebhookNotifier : public INotifier {
public:
    explicit WebhookNotifier(std::string url);

    bool Send(const AlertEvent& alert) override;
    std::string Name() const override { return "webhook"; }

private:
    std::string url_;
    std::string host_;   // 主机名（构造时取一次）

    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);
};
