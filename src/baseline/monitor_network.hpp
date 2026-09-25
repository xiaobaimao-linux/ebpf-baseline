#pragma once

#include <cstddef>

// 前向声明：定义分别来自生成的 net_watch.skel.h 与 libbpf
struct net_watch_bpf;
struct ring_buffer;

// 打开/加载/attach 网络遥测 BPF 程序（tcp_v4_connect / inet_csk_accept / sys_enter_bind），
// 并为其 net_events ring buffer 创建消费者。
// 成功返回 skeleton 指针且 *rb_out 非空；失败返回 nullptr，错误已 spdlog 记录，
// 调用方应降级为仅文件监控（telemetry.network 开启不阻断主流程）。
struct net_watch_bpf *network_monitor_start(struct ring_buffer **rb_out);

// ring buffer 事件回调：net_event 转 JSON 经 spdlog info 输出
int handle_network_event(void *ctx, void *data, size_t data_sz);

// 停止并释放网络遥测资源（rb 可为 nullptr）
void network_monitor_stop(struct net_watch_bpf *skel, struct ring_buffer *rb);
