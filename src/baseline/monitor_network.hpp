#pragma once

#include <cstddef>

#include <nlohmann/json.hpp>

// 前向声明：定义分别来自生成的 net_watch.skel.h 与 libbpf
struct net_watch_bpf;
struct ring_buffer;
struct net_event;
class EventBus;
struct EventRecord;

// 打开/加载/attach 网络遥测 BPF 程序（connect/accept/bind + DNS sendto/sendmsg），
// 并为其 net_events ring buffer 创建消费者。
// enable_conn=false 时不加载 connect/accept/bind 程序（dns-only 模式）；
// enable_dns=false 时不加载 sendto/sendmsg 程序（纯连接遥测模式）。
// bus 为事件总线指针（作为 ring buffer 回调 ctx），事件归一化后入队。
// 成功返回 skeleton 指针且 *rb_out 非空；失败返回 nullptr，错误已 spdlog 记录，
// 调用方应降级为仅文件监控（遥测开启不阻断主流程）。
struct net_watch_bpf *network_monitor_start(struct ring_buffer **rb_out,
                                            bool enable_conn, bool enable_dns,
                                            class EventBus *bus);

// ring buffer 事件回调：net_event 归一化为 EventRecord 入事件总线（非阻塞，禁 /proc IO）
int handle_network_event(void *ctx, void *data, size_t data_sz);

// 消费线程调用：net_event 渲染为 JSON（含 exe/container /proc IO），
// 日志输出与迁移前逐字节一致；同时回填 rec.exe / rec.container_id 供落库。
// 渲染逻辑从原 rb 回调原样迁移（行为零变化）。
void render_network_event(const struct net_event& evt, struct EventRecord& rec,
                          nlohmann::json& out);

// 停止并释放网络遥测资源（rb 可为 nullptr）
void network_monitor_stop(struct net_watch_bpf *skel, struct ring_buffer *rb);
