#pragma once

#include <cstddef>

#include <nlohmann/json.hpp>

// 前向声明：定义分别来自生成的 priv_watch.skel.h 与 libbpf
struct priv_watch_bpf;
struct ring_buffer;
struct priv_event;
class EventBus;
struct EventRecord;

// 打开/加载/attach 权限遥测 BPF 程序（setuid/setgid 系 / capset / ptrace / module_load），
// 并为其 priv_events ring buffer 创建消费者。
// bus 为事件总线指针（作为 ring buffer 回调 ctx），事件归一化后入队。
// 成功返回 skeleton 指针且 *rb_out 非空；失败返回 nullptr，错误已 spdlog 记录，
// 调用方应降级为无权限遥测（telemetry.privilege 开启不阻断主流程）。
struct priv_watch_bpf *privilege_monitor_start(struct ring_buffer **rb_out,
                                               class EventBus *bus);

// ring buffer 事件回调：priv_event 归一化为 EventRecord 入事件总线（非阻塞，禁 /proc IO）
int handle_privilege_event(void *ctx, void *data, size_t data_sz);

// 消费线程调用：priv_event 渲染为 JSON（含 exe/container /proc IO），
// 日志输出与迁移前逐字节一致；同时回填 rec.exe / rec.container_id 供落库。
// 渲染逻辑从原 rb 回调原样迁移（行为零变化）。
void render_privilege_event(const struct priv_event& evt, struct EventRecord& rec,
                            nlohmann::json& out);

// 停止并释放权限遥测资源（rb 可为 nullptr）
void privilege_monitor_stop(struct priv_watch_bpf *skel, struct ring_buffer *rb);
