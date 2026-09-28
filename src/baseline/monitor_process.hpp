#pragma once

#include <cstddef>

#include <nlohmann/json.hpp>

// 前向声明：定义分别来自生成的 proc_watch.skel.h 与 libbpf
struct proc_watch_bpf;
struct ring_buffer;
struct proc_event;
class EventBus;
struct EventRecord;

// 打开/加载/attach 进程生命周期遥测 BPF 程序（sched_process_fork/exec/exit），
// 并为其 proc_events ring buffer 创建消费者。
// bus 为事件总线指针（作为 ring buffer 回调 ctx），事件归一化后入 hi 队列
// （category=process, priority=1）。失败返回 nullptr，错误已 spdlog 记录，
// 调用方应降级为无进程遥测（不阻断主流程）。
struct proc_watch_bpf *process_monitor_start(struct ring_buffer **rb_out,
                                             class EventBus *bus);

// ring buffer 事件回调：proc_event 归一化为 EventRecord 入事件总线 hi 队列
int handle_process_event(void *ctx, void *data, size_t data_sz);

// 消费线程调用：proc_event(exec) 渲染为落库 JSON 负载（不含祖先链，
// 祖先链由 Enricher 追加）。exe 用 /proc 解析后的真实路径。
void render_process_exec_event(const struct proc_event& evt, struct EventRecord& rec,
                               nlohmann::json& out);

// 停止并释放进程遥测资源（rb 可为 nullptr）
void process_monitor_stop(struct proc_watch_bpf *skel, struct ring_buffer *rb);
