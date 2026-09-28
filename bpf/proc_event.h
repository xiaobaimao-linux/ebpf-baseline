#ifndef PROC_EVENT_H
#define PROC_EVENT_H

// 数值定义，无枚举（风格同 event.h / net_event.h / priv_event.h）
#define PROC_KIND_FORK  1
#define PROC_KIND_EXEC  2
#define PROC_KIND_EXIT  3

// 进程生命周期事件：fork / exec / exit（tracepoint sched_process_*）
// 事件头字段风格与 net_event / priv_event 对齐。
// exe 为尽力填充：exec 事件填 tracepoint filename（未解析相对路径），
// fork/exit 填空串；消费线程会再读 /proc/<pid>/exe 解析出真实路径。
// start_time 为 task_struct.start_time（纳秒，CLOCK_MONOTONIC 域）：
// exec/exit 取当前任务可靠填充；fork 侧子任务 start_time 无法在内核侧
// 便捷获得，填 0，由消费线程读 /proc/<pid>/stat 补齐（尽力）。
struct proc_event {
    unsigned long long ts_ns;
    unsigned int pid;            // fork=子进程  exec/exit=当前进程
    unsigned int ppid;           // fork=父进程  exec/exit=父进程
    unsigned int uid;
    unsigned int gid;
    unsigned long long start_time; // 进程启动时间（ns），fork 事件为 0（待 /proc 补）
    unsigned char kind;          // 1=fork 2=exec 3=exit
    unsigned char pad[7];
    char comm[16];               // 不保证 NUL 结尾
    char exe[256];               // exec 尽力（tracepoint filename），其余为空
};

#endif
