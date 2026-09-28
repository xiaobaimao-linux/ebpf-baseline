#pragma once

#include <cstdint>
#include <cstring>
#include <time.h>

// CLOCK_MONOTONIC 纳秒：入队时间戳（enqueue_ts_ns）基准，与内核
// bpf_ktime_get_ns() 同时钟域，排队/端到端延迟均以此计算。
inline unsigned long long now_monotonic_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<unsigned long long>(ts.tv_sec) * 1000000000ULL +
           static_cast<unsigned long long>(ts.tv_nsec);
}

// ── 事件类别（路由依据）────────────────────────────────────────────
// file    : 文件事件（lsm_file），路由回原文件处理函数，行为零变化
// process : 进程事件（proc_watch fork/exec/exit），先更新进程树
// priv    : 权限事件（priv_watch setuid/setgid/capset/ptrace/module_load）
// ns      : 命名空间事件（priv_watch mount/unshare/setns）
// network : 网络连接事件（net_watch connect/accept/bind）
// dns     : DNS 查询事件（net_watch sendto/sendmsg/sendmmsg）
#define CAT_FILE    0
#define CAT_PROCESS 1
#define CAT_PRIV    2
#define CAT_NS      3
#define CAT_NETWORK 4
#define CAT_DNS     5

// ── 优先级（队列路由 + 落库 severity 推导依据）────────────────────
// 0=file 1=priv/ns/process 2=network 3=dns
// priority<=1 进 hi 队列，否则进 lo 队列
#define PRIO_FILE    0
#define PRIO_CTRL    1   // priv / ns / process
#define PRIO_NETWORK 2
#define PRIO_DNS     3

// category -> priority（生产者填 EventRecord.priority 时参照）
inline unsigned char category_priority(unsigned char category) {
    switch (category) {
    case CAT_FILE:    return PRIO_FILE;
    case CAT_NETWORK: return PRIO_NETWORK;
    case CAT_DNS:     return PRIO_DNS;
    default:          return PRIO_CTRL;   // process / priv / ns
    }
}

// ── 定长 POD 事件记录 ─────────────────────────────────────────────
// 队列槽即此结构，禁止在 rb 回调内 malloc / 阻塞 / /proc IO。
// payload_json 在【路由前】承载各 BPF 原始事件结构（struct event /
// net_event / priv_event / proc_event）的字节拷贝，供消费线程还原；
// 落库前会被渲染后的 JSON（含 process.ancestors 富化）覆盖。
struct EventRecord {
    unsigned long long ts_ns;          // 事件时间（内核 bpf_ktime_get_ns，CLOCK_MONOTONIC 域）
    unsigned long long enqueue_ts_ns;  // 入队时间（用户态 CLOCK_MONOTONIC，排队延迟基准）
    unsigned int       pid;
    unsigned int       ppid;
    unsigned int       uid;
    unsigned int       gid;
    unsigned char      category;       // CAT_*
    unsigned char      action;         // 类别内子类型（EVENT_*/NET_EVENT_*/PRIV_KIND_*/PROC_KIND_*）
    unsigned char      priority;       // PRIO_*
    unsigned char      pad;
    char               comm[16];       // 不保证 NUL 结尾，消费侧以长度为界
    char               exe[256];       // 尽力填充，不保证 NUL 结尾
    char               container_id[13]; // 12 位短 ID + NUL；无容器为空串
    char               payload_json[2048]; // 路由前=原始事件字节；落库前=渲染 JSON（含转义）
};

// 字符串字段以定长数组承载时的安全拷贝：保证 NUL 结尾
inline void record_set_str(char *dst, size_t dst_size, const char *src, size_t src_len) {
    if (dst_size == 0)
        return;
    size_t n = src_len < dst_size - 1 ? src_len : dst_size - 1;
    if (n > 0)
        std::memcpy(dst, src, n);
    dst[n] = '\0';
}
