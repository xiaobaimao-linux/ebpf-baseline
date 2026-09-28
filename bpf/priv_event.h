#ifndef PRIV_EVENT_H
#define PRIV_EVENT_H

// 数值定义，无枚举（风格同 event.h / net_event.h）
#define PRIV_KIND_SETUID       1
#define PRIV_KIND_SETGID       2
#define PRIV_KIND_CAPSET       3
#define PRIV_KIND_PTRACE       4
#define PRIV_KIND_MODULE_LOAD  5
#define PRIV_KIND_MOUNT        6
#define PRIV_KIND_UNSHARE      7
#define PRIV_KIND_SETNS        8

// 权限类事件：setuid/setgid 系 / capset / ptrace / 内核模块加载
// 命名空间事件：mount / unshare / setns（复用同一 ring buffer 与开关）
// 事件头字段风格与 net_event 对齐；负载按 priv_kind 取联合体中对应成员
struct priv_event {
    unsigned long long ts_ns;
    unsigned int pid;
    unsigned int ppid;
    unsigned int uid;
    unsigned int gid;
    char comm[16];
    unsigned long long cgroup_id;
    unsigned char priv_kind;   // 1=setuid 2=setgid 3=capset 4=ptrace 5=module_load
                               // 6=mount 7=unshare 8=setns
    unsigned char pad[7];
    union {
        unsigned int target_id;     // setuid/setgid：目标 uid/gid
        unsigned int effective_lo;  // capset：effective 掩码低 32 位；0xFFFFFFFF=读取失败（未知）
        struct {
            unsigned long long request;    // ptrace request 原始数值（PTRACE_ATTACH=16 等）
            unsigned int target_pid;       // 被跟踪进程 pid
        } ptrace;
        char name[64];              // module_load：模块名
        struct {
            char source[256];       // mount：源设备（probe_read 失败填空串）
            char target[256];       // mount：挂载点
            char fstype[32];        // mount：文件系统类型
            unsigned long long flags;
        } mount;
        struct {
            unsigned long long flags;   // unshare：CLONE_NEW* 掩码
        } unshare;
        struct {
            int fd;                 // setns：第一个参数
            unsigned int nstype;    // setns：第二个参数（CLONE_NEW*，0=任意）
        } setns;
    } u;
};

#endif
