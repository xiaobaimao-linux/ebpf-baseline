#ifndef EVENT_H
#define EVENT_H

// 数值定义，无枚举
#define ACTION_LOG 0
#define ACTION_ALERT 1
#define ACTION_THROTTLE 2
#define ACTION_BLOCK 3
#define ACTION_KILL 4

#define EVENT_READ 1
#define EVENT_WRITE 2
#define EVENT_CHMOD 3
#define EVENT_CHOWN 4
#define EVENT_UNLINK 5
#define EVENT_UNLINK 5

// 监控规则：由用户态写入 eBPF monitor_actions map，作为 value 存储
// eBPF hook 通过 inode 查到该结构后，据此决定是否拦截/告警
struct monitor_rule {
    unsigned char action;       // 触发动作：ACTION_LOG(0) / ACTION_ALERT(1) / ACTION_BLOCK(3) 等
    unsigned char events_mask;  // 事件掩码（位运算）：EVENT_READ(1) | EVENT_WRITE(2) 等
};

struct event {
    unsigned int pid;
    char comm[16];
    char path[256];
    unsigned long ino; // inode 编号
    int mask;
    unsigned char action; // 0-4
    unsigned char event_type; // 0=read/write, 3=chmod, 4=chown
    unsigned int new_mode;    // chmod: new mode
    unsigned int new_uid;     // chown: new uid
    unsigned int new_gid;     // chown: new gid
};

#endif