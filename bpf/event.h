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

// 严重等级（数值越高越严重，与用户态 SeverityLevel 枚举对应）
#define SEVERITY_LOW      0
#define SEVERITY_MEDIUM   1
#define SEVERITY_HIGH     2
#define SEVERITY_CRITICAL 3
#define SEVERITY_UNKNOWN  ((unsigned char)-1)

// 水位等级（由用户态写入 watermark_level map，eBPF 读取后做背压决策）
#define WATERMARK_NORMAL   0   // 0%  ~ 70%
#define WATERMARK_WARNING  1   // 70% ~ 85%
#define WATERMARK_HIGH     2   // 85% ~ 95%
#define WATERMARK_OVERLOAD 3   // 95% ~ 100%

// 监控规则：由用户态写入 eBPF monitor_actions map，作为 value 存储
// eBPF hook 通过 inode 查到该结构后，据此决定是否拦截/告警
struct monitor_rule {
    unsigned char action;       // 触发动作：ACTION_LOG(0) / ACTION_ALERT(1) / ACTION_BLOCK(3) 等
    unsigned char events_mask;  // 事件掩码（位运算）：EVENT_READ(1) | EVENT_WRITE(2) 等
    unsigned char severity;     // 严重等级：SEVERITY_LOW(0) ~ SEVERITY_CRITICAL(3)
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