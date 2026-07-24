#ifndef EVENT_H
#define EVENT_H

// 数值定义，无枚举
#define ACTION_LOG 0
#define ACTION_ALERT 1
#define ACTION_THROTTLE 2
#define ACTION_BLOCK 3
#define ACTION_KILL 4

struct event {
    unsigned int pid;
    char comm[16];
    char path[256];
    unsigned long ino; // inode 编号
    int mask;
    unsigned char action; // 0-4
};

#endif