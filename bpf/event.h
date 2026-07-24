#ifndef EVENT_H
#define EVENT_H

struct event {
    unsigned int pid;
    char comm[16];
    char path[256];
    unsigned long ino;  // inode 编号
    int mask;
};

#endif