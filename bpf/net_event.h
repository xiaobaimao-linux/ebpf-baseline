#ifndef NET_EVENT_H
#define NET_EVENT_H

// 数值定义，无枚举（风格同 event.h）
#define NET_EVENT_CONNECT 1
#define NET_EVENT_ACCEPT  2
#define NET_EVENT_BIND    3

#define NET_FAMILY_INET 2   // AF_INET；本期仅采集 IPv4，其余 family 不处理

#define NET_PROTO_TCP   6

// 网络连接事件：connect / accept / bind 共用
// 地址为网络字节序原始字节：IPv4 放前 4 字节，其余字节为 0
// 端口为主机序
struct net_event {
    unsigned long long ts_ns;
    unsigned int pid;
    unsigned int ppid;
    unsigned int uid;
    unsigned int gid;
    unsigned long long cgroup_id;
    unsigned char event_kind;   // 1=connect 2=accept 3=bind
    unsigned char family;       // AF_INET
    unsigned char protocol;     // IPPROTO_TCP=6；bind 事件无法从用户态地址推断，填 0
    unsigned char pad;
    unsigned short sport;       // 主机序
    unsigned short dport;       // 主机序
    unsigned char saddr[16];
    unsigned char daddr[16];
    char comm[16];
};

#endif
