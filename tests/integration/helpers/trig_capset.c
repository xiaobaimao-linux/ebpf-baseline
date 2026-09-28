// 权限遥测验收触发器（PRIV-002）：capget 读取当前线程能力集，
// 再 capset 从 effective 掩码中去掉 CAP_NET_RAW（bit 13）。
// 不依赖 libcap，直接走 syscall；capset 无论是否真正降权都会触发 sys_enter_capset。
// 用法: trig_capset
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

struct cap_hdr {
    unsigned int version;
    int pid;
};

struct cap_data {
    unsigned int effective;
    unsigned int permitted;
    unsigned int inheritable;
};

int main(void)
{
    /* _LINUX_CAPABILITY_VERSION_3 */
    struct cap_hdr hdr = { 0x20080522, 0 };
    struct cap_data data[2];

    memset(data, 0, sizeof(data));
    if (syscall(SYS_capget, &hdr, data) != 0) {
        perror("capget");
        return 1;
    }
    printf("capget ok: effective_lo=0x%08x\n", data[0].effective);

    data[0].effective &= ~(1u << 13);   /* CAP_NET_RAW */
    if (syscall(SYS_capset, &hdr, data) != 0) {
        perror("capset");
        return 1;
    }
    printf("capset ok: effective_lo=0x%08x\n", data[0].effective);
    return 0;
}
