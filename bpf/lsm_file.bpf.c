#include "event.h"
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1

static long (*bpf_strlen)(const char *str) = (void *)115;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// 存储要监控的文件 inode（从用户态传入）和对应的 action / events_mask
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, unsigned long); // inode
    __type(value, struct monitor_rule);
} monitor_actions SEC(".maps");

struct print_ctx {
    u32 count;
};

extern int bpf_path_d_path(struct path *path, char *buf, int buf_len) __ksym;

SEC("lsm/file_permission")
int BPF_PROG(file_permission, struct file *file, int mask) {

    char comm[16] = {};
    unsigned long ino;
    char fname[256] = {};

    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry)
        return 0;

    unsigned int name_len = BPF_CORE_READ(dentry, d_name.len);

    const unsigned char *name_ptr = BPF_CORE_READ(file, f_path.dentry, d_name.name);
    if (!name_ptr)
        return 0;

    // 2) 拷到栈缓冲区
    bpf_probe_read_kernel_str(fname, sizeof(fname), name_ptr);

    if (name_len == 28) {
        bpf_printk("file name: %s\n", fname);
    }

    ino = BPF_CORE_READ(file, f_inode, i_ino);

    // 查规则（存在即监控，不存在则忽略）
    struct monitor_rule *rule = bpf_map_lookup_elem(&monitor_actions, &ino);
    if (!rule) {
        return 0;
    }
    bpf_printk("begin  check action and events for %s\n", fname);

    // 只在规则声明的事件位上发事件
    if (!((rule->events_mask & EVENT_READ) && (mask & EVENT_READ)) &&
        !((rule->events_mask & EVENT_WRITE) && (mask & EVENT_WRITE))) {
        bpf_printk("NO READ\WRITE, PASS: %s\n", fname);
        return 0;
    }

    // 匹配成功
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    __builtin_memcpy(e->comm, comm, sizeof(comm));
    e->ino = ino;
    e->action = rule->action;
    e->mask = mask;

    dentry = BPF_CORE_READ(file, f_path.dentry);
    bpf_probe_read_str(e->path, sizeof(e->path), BPF_CORE_READ(dentry, d_name.name));

    bpf_ringbuf_submit(e, 0);

    // 使用
    if (rule->action == ACTION_BLOCK) {
        bpf_printk("BLOCK FILE %s  READ OR WRITE, mask: %d\n", fname, mask);
        return -EPERM;
    }

    return 0;
}

SEC("lsm/path_chmod")
int BPF_PROG(file_chmod_hook, const struct path *path, umode_t mode) {
    char comm[16] = {};
    unsigned long ino;
    char fname[256] = {};

    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    if (!dentry)
        return 0;

    ino = BPF_CORE_READ(dentry, d_inode, i_ino);

    // 查规则（存在即监控）
    struct monitor_rule *rule = bpf_map_lookup_elem(&monitor_actions, &ino);
    if (!rule)
        return 0;

    // 发送 chmod 事件
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    __builtin_memcpy(e->comm, comm, sizeof(comm));
    e->ino = ino;
    e->action = rule->action;
    e->event_type = EVENT_CHMOD;
    e->new_mode = mode;
    e->new_uid = 0;
    e->new_gid = 0;
    e->mask = 0;

    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
    if (name_ptr)
        bpf_probe_read_str(e->path, sizeof(e->path), name_ptr);

    bpf_ringbuf_submit(e, 0);
    bpf_printk("CHMOD detected for inode %lu, new mode: %u\n", ino, mode);

    return 0;
}

SEC("lsm/path_chown")
int BPF_PROG(file_chown_hook, const struct path *path, unsigned int uid, unsigned int gid) {
    char comm[16] = {};
    unsigned long ino;

    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    if (!dentry)
        return 0;

    ino = BPF_CORE_READ(dentry, d_inode, i_ino);

    // 查规则（存在即监控）
    struct monitor_rule *rule = bpf_map_lookup_elem(&monitor_actions, &ino);
    if (!rule)
        return 0;

    // 发送 chown 事件
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    __builtin_memcpy(e->comm, comm, sizeof(comm));
    e->ino = ino;
    e->action = rule->action;
    e->event_type = EVENT_CHOWN;
    e->new_mode = 0;
    e->new_uid = uid;
    e->new_gid = gid;
    e->mask = 0;

    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
    if (name_ptr)
        bpf_probe_read_str(e->path, sizeof(e->path), name_ptr);

    bpf_ringbuf_submit(e, 0);
    bpf_printk("CHOWN detected for inode %lu, new uid: %u, gid: %u\n", ino, uid, gid);

    return 0;
}

SEC("lsm/path_unlink")
int BPF_PROG(file_unlink_hook, const struct path *path, struct dentry *dentry) {
    char comm[16] = {};
    unsigned long ino;

    if (!dentry)
        return 0;

    ino = BPF_CORE_READ(dentry, d_inode, i_ino);

    // 查规则（存在即监控）
    struct monitor_rule *rule = bpf_map_lookup_elem(&monitor_actions, &ino);
    if (!rule)
        return 0;

    // 发送 unlink 事件
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    __builtin_memcpy(e->comm, comm, sizeof(comm));
    e->ino = ino;
    e->action = rule->action;
    e->event_type = EVENT_UNLINK;
    e->new_mode = 0;
    e->new_uid = 0;
    e->new_gid = 0;
    e->mask = 0;

    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
    if (name_ptr)
        bpf_probe_read_str(e->path, sizeof(e->path), name_ptr);

    bpf_ringbuf_submit(e, 0);
    bpf_printk("UNLINK detected for inode %lu\n", ino);

    return 0;
}