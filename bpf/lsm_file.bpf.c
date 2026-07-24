#include "event.h"
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// 存储要监控的文件indoe（从用户态传入）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, unsigned long); // inode
    __type(value, u8);          // 1=monitor
} monitor_inodes SEC(".maps");

struct print_ctx {
    u32 count;
};

extern int bpf_path_d_path(struct path *path, char *buf, int buf_len) __ksym;

SEC("lsm/file_permission")
int BPF_PROG(file_permission, struct file *file, int mask) {

    char ignore_comm[] = "baseline-guard";
    char comm[16] = {};
    unsigned long ino;

    bpf_get_current_comm(comm, sizeof(comm));
    if (bpf_strncmp(comm, sizeof(comm), "baseline-guard") == 0) {
        return 0;
    }

    ino = BPF_CORE_READ(file, f_inode, i_ino);

    u8 *monitor = bpf_map_lookup_elem(&monitor_inodes, &ino);
    if (!monitor) {

        return 0;
    }

    // 匹配成功
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    __builtin_memcpy(e->comm, comm, sizeof(comm));
    e->ino = ino;
    e->mask = mask;

    // 路径可选
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    bpf_probe_read_str(e->path, sizeof(e->path), BPF_CORE_READ(dentry, d_name.name));

    bpf_ringbuf_submit(e, 0);
    return 0;
}