/*
 * lsm_kprobe.bpf.c — kprobe 版 BPF 程序，支持 Linux 5.4+
 *
 * 当内核 < 5.7 时，BPF LSM 不可用，改用 kprobe 挂载内核安全函数。
 * kprobe 无法返回 -EPERM 阻止操作，因此 monitor 模式下 block 降级为告警。
 * 事件通过 perf event buffer 传输到用户态。
 *
 * 编译时必须定义 -DUSE_PERF_BUFFER。
 * 公共 map / 事件提交逻辑 定义在 bpf_common.h 中。
 */

#include "bpf_common.h"

char LICENSE[] SEC("license") = "GPL";

/* ── file_permission kprobe ────────────────────────────────────── */
SEC("kprobe/security_file_permission")
int BPF_KPROBE(kprobe_file_permission, struct file *file, int mask)
{
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry)
        return 0;

    unsigned long ino = BPF_CORE_READ(file, f_inode, i_ino);

    struct monitor_rule *rule = bpf_map_lookup_elem(&monitor_actions, &ino);
    if (!rule)
        return 0;

    if (!((rule->events_mask & EVENT_READ) && (mask & EVENT_READ)) &&
        !((rule->events_mask & EVENT_WRITE) && (mask & EVENT_WRITE)))
        return 0;

    /* kprobe 无法阻止操作，ACTION_BLOCK 降级为 ACTION_ALERT */
    unsigned char effective_action = rule->action;
    if (effective_action == ACTION_BLOCK)
        effective_action = ACTION_ALERT;

    emit_attr_event(ctx, ino, dentry, 0, mask, 0, 0, 0, effective_action, BACKPRESSURE_REALTIME);
    return 0;
}

/* ── path_chmod kprobe ─────────────────────────────────────────── */
SEC("kprobe/security_path_chmod")
int BPF_KPROBE(kprobe_path_chmod, const struct path *path, umode_t mode)
{
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    if (!dentry) return 0;

    unsigned long ino = BPF_CORE_READ(dentry, d_inode, i_ino);
    struct monitor_rule *rule = bpf_map_lookup_elem(&monitor_actions, &ino);
    if (!rule || !(rule->events_mask & EVENT_MASK_BIT(EVENT_CHMOD))) return 0;

    unsigned char effective_action = rule->action;
    if (effective_action == ACTION_BLOCK)
        effective_action = ACTION_ALERT;

    emit_attr_event(ctx, ino, dentry, EVENT_CHMOD, 0, mode, 0, 0, effective_action, BACKPRESSURE_REALTIME);
    return 0;
}

/* ── path_chown kprobe ─────────────────────────────────────────── */
SEC("kprobe/security_path_chown")
int BPF_KPROBE(kprobe_path_chown, const struct path *path, unsigned int uid, unsigned int gid)
{
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    if (!dentry) return 0;

    unsigned long ino = BPF_CORE_READ(dentry, d_inode, i_ino);
    struct monitor_rule *rule = bpf_map_lookup_elem(&monitor_actions, &ino);
    if (!rule || !(rule->events_mask & EVENT_MASK_BIT(EVENT_CHOWN))) return 0;

    unsigned char effective_action = rule->action;
    if (effective_action == ACTION_BLOCK)
        effective_action = ACTION_ALERT;

    emit_attr_event(ctx, ino, dentry, EVENT_CHOWN, 0, 0, uid, gid, effective_action, BACKPRESSURE_REALTIME);
    return 0;
}

/* ── inode_unlink kprobe ───────────────────────────────────────── */
SEC("kprobe/security_inode_unlink")
int BPF_KPROBE(kprobe_inode_unlink, struct inode *dir, struct dentry *dentry)
{
    if (!dentry) return 0;

    unsigned long ino = BPF_CORE_READ(dentry, d_inode, i_ino);
    struct monitor_rule *rule = bpf_map_lookup_elem(&monitor_actions, &ino);
    if (!rule || !(rule->events_mask & EVENT_MASK_BIT(EVENT_UNLINK))) return 0;

    unsigned char effective_action = rule->action;
    if (effective_action == ACTION_BLOCK)
        effective_action = ACTION_ALERT;

    emit_attr_event(ctx, ino, dentry, EVENT_UNLINK, 0, 0, 0, 0, effective_action, BACKPRESSURE_REALTIME);
    return 0;
}

/* ── inode_rename kprobe ───────────────────────────────────────── */
SEC("kprobe/security_inode_rename")
int BPF_KPROBE(kprobe_inode_rename,
               struct inode *old_dir, struct dentry *old_dentry,
               struct inode *new_dir, struct dentry *new_dentry)
{
    if (old_dentry) {
        unsigned long ino = BPF_CORE_READ(old_dentry, d_inode, i_ino);
        struct monitor_rule *rule = bpf_map_lookup_elem(&monitor_actions, &ino);
        if (rule && (rule->events_mask & EVENT_WRITE)) {
            unsigned char effective_action = rule->action;
            if (effective_action == ACTION_BLOCK)
                effective_action = ACTION_ALERT;
            emit_attr_event(ctx, ino, old_dentry, EVENT_RENAME, 0, 0, 0, 0,
                            effective_action, BACKPRESSURE_REALTIME);
        }
    }

    if (new_dentry) {
        unsigned long ino = BPF_CORE_READ(new_dentry, d_inode, i_ino);
        struct monitor_rule *rule = bpf_map_lookup_elem(&monitor_actions, &ino);
        if (rule && (rule->events_mask & EVENT_WRITE)) {
            unsigned char effective_action = rule->action;
            if (effective_action == ACTION_BLOCK)
                effective_action = ACTION_ALERT;
            emit_attr_event(ctx, ino, new_dentry, EVENT_RENAME, 0, 0, 0, 0,
                            effective_action, BACKPRESSURE_REALTIME);
        }
    }

    return 0;
}
