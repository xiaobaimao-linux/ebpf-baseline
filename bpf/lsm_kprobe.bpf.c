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

    /* R13：规则集合匹配；顺带修正内核 MAY_* 位编码（MAY_READ=4/MAY_WRITE=2，
     * 原码误用 EVENT_READ(1) 判定导致 read 永不命中），并归一化 mask 与 LSM
     * 路径一致 */
    struct monitor_rule_set *set = bpf_map_lookup_elem(&monitor_actions, &ino);
    struct rule_match_result m = match_rule_set(set, mask & 4, mask & 2, 0);
    if (!m.matched)
        return 0;

    int norm_mask = 0;
    if (mask & 4) norm_mask |= EVENT_READ;
    if (mask & 2) norm_mask |= EVENT_WRITE;

    /* kprobe 无法阻止操作，ACTION_BLOCK 降级为 ACTION_ALERT */
    unsigned char effective_action = m.action;
    if (effective_action == ACTION_BLOCK)
        effective_action = ACTION_ALERT;

    emit_attr_event(ctx, ino, dentry, 0, norm_mask, 0, 0, 0, effective_action, BACKPRESSURE_REALTIME);
    return 0;
}

/* ── path_chmod kprobe ─────────────────────────────────────────── */
SEC("kprobe/security_path_chmod")
int BPF_KPROBE(kprobe_path_chmod, const struct path *path, umode_t mode)
{
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    if (!dentry) return 0;

    unsigned long ino = BPF_CORE_READ(dentry, d_inode, i_ino);
    struct monitor_rule_set *set = bpf_map_lookup_elem(&monitor_actions, &ino);
    struct rule_match_result m = match_rule_set(set, 0, 0, EVENT_MASK_BIT(EVENT_CHMOD));
    if (!m.matched) return 0;

    unsigned char effective_action = m.action;
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
    struct monitor_rule_set *set = bpf_map_lookup_elem(&monitor_actions, &ino);
    struct rule_match_result m = match_rule_set(set, 0, 0, EVENT_MASK_BIT(EVENT_CHOWN));
    if (!m.matched) return 0;

    unsigned char effective_action = m.action;
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
    struct monitor_rule_set *set = bpf_map_lookup_elem(&monitor_actions, &ino);
    struct rule_match_result m = match_rule_set(set, 0, 0, EVENT_MASK_BIT(EVENT_UNLINK));
    if (!m.matched) return 0;

    unsigned char effective_action = m.action;
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
        struct monitor_rule_set *set = bpf_map_lookup_elem(&monitor_actions, &ino);
        struct rule_match_result m = match_rule_set(set, 0, 1, 0);
        if (m.matched) {
            unsigned char effective_action = m.action;
            if (effective_action == ACTION_BLOCK)
                effective_action = ACTION_ALERT;
            emit_attr_event(ctx, ino, old_dentry, EVENT_RENAME, 0, 0, 0, 0,
                            effective_action, BACKPRESSURE_REALTIME);
        }
    }

    if (new_dentry) {
        unsigned long ino = BPF_CORE_READ(new_dentry, d_inode, i_ino);
        struct monitor_rule_set *set = bpf_map_lookup_elem(&monitor_actions, &ino);
        struct rule_match_result m = match_rule_set(set, 0, 1, 0);
        if (m.matched) {
            unsigned char effective_action = m.action;
            if (effective_action == ACTION_BLOCK)
                effective_action = ACTION_ALERT;
            emit_attr_event(ctx, ino, new_dentry, EVENT_RENAME, 0, 0, 0, 0,
                            effective_action, BACKPRESSURE_REALTIME);
        }
    }

    return 0;
}
