/*
 * lsm_file.bpf.c — BPF LSM 版监控程序，支持 Linux 5.7+
 *
 * 编译模式：
 *   默认（5.8+）：ring buffer + 水位背压 + block 支持
 *   -DUSE_PERF_BUFFER（5.7）：perf event buffer，无水位背压
 *
 * 公共 map / 事件提交 / 背压逻辑 定义在 bpf_common.h 中。
 */

#include "bpf_common.h"

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1

struct print_ctx {
    u32 count;
};

/* ── file_permission ───────────────────────────────────────────── */
SEC("lsm/file_permission")
int BPF_PROG(file_permission, struct file *file, int mask)
{
    char comm[16] = {};
    unsigned long ino;

    // R13：调试期 fname 预读/bpf_printk 已移除（trace_printk 命中路径 +0.9μs、
    // 未命中路径全系统每次 file_permission +87ns，见 docs/perf-tuning-w4d1.md R13-3）
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry)
        return 0;

    ino = BPF_CORE_READ(file, f_inode, i_ino);

    // R13：同 inode 多规则集合匹配（read/write 语义位分别判定）
    struct monitor_rule_set *set = bpf_map_lookup_elem(&monitor_actions, &ino);
    struct rule_match_result m = match_rule_set(set, mask & 4, mask & 2, 0);
    if (!m.matched)
        return 0;

    // 归一化为 EVENT_READ/EVENT_WRITE 语义位后随事件上报，保持用户态
    // e->mask 的判定逻辑不变
    int norm_mask = 0;
    if (mask & 4) norm_mask |= EVENT_READ;
    if (mask & 2) norm_mask |= EVENT_WRITE;

#ifdef USE_PERF_BUFFER
    int bp_decision = BACKPRESSURE_REALTIME;
#else
    int bp_decision = check_backpressure(m.severity);
    if (bp_decision == BACKPRESSURE_DROP) {
        inc_drop_count();
        return 0;
    }
#endif

    emit_attr_event(ctx, ino, dentry, 0, norm_mask, 0, 0, 0, m.action, bp_decision);

    if (m.action == ACTION_BLOCK)
        return -EPERM;
    return 0;
}

/* ── chmod / chown / unlink ────────────────────────────────────── */
SEC("lsm/path_chmod")
int BPF_PROG(file_chmod_hook, const struct path *path, umode_t mode)
{
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    if (!dentry) return 0;
    unsigned long ino = BPF_CORE_READ(dentry, d_inode, i_ino);

    struct monitor_rule_set *set = bpf_map_lookup_elem(&monitor_actions, &ino);
    struct rule_match_result m = match_rule_set(set, 0, 0, EVENT_MASK_BIT(EVENT_CHMOD));
    if (!m.matched) return 0;
#ifdef USE_PERF_BUFFER
    int bp = BACKPRESSURE_REALTIME;
#else
    int bp = check_backpressure(m.severity);
    if (bp == BACKPRESSURE_DROP) { inc_drop_count(); return 0; }
#endif
    emit_attr_event(ctx, ino, dentry, EVENT_CHMOD, 0, mode, 0, 0, m.action, bp);
    return (m.action == ACTION_BLOCK) ? -EPERM : 0;
}

SEC("lsm/path_chown")
int BPF_PROG(file_chown_hook, const struct path *path, unsigned int uid, unsigned int gid)
{
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    if (!dentry) return 0;
    unsigned long ino = BPF_CORE_READ(dentry, d_inode, i_ino);

    struct monitor_rule_set *set = bpf_map_lookup_elem(&monitor_actions, &ino);
    struct rule_match_result m = match_rule_set(set, 0, 0, EVENT_MASK_BIT(EVENT_CHOWN));
    if (!m.matched) return 0;
#ifdef USE_PERF_BUFFER
    int bp = BACKPRESSURE_REALTIME;
#else
    int bp = check_backpressure(m.severity);
    if (bp == BACKPRESSURE_DROP) { inc_drop_count(); return 0; }
#endif
    emit_attr_event(ctx, ino, dentry, EVENT_CHOWN, 0, 0, uid, gid, m.action, bp);
    return (m.action == ACTION_BLOCK) ? -EPERM : 0;
}

SEC("lsm/inode_unlink")
int BPF_PROG(file_unlink_hook, struct inode *dir, struct dentry *dentry)
{
    if (!dentry) return 0;
    unsigned long ino = BPF_CORE_READ(dentry, d_inode, i_ino);

    struct monitor_rule_set *set = bpf_map_lookup_elem(&monitor_actions, &ino);
    struct rule_match_result m = match_rule_set(set, 0, 0, EVENT_MASK_BIT(EVENT_UNLINK));
    if (!m.matched) return 0;
#ifdef USE_PERF_BUFFER
    int bp = BACKPRESSURE_REALTIME;
#else
    int bp = check_backpressure(m.severity);
    if (bp == BACKPRESSURE_DROP) { inc_drop_count(); return 0; }
#endif
    emit_attr_event(ctx, ino, dentry, EVENT_UNLINK, 0, 0, 0, 0, m.action, bp);
    return (m.action == ACTION_BLOCK) ? -EPERM : 0;
}

/* ── rename ────────────────────────────────────────────────────── */
static __always_inline int check_rename_target(void *ctx, struct dentry *dentry)
{
    if (!dentry) return 0;
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode) return 0;

    unsigned long ino = BPF_CORE_READ(inode, i_ino);
    struct monitor_rule_set *set = bpf_map_lookup_elem(&monitor_actions, &ino);
    struct rule_match_result m = match_rule_set(set, 0, 1, 0);
    if (!m.matched) return 0;

#ifdef USE_PERF_BUFFER
    int bp = BACKPRESSURE_REALTIME;
#else
    int bp = check_backpressure(m.severity);
    if (bp == BACKPRESSURE_DROP) { inc_drop_count(); return 0; }
#endif
    emit_attr_event(ctx, ino, dentry, EVENT_RENAME, 0, 0, 0, 0, m.action, bp);
    return (m.action == ACTION_BLOCK) ? -EPERM : 0;
}

SEC("lsm/inode_rename")
int BPF_PROG(inode_rename_hook, struct inode *old_dir, struct dentry *old_dentry,
             struct inode *new_dir, struct dentry *new_dentry)
{
    int ret = check_rename_target(ctx, old_dentry);
    if (ret != 0) return ret;
    return check_rename_target(ctx, new_dentry);
}

/* ── mmap_file（5.9+ 内核，__weak 兼容 5.8）───────────────────── */
SEC("lsm/mmap_file")
int __weak BPF_PROG(file_mmap_hook, struct file *file, unsigned long reqprot,
                    unsigned long prot, unsigned long flags)
{
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry) return 0;

    unsigned long ino = BPF_CORE_READ(file, f_inode, i_ino);
    struct monitor_rule_set *set = bpf_map_lookup_elem(&monitor_actions, &ino);
    struct rule_match_result m = match_rule_set(set, reqprot & 0x1, reqprot & 0x2, 0);
    if (!m.matched) return 0;

#ifdef USE_PERF_BUFFER
    int bp = BACKPRESSURE_REALTIME;
#else
    int bp = check_backpressure(m.severity);
    if (bp == BACKPRESSURE_DROP) { inc_drop_count(); return 0; }
#endif
    emit_attr_event(ctx, ino, dentry, EVENT_MMAP, 0, 0, (unsigned int)reqprot, 0, m.action, bp);
    return (m.action == ACTION_BLOCK) ? -EPERM : 0;
}
