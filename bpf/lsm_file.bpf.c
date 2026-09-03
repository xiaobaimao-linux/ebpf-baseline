#include "event.h"
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1

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

// 定义 per-CPU 丢包统计 Map
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);    // 只有1个计数槽（key=0）
    __type(key, __u32);
    __type(value, __u64);     // 64位计数器，避免长时间运行溢出
} drop_stats SEC(".maps");

// 水位等级 Map：由用户态写入当前水位，eBPF 读取后做背压决策
// key=0, value=当前水位 (WATERMARK_NORMAL/WARNING/HIGH/OVERLOAD)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} watermark_level SEC(".maps");

// 背压决策返回值
#define BACKPRESSURE_REALTIME  0   // 实时提交（带唤醒）
#define BACKPRESSURE_BATCH     1   // 批量提交（禁唤醒 BPF_RB_NO_WAKEUP）
#define BACKPRESSURE_DROP      2   // 直接丢弃

// 计数函数
static __always_inline void inc_drop_count()
{
    __u32 key = 0;
    __u64 *cnt = bpf_map_lookup_elem(&drop_stats, &key);
    if (cnt) {
        (*cnt)++;
    }
}

// ── 水位背压决策 ──────────────────────────────────────────────────
// 根据当前水位 + 规则严重等级，返回 BACKPRESSURE_REALTIME / BATCH / DROP
//
// 策略矩阵：
//
//               | NORMAL | WARNING | HIGH   | OVERLOAD
//  -------------+--------+---------+--------+---------
//  LOW(0)       | 实时   | 批量    | 丢弃   | 丢弃
//  MEDIUM(1)    | 实时   | 实时    | 批量   | 丢弃
//  HIGH(2)      | 实时   | 实时    | 实时   | 批量
//  CRITICAL(3)  | 实时   | 实时    | 实时   | 实时
//
static __always_inline int check_backpressure(unsigned char severity)
{
    __u32 key = 0;
    __u32 *level = bpf_map_lookup_elem(&watermark_level, &key);
    if (!level)
        return BACKPRESSURE_REALTIME;  // map 未初始化时默认实时提交

    switch (*level) {
    case WATERMARK_NORMAL:
        return BACKPRESSURE_REALTIME;

    case WATERMARK_WARNING:
        // Low → 批量，其余实时
        if (severity == SEVERITY_LOW)
            return BACKPRESSURE_BATCH;
        return BACKPRESSURE_REALTIME;

    case WATERMARK_HIGH:
        // Low → 丢弃，Medium → 批量，High/Critical → 实时
        if (severity == SEVERITY_LOW)
            return BACKPRESSURE_DROP;
        if (severity == SEVERITY_MEDIUM)
            return BACKPRESSURE_BATCH;
        return BACKPRESSURE_REALTIME;

    case WATERMARK_OVERLOAD:
        // Low/Medium → 丢弃，High → 批量，Critical → 实时
        if (severity == SEVERITY_LOW || severity == SEVERITY_MEDIUM)
            return BACKPRESSURE_DROP;
        if (severity == SEVERITY_HIGH)
            return BACKPRESSURE_BATCH;
        return BACKPRESSURE_REALTIME;

    default:
        return BACKPRESSURE_REALTIME;
    }
}

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

    // 2) CO-RE 感知字符串读取，生成 BTF 重定位信息
    bpf_core_read_str(fname, sizeof(fname), name_ptr);

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
        bpf_printk("NO READ/WRITE, PASS: %s\n", fname);
        return 0;
    }

    // ── 水位背压决策 ──────────────────────────────────────────
    int bp_decision = check_backpressure(rule->severity);
    if (bp_decision == BACKPRESSURE_DROP) {
        inc_drop_count();
        return 0;
    }

    // 匹配成功
    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        bpf_printk("ringbuf reserve failed\n");
        inc_drop_count();
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    __builtin_memcpy(e->comm, comm, sizeof(comm));
    e->ino = ino;
    e->action = rule->action;
    e->mask = mask;

    // CO-RE: 先通过 BPF_CORE_READ 获取指针（生成重定位），再用 bpf_core_read_str 读取字符串
    bpf_core_read_str(e->path, sizeof(e->path), name_ptr);

    // BATCH → BPF_RB_NO_WAKEUP（禁唤醒，批量提交）；REALTIME → 0（实时提交）
    bpf_ringbuf_submit(e, bp_decision == BACKPRESSURE_BATCH ? BPF_RB_NO_WAKEUP : 0);

    // 使用
    if (rule->action == ACTION_BLOCK) {
        bpf_printk("BLOCK FILE %s  READ OR WRITE, mask: %d\n", fname, mask);
        return -EPERM;
    }

    return 0;
}

// ── chmod/chown/unlink 公共处理 ─────────────────────────────────
// 查规则 → 背压决策 → 填充并提交事件，消除各 hook 重复代码
static __always_inline int emit_attr_event(unsigned long ino,
                                           struct dentry *dentry,
                                           unsigned char event_type,
                                           unsigned int new_mode,
                                           unsigned int new_uid,
                                           unsigned int new_gid)
{
    struct monitor_rule *rule = bpf_map_lookup_elem(&monitor_actions, &ino);
    if (!rule)
        return 0;

    // 检查 events_mask 是否包含该事件类型
    if (!(rule->events_mask & EVENT_MASK_BIT(event_type)))
        return 0;

    int bp_decision = check_backpressure(rule->severity);
    if (bp_decision == BACKPRESSURE_DROP) {
        inc_drop_count();
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        inc_drop_count();
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    __builtin_memset(e->comm, 0, sizeof(e->comm));
    e->ino = ino;
    e->action = rule->action;
    e->event_type = event_type;
    e->new_mode = new_mode;
    e->new_uid = new_uid;
    e->new_gid = new_gid;
    e->mask = 0;

    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
    if (name_ptr)
        bpf_core_read_str(e->path, sizeof(e->path), name_ptr);

    bpf_ringbuf_submit(e, bp_decision == BACKPRESSURE_BATCH ? BPF_RB_NO_WAKEUP : 0);

    // ACTION_BLOCK → 阻止操作
    if (rule->action == ACTION_BLOCK)
        return -EPERM;
    return 0;
}

SEC("lsm/path_chmod")
int BPF_PROG(file_chmod_hook, const struct path *path, umode_t mode) {
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    if (!dentry)
        return 0;
    unsigned long ino = BPF_CORE_READ(dentry, d_inode, i_ino);
    bpf_printk("CHMOD detected for inode %lu, new mode: %u\n", ino, mode);
    return emit_attr_event(ino, dentry, EVENT_CHMOD, mode, 0, 0);
}

SEC("lsm/path_chown")
int BPF_PROG(file_chown_hook, const struct path *path, unsigned int uid, unsigned int gid) {
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    if (!dentry)
        return 0;
    unsigned long ino = BPF_CORE_READ(dentry, d_inode, i_ino);
    bpf_printk("CHOWN detected for inode %lu, new uid: %u, gid: %u\n", ino, uid, gid);
    return emit_attr_event(ino, dentry, EVENT_CHOWN, 0, uid, gid);
}

SEC("lsm/inode_unlink")
int BPF_PROG(file_unlink_hook, struct inode *dir, struct dentry *dentry) {
    if (!dentry)
        return 0;
    unsigned long ino = BPF_CORE_READ(dentry, d_inode, i_ino);
    bpf_printk("UNLINK detected for inode %lu\n", ino);
    return emit_attr_event(ino, dentry, EVENT_UNLINK, 0, 0, 0);
}

// ── rename：仅当 write 事件被监控时，复用 emit_attr_event 处理 ──
static __always_inline int check_rename_target(struct dentry *dentry)
{
    if (!dentry)
        return 0;
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode)
        return 0;

    unsigned long ino = BPF_CORE_READ(inode, i_ino);
    struct monitor_rule *rule = bpf_map_lookup_elem(&monitor_actions, &ino);
    if (!rule || !(rule->events_mask & EVENT_WRITE))
        return 0;

    bpf_printk("RENAME detected for inode %lu (write monitored)\n", ino);
    return emit_attr_event(ino, dentry, EVENT_RENAME, 0, 0, 0);
}

// inode_rename: 同时检查源文件（被移走）和目标文件（被覆盖）
SEC("lsm/inode_rename")
int BPF_PROG(inode_rename_hook, struct inode *old_dir, struct dentry *old_dentry,
             struct inode *new_dir, struct dentry *new_dentry, unsigned int flags) {
    int ret = check_rename_target(old_dentry);
    if (ret != 0)
        return ret;
    return check_rename_target(new_dentry);
}

// file_mmap: 根据 mmap 保护级别匹配监控事件，复用 emit_attr_event 处理
// PROT_READ=0x1, PROT_WRITE=0x2
SEC("lsm/mmap_file")
int BPF_PROG(file_mmap_hook, struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags) {
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry)
        return 0;

    unsigned long ino = BPF_CORE_READ(file, f_inode, i_ino);
    struct monitor_rule *rule = bpf_map_lookup_elem(&monitor_actions, &ino);
    if (!rule)
        return 0;

    // 根据 mmap 保护级别匹配监控事件
    int matched = 0;
    if ((reqprot & 0x2) && (rule->events_mask & EVENT_WRITE))  // PROT_WRITE
        matched = 1;
    if ((reqprot & 0x1) && (rule->events_mask & EVENT_READ))   // PROT_READ
        matched = 1;
    if (!matched)
        return 0;

    bpf_printk("MMAP detected for inode %lu, reqprot: %lu\n", ino, reqprot);
    return emit_attr_event(ino, dentry, EVENT_MMAP, (unsigned int)reqprot, 0, 0);
}