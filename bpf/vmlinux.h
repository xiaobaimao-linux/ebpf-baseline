/*
 * vmlinux.h — 最小化内核类型定义
 *
 * 仅包含 BPF 程序通过 BPF_CORE_READ 访问的内核结构体字段。
 * CO-RE 机制在加载时按字段名匹配内核 BTF 获取真实偏移量，
 * 结构体无需完整定义，字段名正确即可。
 *
 * 如需访问新的内核字段，只需在此处添加对应字段声明。
 */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

/* ── 基础类型（必须在 bpf_helpers.h 之前定义）────────────────── */
typedef unsigned char  __u8;
typedef unsigned short __u16;
typedef unsigned int   __u32;
typedef unsigned long long __u64;
typedef signed char    __s8;
typedef signed short   __s16;
typedef signed int     __s32;
typedef signed long long __s64;
typedef __u8  u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s32 s32;
typedef __s64 s64;
typedef short unsigned int umode_t;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
typedef int   bool;

#include <bpf/bpf_helpers.h>

/* ── BPF map 类型枚举（来自内核 linux/bpf.h）─────────────────── */
enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC        = 0,
	BPF_MAP_TYPE_HASH          = 1,
	BPF_MAP_TYPE_ARRAY         = 2,
	BPF_MAP_TYPE_PROG_ARRAY    = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_PERCPU_HASH   = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY  = 6,
	BPF_MAP_TYPE_STACK_TRACE   = 7,
	BPF_MAP_TYPE_CGROUP_ARRAY  = 8,
	BPF_MAP_TYPE_LRU_HASH      = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
	BPF_MAP_TYPE_LPM_TRIE      = 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS  = 13,
	BPF_MAP_TYPE_DEVMAP        = 14,
	BPF_MAP_TYPE_SOCKMAP       = 15,
	BPF_MAP_TYPE_CPUMAP        = 16,
	BPF_MAP_TYPE_XSKMAP        = 17,
	BPF_MAP_TYPE_SOCKHASH      = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE         = 22,
	BPF_MAP_TYPE_STACK         = 23,
	BPF_MAP_TYPE_SK_STORAGE    = 24,
	BPF_MAP_TYPE_DEVMAP_HASH   = 25,
	BPF_MAP_TYPE_STRUCT_OPS    = 26,
	BPF_MAP_TYPE_RINGBUF       = 27,
	BPF_MAP_TYPE_INODE_STORAGE = 28,
	BPF_MAP_TYPE_TASK_STORAGE  = 29,
};

/* ── BPF 辅助宏/标志 ──────────────────────────────────────────── */
#define BPF_RB_NO_WAKEUP     (1ULL)
#define BPF_RB_FORCE_WAKEUP  (2ULL)
#define BPF_F_CURRENT_CPU    ((__u64)-1)

/* ── 内核结构体（仅声明 BPF 程序访问的字段）──────────────────── */
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

/* x86_64 pt_regs（BPF_KPROBE 宏需要完整定义） */
struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
	unsigned long orig_ax;
	unsigned long ip;
	unsigned long cs;
	unsigned long flags;
	unsigned long sp;
	unsigned long ss;
};

struct qstr {
	union {
		struct {
			u32 hash;
			u32 len;
		};
		u64 hash_len;
	};
	const unsigned char *name;
};

struct inode {
	umode_t i_mode;
	/* CO-RE: i_ino 按字段名匹配，中间省略的字段不影响偏移量解析 */
	unsigned long i_ino;
};

struct dentry {
	/* 前置字段省略 */
	struct qstr d_name;
	struct inode *d_inode;
};

struct path {
	void *mnt;              /* struct vfsmount * */
	struct dentry *dentry;
};

struct file {
	/* 前置字段省略 */
	struct inode *f_inode;
	/* 中间字段省略 */
	struct path f_path;
};

#pragma clang attribute pop
#endif /* __VMLINUX_H__ */
