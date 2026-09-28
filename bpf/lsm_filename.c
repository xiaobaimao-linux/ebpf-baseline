#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* 目标 inode 号，修改为实际要查询的值 */
#define TARGET_INO 3578369

extern int bpf_path_d_path(struct path *path, char *buf, int buf_len) __ksym;

/*
 * LSM hook: file_permission
 * 每当进程对文件执行 read/write 操作时，内核会调用此 hook
 * 我们在此拦截，检查文件 inode 是否匹配目标值，匹配则输出文件名
 */
SEC("lsm/file_permission")
int BPF_PROG(lookup_filename_by_inode, struct file *file, int mask)
{
    unsigned long ino;

    /*
     * BPF_CORE_READ 宏：安全地读取内核结构体字段
     * file->f_inode->i_ino 是文件的 inode 编号
     * 等价于: ino = file->f_inode->i_ino (但带边界检查)
     */
    ino = BPF_CORE_READ(file, f_inode, i_ino);
    
    /* 快速过滤：inode 不匹配直接返回，不做任何处理 */
    if (ino != TARGET_INO)
        return 0;

    /*
     * inode 匹配，尝试获取文件的完整路径
     * bpf_path_d_path: eBPF helper 函数，将 struct path 转为字符串路径
     * 例如: /home/user/test.txt
     * 返回值: >=0 表示成功，<0 表示失败
     */
    char path_buf[256] = {};
    int ret = bpf_path_d_path(&file->f_path, path_buf, sizeof(path_buf));
    
    if (ret >= 0) {
        /* 成功获取路径，输出到 kernel trace (可通过 trace_pipe 查看) */
        bpf_printk("[inode_lookup] inode=%lu path=%s\n", ino, path_buf);
    } else {
        /*
         * d_path 失败（某些特殊文件系统不支持路径解析）
         * 退化为只读取 dentry->d_name.name（文件名，不含目录）
         * 例如: test.txt
         */
        const unsigned char *name_ptr = BPF_CORE_READ(file, f_path.dentry, d_name.name);
        char fname[64] = {};
        if (name_ptr)
            bpf_probe_read_kernel_str(fname, sizeof(fname), name_ptr);
        bpf_printk("[inode_lookup] inode=%lu filename=%s (d_path failed: %d)\n", ino, fname, ret);
    }

    /* 返回 0 表示允许操作，不阻止文件访问 */
    return 0;
}
