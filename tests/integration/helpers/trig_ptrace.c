// 权限遥测验收触发器（PRIV-003）：fork 子进程 pause，
// 父进程对其 ptrace(PTRACE_ATTACH)，等待 SIGTRAP 后 DETACH 并回收。
// 子进程 pid 写入 argv[1] 指定文件，供测试脚本比对 target_pid。
// 用法: trig_ptrace <child_pid_file>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    pid_t child;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <child_pid_file>\n", argv[0]);
        return 2;
    }

    child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }
    if (child == 0) {
        pause();          /* 挂起等待父进程 attach */
        _exit(0);
    }

    FILE *f = fopen(argv[1], "w");
    if (f) {
        fprintf(f, "%d\n", child);
        fclose(f);
    }

    if (ptrace(PTRACE_ATTACH, child, 0, 0) != 0) {
        perror("PTRACE_ATTACH");
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 1;
    }
    waitpid(child, NULL, 0);              /* 等待 attach 触发的 SIGTRAP */
    ptrace(PTRACE_DETACH, child, 0, 0);
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    return 0;
}
