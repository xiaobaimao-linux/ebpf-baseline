// 白名单集成测试 helper：fork + exec wl_writer（构造父链维度测试场景）
// 用法: wl_parent <wl_writer 路径> <output-file>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <wl_writer-path> <output-file>\n", argv[0]);
        return 1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }
    if (pid == 0) {
        execl(argv[1], argv[1], argv[2], (char*)NULL);
        perror("execl");
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return 1;
    }
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : 1;
}
