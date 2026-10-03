// 白名单集成测试 helper：直接向 argv[1] 写一字节（触发 file.write 事件）
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <output-file>\n", argv[0]);
        return 1;
    }
    int fd = open(argv[1], O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    if (write(fd, "x", 1) != 1) {
        fprintf(stderr, "write failed\n");
        close(fd);
        return 1;
    }
    close(fd);
    return 0;
}
