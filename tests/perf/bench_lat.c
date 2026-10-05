// 系统调用额外延迟基准：单文件 open+write+close 循环，逐次计时。
// 用法: bench_lat <path> <iterations>
// 输出: P50/P90/P99/P999/avg/max（纳秒），前 100 次为预热不计入。
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static long long now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static int cmp_ll(const void *a, const void *b) {
    long long x = *(const long long *)a, y = *(const long long *)b;
    return (x > y) - (x < y);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <path> <iterations>\n", argv[0]);
        return 1;
    }
    const char *path = argv[1];
    int iters = atoi(argv[2]);
    const int warmup = 100;
    long long *samples = malloc(sizeof(long long) * iters);

    char buf[16] = "latency-probe\n";
    for (int i = 0; i < iters + warmup; i++) {
        long long t0 = now_ns();
        int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (fd >= 0) {
            (void)write(fd, buf, sizeof(buf) - 1);
            close(fd);
        }
        long long dt = now_ns() - t0;
        if (i >= warmup) samples[i - warmup] = dt;
    }

    qsort(samples, iters, sizeof(long long), cmp_ll);
    long long sum = 0;
    for (int i = 0; i < iters; i++) sum += samples[i];
    printf("path=%s iters=%d\n", path, iters);
    printf("P50=%lld P90=%lld P99=%lld P999=%lld avg=%lld max=%lld (ns)\n",
           samples[iters * 50 / 100], samples[iters * 90 / 100],
           samples[iters * 99 / 100], samples[iters * 999 / 1000],
           sum / iters, samples[iters - 1]);
    free(samples);
    return 0;
}
