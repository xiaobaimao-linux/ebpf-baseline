// 事件吞吐压测：单文件 open+write+close 循环，统计 ops/s。
// 用法: gen_load <path> <ops> [seconds] [rate_per_s]
// 达到 ops、超时或按下 Ctrl+C 即停。rate_per_s > 0 时按固定速率节流（验证目标速率不丢事件）。
// 输出: 总 ops、耗时、ops/s。
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

static void sleep_ns(long long ns) {
    struct timespec ts = { ns / 1000000000LL, ns % 1000000000LL };
    nanosleep(&ts, NULL);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <path> <ops> [seconds] [rate_per_s]\n", argv[0]);
        return 1;
    }
    const char *path = argv[1];
    long long target = atoll(argv[2]);
    long long limit_s = argc > 3 ? atoll(argv[3]) : 30;
    long long rate = argc > 4 ? atoll(argv[4]) : 0;   // 0 = 全速
    char buf[32] = "throughput-probe-event-payload\n";
    long long ops = 0;
    long long start = now_ns();
    long long deadline = start + limit_s * 1000000000LL;
    // 窗口节流：每 100ms 一个窗口，窗口内跑满 rate/10 个 op，剩余时间 sleep。
    // 避免 per-op nanosleep 被调度器拉长导致达不到目标速率。
    const long long WINDOW_NS = 100000000LL;          // 100ms
    long long quota = rate > 0 ? rate / 10 : 0;       // 每窗口 op 数
    long long win_start = start;
    long long win_ops = 0;

    while (ops < target && now_ns() < deadline) {
        int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (fd >= 0) {
            if (write(fd, buf, sizeof(buf) - 1) > 0) ops++;
            close(fd);
        }
        if (quota > 0) {
            win_ops++;
            if (win_ops >= quota) {
                long long win_end = win_start + WINDOW_NS;
                long long rem = win_end - now_ns();
                if (rem > 0) sleep_ns(rem);
                win_start = now_ns();
                win_ops = 0;
            }
        }
    }
    long long elapsed = now_ns() - start;
    printf("ops=%lld elapsed_ms=%lld ops_per_s=%lld\n",
           ops, elapsed / 1000000, ops * 1000000000LL / elapsed);
    return 0;
}
