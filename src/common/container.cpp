#include "container.hpp"

#include <cstdio>
#include <cstring>

// 移植自 ~/spike/exec_spike.c 的 container_id_of()，逻辑保持一致：
// /proc/<pid>/cgroup 逐行匹配运行时前缀，提取 64hex 截 12 位展示短 ID。
// 短寿进程 /proc 已回收属于正常场景，静默返回空串，由调用方省略字段。
std::string container_id_of(int pid)
{
    char path[64];
    char line[512];

    if (pid <= 0)
        return "";

    snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return "";

    std::string cid;
    while (fgets(line, sizeof(line), f)) {
        static const char *marks[] = {"docker-", "cri-containerd-", "crio-", "docker/", nullptr};
        for (int i = 0; marks[i]; i++) {
            char *p = strstr(line, marks[i]);
            if (!p)
                continue;
            p += strlen(marks[i]);
            size_t n = 0;
            while (n < 64 && ((p[n] >= '0' && p[n] <= '9') || (p[n] >= 'a' && p[n] <= 'f')))
                n++;
            if (n >= 12) {
                cid.assign(p, 12);
                fclose(f);
                return cid;
            }
        }
    }

    fclose(f);
    return "";
}
