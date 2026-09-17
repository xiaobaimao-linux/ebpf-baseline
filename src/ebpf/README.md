# eBPF 用户态遥测加载层

对应 PRD 第 5 章架构图中"eBPF 遥测层"的用户态部分。

本期（v0.3 迁移）仅预留目录。BPF 程序的加载、skeleton 封装、
ring/perf buffer 消费逻辑当前位于 `src/baseline/monitor.cpp`，
后续版本拆出迁入此目录，供 M2/M3/M4 多个子系统复用。
内核态 BPF 程序源码位于仓库根目录 `bpf/`。
