#pragma once

// 读取 eBPF drop_stats map 并输出统计信息
// 返回 0 表示成功，非 0 表示出错
int RunStats(int argc, char* argv[]);
