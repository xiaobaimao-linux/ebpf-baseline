#pragma once

#include <string>

// 从 /proc/<pid>/cgroup 解析容器 ID：匹配 docker-/cri-containerd-/crio-/docker/ 前缀，
// 提取 64 位十六进制 ID 并截断为 12 位短 ID。
// 宿主机进程、短寿进程 /proc 已消失、解析失败均返回空串（调用方应省略 container 字段）。
std::string container_id_of(int pid);

// /proc/<pid>/exe readlink 解析进程真实可执行路径。
// 短寿进程 /proc 已回收、内核线程（无 exe）等失败场景返回空串（调用方尽力处理）。
std::string exe_path_of(int pid);
