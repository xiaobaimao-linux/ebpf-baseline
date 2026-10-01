// 单元测试：进程树（M0-1：ProcNode 身份字段 / (pid,start_time) 版本查找 /
// tombstone 可查性）。编译目标见 tests/Makefile（test_process_tree）。
//
// 说明：fake pid（424242x）在系统中不存在，apply() 内对 /proc 的尽力读取
// 全部失败，正好隔离出“纯事件字段”路径；涉及真实 /proc 解析的断言改用
// 测试进程自身 pid。

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>

#include "container.hpp"
#include "process_tree.hpp"

static proc_event make_event(unsigned char kind, unsigned int pid, unsigned int ppid) {
    proc_event pe{};
    pe.kind = kind;
    pe.pid = pid;
    pe.ppid = ppid;
    return pe;
}

// ====== PT-001: bootstrap 存储 uid/gid（与 /proc 一致）+ 容器字段一致 ======
static void test_bootstrap_identity() {
    ProcessTree tree;
    tree.bootstrap();

    // 自身进程必有节点；uid 与 getuid() 一致，start_time 非 0
    const ProcNode* self = tree.find(static_cast<unsigned int>(getpid()));
    assert(self != nullptr);
    assert(self->uid == static_cast<unsigned int>(getuid()));
    assert(self->start_time != 0);
    // comm 为二进制名截断到 15 字符（TASK_COMM_LEN-1）
    std::string expected_comm = "test_process_tree";
    expected_comm.resize(15);
    assert(self->comm_str() == expected_comm);

    // 容器短 ID 与 /proc 解析一致；非空时必须是 12 位
    assert(self->container_id_str() == container_id_of(getpid()));
    if (!self->container_id_str().empty())
        assert(self->container_id_str().size() == 12);

    // 1 号进程（init）必有节点
    assert(tree.find(1) != nullptr);
    printf("  [PASS] PT-001: bootstrap 存储 uid/gid + 容器字段与 /proc 一致\n");
}

// ====== PT-002: fork 事件存 uid/gid，不填 container_id（等 exec）========
static void test_fork_stores_uid_gid() {
    ProcessTree tree;
    proc_event pe = make_event(PROC_KIND_FORK, 4242420, 1);
    pe.uid = 1000;
    pe.gid = 1001;
    strcpy(pe.comm, "forktest");
    tree.apply(pe);

    const ProcNode* node = tree.find(pe.pid);
    assert(node != nullptr);
    assert(node->uid == 1000 && node->gid == 1001);
    assert(node->ppid == 1);
    assert(node->comm_str() == "forktest");
    assert(node->container_id_str().empty());  // fork 不填，等 exec
    printf("  [PASS] PT-002: fork 存 uid/gid、container_id 留空\n");
}

// ====== PT-003: exec 更新 uid/gid + container_id（已有节点 + 就地补建）====
static void test_exec_fills_identity() {
    ProcessTree tree;

    // 就地补建：树中无此 pid（fake pid，/proc 读取失败走事件值）
    proc_event pe = make_event(PROC_KIND_EXEC, 4242421, 4242420);
    pe.uid = 1002;
    pe.gid = 1003;
    pe.start_time = 123456789ULL;
    strcpy(pe.comm, "exectest");
    tree.apply(pe);

    const ProcNode* node = tree.find(pe.pid);
    assert(node != nullptr);
    assert(node->uid == 1002 && node->gid == 1003);
    assert(node->start_time == 123456789ULL);
    assert(node->container_id_str().empty());  // fake pid 无 /proc，容器留空

    // 已有节点（测试进程自身）：container_id/exe 与 /proc 解析一致
    proc_event me = make_event(PROC_KIND_EXEC,
                               static_cast<unsigned int>(getpid()),
                               static_cast<unsigned int>(getppid()));
    me.uid = 4242;
    me.gid = 4243;
    strcpy(me.comm, "pt_exec_self");
    tree.apply(me);

    const ProcNode* self = tree.find(static_cast<unsigned int>(getpid()));
    assert(self != nullptr);
    assert(self->uid == 4242 && self->gid == 4243);
    assert(self->comm_str() == "pt_exec_self");
    assert(self->container_id_str() == container_id_of(getpid()));
    assert(self->exe_str() == exe_path_of(getpid()));
    printf("  [PASS] PT-003: exec 更新 uid/gid + container_id（就地补建 + 已有节点）\n");
}

// ====== PT-004: find(pid, start_time) 版本匹配（pid 复用防护）============
static void test_find_by_start_time() {
    ProcessTree tree;
    proc_event pe = make_event(PROC_KIND_EXEC, 4242422, 1);
    pe.uid = 7;
    pe.gid = 8;
    pe.start_time = 111222333ULL;
    tree.apply(pe);

    // start_time 匹配 / 为 0 退化 / 不匹配（pid 复用）/ pid 不存在
    assert(tree.find(pe.pid, 111222333ULL) != nullptr);
    assert(tree.find(pe.pid, 0) != nullptr);
    assert(tree.find(pe.pid, 999888777ULL) == nullptr);
    assert(tree.find(7777777, 111222333ULL) == nullptr);
    // 节点身份字段经重载查找仍可取
    const ProcNode* node = tree.find(pe.pid, 111222333ULL);
    assert(node->uid == 7 && node->gid == 8);
    printf("  [PASS] PT-004: find(pid,start_time) 匹配/退化/复用返回空\n");
}

// ====== PT-005: tombstone 节点仍可查（含身份字段），sweep 不误删 ========
static void test_tombstone_findable() {
    ProcessTree tree;
    proc_event fork = make_event(PROC_KIND_FORK, 4242423, 1);
    fork.uid = 9;
    fork.gid = 10;
    tree.apply(fork);

    proc_event exit_e = make_event(PROC_KIND_EXIT, 4242423, 1);
    exit_e.start_time = 555ULL;
    tree.apply(exit_e);

    const ProcNode* node = tree.find(4242423);
    assert(node != nullptr);
    assert(node->exited);
    assert(node->uid == 9 && node->gid == 10);  // tombstone 保留 fork 时身份
    // 未过 60s 窗口，sweep 不得清除
    tree.sweep_tombstones();
    assert(tree.find(4242423) != nullptr);
    assert(tree.tombstone_count() == 1);
    printf("  [PASS] PT-005: tombstone 可查且保留身份字段、sweep 不误删\n");
}

int main() {
    printf("=== test_process_tree ===\n");
    test_bootstrap_identity();
    test_fork_stores_uid_gid();
    test_exec_fills_identity();
    test_find_by_start_time();
    test_tombstone_findable();
    printf("=== all process_tree tests passed ===\n");
    return 0;
}
