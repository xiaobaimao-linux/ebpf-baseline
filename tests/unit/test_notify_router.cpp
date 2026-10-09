// 单元测试：外发路由判定（级别 vs min_level）与静默窗口判定（W5 D4）
// 编译: g++ -std=c++17 -I../../src -I../../src/common -I../../src/alerts \
//       -o test_notify_router test_notify_router.cpp

#include <cassert>
#include <cstdio>
#include <chrono>
#include "notify_router.hpp"

using namespace std::chrono;

// ====== NRT-001: 级别路由全矩阵（severity × min_level）======
void test_route_matrix() {
    const char* sevs[] = {"critical", "high", "medium", "low"};
    // expected[sev][min_level=critical,high,medium,low]
    const bool expected[4][4] = {
        {true,  true,  true,  true},   // critical
        {false, true,  true,  true},   // high
        {false, false, true,  true},   // medium
        {false, false, false, true},   // low
    };
    const char* mins[] = {"critical", "high", "medium", "low"};
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            assert(notify::ShouldRouteByLevel(sevs[i], mins[j]) == expected[i][j]);
        }
    }
    printf("  [PASS] NRT-001: 级别路由全矩阵\n");
}

// ====== NRT-002: 边界与非法值 ======
void test_route_edge() {
    // 未知 severity 按 medium（DSL priority 缺省口径）
    assert(notify::ShouldRouteByLevel("weird", "medium"));
    assert(!notify::ShouldRouteByLevel("weird", "high"));
    assert(!notify::ShouldRouteByLevel("", "high"));
    // min_level 空/非法按默认 high
    assert(notify::ShouldRouteByLevel("critical", ""));
    assert(!notify::ShouldRouteByLevel("medium", ""));
    assert(notify::ShouldRouteByLevel("high", "bogus"));
    assert(!notify::ShouldRouteByLevel("medium", "bogus"));
    printf("  [PASS] NRT-002: 路由边界与非法值\n");
}

// ====== NRT-003: 静默对象 key —— 进程类 exe+pid / 文件类路径 ======
void test_silence_object_key() {
    AlertEvent e;
    e.rule_id = "dsl.reverse_shell";

    // 进程类告警：process.* 事件用 exe+pid 命名空间
    e.event_type = "process.exec";
    e.exe = "/bin/bash";
    e.pid = 1234;
    e.file_path = "/bin/bash";   // exec 告警 file_path=exe，不应被当作文件类
    assert(notify::SilenceObjectKey(e) == "proc:/bin/bash:1234");

    // 同 exe 不同 pid → 不同 key
    e.pid = 5678;
    assert(notify::SilenceObjectKey(e) == "proc:/bin/bash:5678");

    // 文件类告警：用路径
    e.event_type = "read";
    e.file_path = "/etc/shadow";
    e.exe = "/usr/bin/cat";
    e.pid = 999;
    assert(notify::SilenceObjectKey(e) == "file:/etc/shadow");

    // 文件类无路径、有 exe → 退 proc 命名空间
    e.event_type = "check_mismatch";
    e.file_path.clear();
    assert(notify::SilenceObjectKey(e) == "proc:/usr/bin/cat:999");

    // 全空 → "-"（仅剩 rule_id 维度）
    e.exe.clear();
    e.pid = 0;
    assert(notify::SilenceObjectKey(e) == "-");
    printf("  [PASS] NRT-003: 静默对象 key\n");
}

// ====== NRT-004: 静默窗口判定 ======
void test_silence_window() {
    const auto t0 = steady_clock::now();

    // 窗口内活跃（抑制）
    assert(notify::SilenceWindowActive(t0, t0 + seconds(599), 600));
    // 窗口边界/超时 → 不抑制
    assert(!notify::SilenceWindowActive(t0, t0 + seconds(600), 600));
    assert(!notify::SilenceWindowActive(t0, t0 + seconds(601), 600));
    // 窗口 <=0 → 静默关闭，永不抑制
    assert(!notify::SilenceWindowActive(t0, t0, 0));
    assert(!notify::SilenceWindowActive(t0, t0, -5));
    printf("  [PASS] NRT-004: 静默窗口判定\n");
}

// ====== NRT-005: 聚合窗口动作（W5 D5）======
void test_aggregation_action() {
    const auto t0 = steady_clock::now();

    // 无窗口 → 开新窗并立即发（首条不延迟）
    assert(notify::AggregationAction(false, t0, t0, 300) == notify::AggAction::kOpenAndSend);
    // 窗口活跃 → 合并（窗内任意点，含边界前 1s）
    assert(notify::AggregationAction(true, t0, t0, 300) == notify::AggAction::kMerge);
    assert(notify::AggregationAction(true, t0, t0 + seconds(299), 300) == notify::AggAction::kMerge);
    // 窗口到期（含边界）→ 先 flush 旧窗摘要，本条开新窗立即发
    assert(notify::AggregationAction(true, t0, t0 + seconds(300), 300) == notify::AggAction::kFlushAndSend);
    assert(notify::AggregationAction(true, t0, t0 + seconds(600), 300) == notify::AggAction::kFlushAndSend);
    // 窗口 <=0 → 聚合关闭语义：恒为开窗直发（调用方以 cfg>0 为前置，此处防御）
    assert(notify::AggregationAction(true, t0, t0, 0) == notify::AggAction::kFlushAndSend);
    printf("  [PASS] NRT-005: 聚合窗口动作\n");
}

int main() {
    printf("=== test_notify_router ===\n");
    test_route_matrix();
    test_route_edge();
    test_silence_object_key();
    test_silence_window();
    test_aggregation_action();
    printf("=== all notify_router tests passed ===\n");
    return 0;
}
