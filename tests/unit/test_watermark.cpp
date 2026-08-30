// 单元测试：四级水位控制器
// 编译: g++ -std=c++17 -I../../src -I../../src/monitor -I../../src/common \
//       -I../../src/alerts -I../../src/storage -I../../src/cli -I../../bpf \
//       -o test_watermark test_watermark.cpp \
//       ../../src/monitor/watermark_backpressure.cpp \
//       ../../src/storage/baseline_db.cpp ../../src/common/commonfun.cpp \
//       -lsqlite3 -lfmt -lssl -lcrypto -lbpf

#include <cassert>
#include <cstdio>
#include <string>
#include "watermark_backpressure.hpp"

// ====== WM-001: 正常水位判定 (0%~70%) ======
void test_watermark_normal() {
    WatermarkBackpressure bp;

    bp.SetUtilization(0.0);
    assert(bp.GetWatermarkLevel() == WATERMARK_NORMAL);
    assert(bp.GetUtilization() == 0.0);

    bp.SetUtilization(50.0);
    assert(bp.GetWatermarkLevel() == WATERMARK_NORMAL);

    bp.SetUtilization(69.9);
    assert(bp.GetWatermarkLevel() == WATERMARK_NORMAL);

    printf("  [PASS] WM-001: 正常水位判定 (0%%~70%%)\n");
}

// ====== WM-002: 预警水位判定 (70%~85%) ======
void test_watermark_warning() {
    WatermarkBackpressure bp;

    bp.SetUtilization(70.0);
    assert(bp.GetWatermarkLevel() == WATERMARK_WARNING);

    bp.SetUtilization(80.0);
    assert(bp.GetWatermarkLevel() == WATERMARK_WARNING);

    bp.SetUtilization(84.9);
    assert(bp.GetWatermarkLevel() == WATERMARK_WARNING);

    printf("  [PASS] WM-002: 预警水位判定 (70%%~85%%)\n");
}

// ====== WM-003: 高水位判定 (85%~95%) ======
void test_watermark_high() {
    WatermarkBackpressure bp;

    bp.SetUtilization(85.0);
    assert(bp.GetWatermarkLevel() == WATERMARK_HIGH);

    bp.SetUtilization(90.0);
    assert(bp.GetWatermarkLevel() == WATERMARK_HIGH);

    bp.SetUtilization(94.9);
    assert(bp.GetWatermarkLevel() == WATERMARK_HIGH);

    printf("  [PASS] WM-003: 高水位判定 (85%%~95%%)\n");
}

// ====== WM-004: 过载水位判定 (95%~100%) ======
void test_watermark_overload() {
    WatermarkBackpressure bp;

    bp.SetUtilization(95.0);
    assert(bp.GetWatermarkLevel() == WATERMARK_OVERLOAD);

    bp.SetUtilization(99.9);
    assert(bp.GetWatermarkLevel() == WATERMARK_OVERLOAD);

    bp.SetUtilization(100.0);
    assert(bp.GetWatermarkLevel() == WATERMARK_OVERLOAD);

    printf("  [PASS] WM-004: 过载水位判定 (95%%~100%%)\n");
}

// ====== WM-005: 利用率边界值钳制 ======
void test_utilization_clamp() {
    WatermarkBackpressure bp;

    bp.SetUtilization(-10.0);
    assert(bp.GetUtilization() == 0.0);

    bp.SetUtilization(150.0);
    assert(bp.GetUtilization() == 100.0);

    printf("  [PASS] WM-005: 利用率边界值钳制\n");
}

// ====== WM-006: 水位边界精确值 ======
void test_watermark_boundaries() {
    WatermarkBackpressure bp;

    // 69.999 → NORMAL
    bp.SetUtilization(69.999);
    assert(bp.GetWatermarkLevel() == WATERMARK_NORMAL);

    // 70.0 → WARNING
    bp.SetUtilization(70.0);
    assert(bp.GetWatermarkLevel() == WATERMARK_WARNING);

    // 84.999 → WARNING
    bp.SetUtilization(84.999);
    assert(bp.GetWatermarkLevel() == WATERMARK_WARNING);

    // 85.0 → HIGH
    bp.SetUtilization(85.0);
    assert(bp.GetWatermarkLevel() == WATERMARK_HIGH);

    // 94.999 → HIGH
    bp.SetUtilization(94.999);
    assert(bp.GetWatermarkLevel() == WATERMARK_HIGH);

    // 95.0 → OVERLOAD
    bp.SetUtilization(95.0);
    assert(bp.GetWatermarkLevel() == WATERMARK_OVERLOAD);

    printf("  [PASS] WM-006: 水位边界精确值\n");
}

// ====== WM-007: LevelToString 转换 ======
void test_level_to_string() {
    assert(std::string(WatermarkBackpressure::LevelToString(WATERMARK_NORMAL))   == "normal");
    assert(std::string(WatermarkBackpressure::LevelToString(WATERMARK_WARNING))  == "warning");
    assert(std::string(WatermarkBackpressure::LevelToString(WATERMARK_HIGH))     == "high");
    assert(std::string(WatermarkBackpressure::LevelToString(WATERMARK_OVERLOAD)) == "overload");

    printf("  [PASS] WM-007: LevelToString 转换\n");
}

// ====== WM-008: 默认构造状态 ======
void test_default_state() {
    WatermarkBackpressure bp;

    assert(bp.GetUtilization() == 0.0);
    assert(bp.GetWatermarkLevel() == WATERMARK_NORMAL);

    printf("  [PASS] WM-008: 默认构造状态\n");
}

int main() {
    printf("=== test_watermark ===\n");

    test_watermark_normal();
    test_watermark_warning();
    test_watermark_high();
    test_watermark_overload();
    test_utilization_clamp();
    test_watermark_boundaries();
    test_level_to_string();
    test_default_state();

    printf("=== all watermark tests passed ===\n");
    return 0;
}
