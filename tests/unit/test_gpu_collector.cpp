// 单元测试：GPU 采集器 nvidia-smi csv 解析（fixture 驱动，本机无需 NVIDIA 卡）
// 编译见 tests/Makefile test_gpu_collector

#include <cassert>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>

#include "gpu_collector.hpp"

static std::string ReadFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// ====== GPU-001: 真实 csv fixture 解析 ======
void test_parse_fixture() {
    const std::string csv = ReadFile("fixtures/nvidia_smi_sample.csv");
    assert(!csv.empty());
    const auto gpus = ParseNvidiaSmiCsv(csv);
    assert(gpus.size() == 3);

    assert(gpus[0].vendor == "nvidia");
    assert(gpus[0].model == "NVIDIA GeForce RTX 4090");
    assert(gpus[0].driver == "550.54.15");
    assert(gpus[0].mem_total_mb == 24564);
    assert(gpus[0].mem_used_mb == 1812);
    assert(gpus[0].util_pct == 23);

    assert(gpus[1].model == "NVIDIA A100-SXM4-80GB");
    assert(gpus[1].mem_total_mb == 81920);
    assert(gpus[1].mem_used_mb == 0);
    assert(gpus[1].util_pct == 0);

    // [N/A] 字段降级为 -1，不丢卡
    assert(gpus[2].model == "Tesla T4");
    assert(gpus[2].mem_used_mb == -1);
    assert(gpus[2].util_pct == -1);
    printf("  [PASS] GPU-001: nvidia-smi fixture 解析\n");
}

// ====== GPU-002: 空输入（无卡）返回空数组 ======
void test_parse_empty() {
    assert(ParseNvidiaSmiCsv("").empty());
    assert(ParseNvidiaSmiCsv("\n\n").empty());
    printf("  [PASS] GPU-002: 空输入返回空数组\n");
}

// ====== GPU-003: 型号含逗号时按右侧固定 4 字段切分 ======
void test_parse_model_with_comma() {
    const auto gpus =
        ParseNvidiaSmiCsv("NVIDIA H100 80GB HBM3, MIG 1g.10gb, 535.104.05, 81559 MiB, 128 MiB, 5 %\n");
    assert(gpus.size() == 1);
    assert(gpus[0].model == "NVIDIA H100 80GB HBM3, MIG 1g.10gb");
    assert(gpus[0].driver == "535.104.05");
    assert(gpus[0].mem_total_mb == 81559);
    assert(gpus[0].util_pct == 5);
    printf("  [PASS] GPU-003: 型号含逗号\n");
}

// ====== GPU-004: 字段不足的坏行跳过，不影响其他行 ======
void test_parse_bad_line() {
    const auto gpus = ParseNvidiaSmiCsv("broken line\nTesla V100, 470.82.01, 16384 MiB, 64 MiB, 3 %\n");
    assert(gpus.size() == 1);
    assert(gpus[0].model == "Tesla V100");
    printf("  [PASS] GPU-004: 坏行跳过\n");
}

// ====== GPU-005: 未适配 stub 语义 ======
void test_stubs() {
    AscendCollector ascend;
    DcuCollector dcu;
    assert(ascend.vendor() == "ascend");
    assert(dcu.vendor() == "dcu");
    assert(!ascend.adapted());
    assert(!dcu.adapted());
    assert(ascend.collect().empty());
    assert(dcu.collect().empty());
    printf("  [PASS] GPU-005: 国产 GPU stub（未适配标记）\n");
}

int main() {
    test_parse_fixture();
    test_parse_empty();
    test_parse_model_with_comma();
    test_parse_bad_line();
    test_stubs();
    printf("All gpu_collector tests passed!\n");
    return 0;
}
