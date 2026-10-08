// 单元测试：AI 工作负载进程识别（纯函数 AiWorkloadSignals/IsAiWorkload，
// 构造 cmdline/environ/maps 字符串喂入，不依赖真实进程与 NVIDIA 硬件）
// 编译见 tests/Makefile test_ai_workload

#include <cassert>
#include <cstdio>
#include <string>
#include <vector>

#include "asset_collector.hpp"

namespace {

bool HasSignal(const std::vector<std::string>& signals, const std::string& want) {
    for (const auto& s : signals) {
        if (s == want) {
            return true;
        }
    }
    return false;
}

// NUL 分隔的环境变量串
std::string MakeEnviron(std::initializer_list<const char*> vars) {
    std::string out;
    for (const char* v : vars) {
        out += v;
        out += '\0';
    }
    return out;
}

// ====== AIW-001: cmdline 含 torch/tensorflow 关键路径 → 命中 ======
void test_cmdline_framework_path() {
    const std::string torch_cmd =
        "python3 /home/u/.local/lib/python3.10/site-packages/torch/distributed/run.py";
    auto signals = AiWorkloadSignals(torch_cmd, "", "");
    assert(HasSignal(signals, "cmdline:torch_path"));
    assert(IsAiWorkload(torch_cmd, "", ""));

    const std::string tf_cmd =
        "python /usr/local/lib/python3.9/dist-packages/tensorflow/python/train.py";
    signals = AiWorkloadSignals(tf_cmd, "", "");
    assert(HasSignal(signals, "cmdline:tensorflow_path"));
    assert(IsAiWorkload(tf_cmd, "", ""));
}

// ====== AIW-002: maps 加载 libcuda.so / libnvidia-ml.so → 命中（含版本后缀） ======
void test_maps_cuda_libs() {
    const std::string maps =
        "7f8b00000000-7f8b00022000 r-xp 00000000 08:01 1 "
        "/usr/lib/x86_64-linux-gnu/libcuda.so.550.54\n"
        "7f8b00022000-7f8b00044000 r--p 00022000 08:01 1 "
        "/usr/lib/x86_64-linux-gnu/libc.so.6\n";
    auto signals = AiWorkloadSignals("python train.py", "", maps);
    assert(HasSignal(signals, "maps:libcuda"));
    assert(IsAiWorkload("python train.py", "", maps));

    const std::string ml_maps =
        "7f8b00000000-7f8b00022000 r-xp 00000000 08:01 1 "
        "/usr/lib/x86_64-linux-gnu/libnvidia-ml.so.1\n";
    signals = AiWorkloadSignals("python infer.py", "", ml_maps);
    assert(HasSignal(signals, "maps:libnvidia_ml"));
    assert(IsAiWorkload("python infer.py", "", ml_maps));
}

// ====== AIW-003: 环境变量按变量边界含 CUDA_VISIBLE_DEVICES → 命中 ======
void test_environ_cuda_visible_devices() {
    const std::string env =
        MakeEnviron({"PATH=/usr/bin", "CUDA_VISIBLE_DEVICES=0,1", "HOME=/root"});
    auto signals = AiWorkloadSignals("python train.py", env, "");
    assert(HasSignal(signals, "env:CUDA_VISIBLE_DEVICES"));
    assert(IsAiWorkload("python train.py", env, ""));

    // 边界：前缀更长的变量名不得误命中
    const std::string near_miss = MakeEnviron({"X_CUDA_VISIBLE_DEVICES=0"});
    assert(!IsAiWorkload("python train.py", near_miss, ""));
}

// ====== AIW-004: 普通 python 进程不误判（特征指向框架/CUDA，不是 python 本身） ======
void test_plain_python_not_flagged() {
    const std::string normal_maps =
        "7f8b00000000-7f8b00022000 r-xp 00000000 08:01 1 "
        "/usr/lib/x86_64-linux-gnu/libc.so.6\n"
        "7f8b00022000-7f8b00044000 r-xp 00000000 08:01 1 "
        "/usr/lib/python3.10/lib-dynload/math.cpython-310-x86_64-linux-gnu.so\n";
    const std::string normal_env = MakeEnviron({"PATH=/usr/bin", "HOME=/root"});

    assert(!IsAiWorkload("python script.py", normal_env, normal_maps));
    assert(!IsAiWorkload("python -c \"print(1)\"", normal_env, normal_maps));
    assert(AiWorkloadSignals("python script.py", normal_env, normal_maps).empty());

    // 全空输入 / 内核线程式空 cmdline
    assert(!IsAiWorkload("", "", ""));
}

} // namespace

int main() {
    test_cmdline_framework_path();
    test_maps_cuda_libs();
    test_environ_cuda_visible_devices();
    test_plain_python_not_flagged();
    std::printf("test_ai_workload: all 4 cases passed\n");
    return 0;
}
