CXX = g++
CC = gcc
BPF_CC = clang

# src 子目录按 PRD 第 5 章九子系统划分：
#   asset=M1(预留) baseline=M2 detect=M3(预留) ai=M4(预留)
#   alerts=M5 storage=M6 cli=M7 ops=M8 ebpf=遥测层(预留)
INCLUDE_DIRS = -I. \
               -I./include \
               -I./src \
               -I./src/alerts \
               -I./src/asset \
               -I./src/baseline \
               -I./src/cli \
               -I./src/common \
               -I./src/detect \
               -I./src/ai \
               -I./src/ebpf \
               -I./src/ops \
               -I./src/storage \
               -I./bpf

CXXFLAGS = -std=c++17 -Wall -Wextra -g -MMD -MP $(INCLUDE_DIRS)
# -Wno-missing-declarations：完整版 vmlinux.h 含未实例化的前向声明成员，
# 会触发 -Wmissing-declarations（旧精简版 vmlinux.h 无此问题），非代码缺陷
BPF_CFLAGS = -target bpf -D__TARGET_ARCH_x86 \
             -I/usr/include/x86_64-linux-gnu \
             -I/usr/include/bpf -g -O2 -Wno-missing-declarations

LDFLAGS = -lbpf -lssl -lcrypto -lfmt -lyaml-cpp -lsqlite3 -lcurl

TARGET = baseline-guard

BPF_SRC = bpf/lsm_file.bpf.c
BPF_OBJ = bpf/lsm_file.bpf.o
BPF_SKEL = bpf/lsm_file.skel.h

# 5.7 perf buffer 版本（复用 lsm_file.bpf.c，加 -DUSE_PERF_BUFFER）
BPF_OBJ_PERF = bpf/lsm_file_perf.bpf.o
BPF_SKEL_PERF = bpf/lsm_file_perf.skel.h

# 5.4 kprobe 版本（独立源文件）
BPF_KPROBE_SRC = bpf/lsm_kprobe.bpf.c
BPF_KPROBE_OBJ = bpf/lsm_kprobe.bpf.o
BPF_KPROBE_SKEL = bpf/lsm_kprobe.skel.h

# 网络遥测版本（connect/accept/bind，独立源文件）
BPF_NET_SRC = bpf/net_watch.bpf.c
BPF_NET_OBJ = bpf/net_watch.bpf.o
BPF_NET_SKEL = bpf/net_watch.skel.h

# 用户态源文件
MAIN_SRCS = src/main.cpp \
            src/alerts/alert_manager.cpp \
            src/baseline/baseline_check.cpp \
            src/baseline/baseline_clean.cpp \
            src/baseline/baseline_delete.cpp \
            src/baseline/baseline_list.cpp \
            src/baseline/baseline_snapshot.cpp \
            src/baseline/check.cpp \
            src/baseline/monitor_baseline.cpp \
            src/baseline/report_generator.cpp \
            src/cli/config.cpp \
            src/common/commonfun.cpp \
            src/common/utils.cpp \
            src/common/container.cpp \
            src/ops/stats.cpp \
            src/storage/baseline_db.cpp
MONITOR_SRC = src/baseline/monitor.cpp \
              src/baseline/monitor_network.cpp \
              src/baseline/watermark_backpressure.cpp

OBJS = $(MAIN_SRCS:.cpp=.o) $(MONITOR_SRC:.cpp=.o)
DEPS = $(OBJS:.o=.d)

.PHONY: all clean test test-monitor test-snapshot

all: $(TARGET)

BPF_COMMON_H = bpf/bpf_common.h bpf/vmlinux.h bpf/event.h

# BPF 编译
$(BPF_OBJ): $(BPF_SRC) $(BPF_COMMON_H)
	$(BPF_CC) $(BPF_CFLAGS) -c -o $@ $<

$(BPF_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

# 5.7 perf buffer 版本
$(BPF_OBJ_PERF): $(BPF_SRC) $(BPF_COMMON_H)
	$(BPF_CC) $(BPF_CFLAGS) -DUSE_PERF_BUFFER -c -o $@ $<

$(BPF_SKEL_PERF): $(BPF_OBJ_PERF)
	bpftool gen skeleton $< > $@

# 5.4 kprobe 版本（始终使用 perf buffer）
$(BPF_KPROBE_OBJ): $(BPF_KPROBE_SRC) $(BPF_COMMON_H)
	$(BPF_CC) $(BPF_CFLAGS) -DUSE_PERF_BUFFER -c -o $@ $<

$(BPF_KPROBE_SKEL): $(BPF_KPROBE_OBJ)
	bpftool gen skeleton $< > $@

# 网络遥测版本（ring buffer，结构同 lsm_file）
BPF_NET_H = bpf/net_event.h bpf/vmlinux.h

$(BPF_NET_OBJ): $(BPF_NET_SRC) $(BPF_NET_H)
	$(BPF_CC) $(BPF_CFLAGS) -c -o $@ $<

$(BPF_NET_SKEL): $(BPF_NET_OBJ)
	bpftool gen skeleton $< > $@

# 编译用户态源文件
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# monitor 依赖生成的 skeleton 头文件
src/baseline/monitor.o: src/baseline/monitor.cpp $(BPF_SKEL) $(BPF_SKEL_PERF) $(BPF_KPROBE_SKEL)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# monitor_network 依赖 net_watch skeleton 头文件
src/baseline/monitor_network.o: src/baseline/monitor_network.cpp $(BPF_NET_SKEL)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# 链接
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

test: $(TARGET)
	./$(TARGET) check -c tests/fixtures/default.yaml

test-monitor: $(TARGET)
	sudo timeout 5 ./$(TARGET) monitor -c tests/fixtures/default.yaml || true

test-snapshot: $(TARGET)
	bash tests/integration/test_snapshot.sh

clean:
	find src -type f \( -name '*.o' -o -name '*.d' \) -delete
	rm -f $(TARGET) $(BPF_OBJ) $(BPF_SKEL) $(BPF_OBJ_PERF) $(BPF_SKEL_PERF) $(BPF_KPROBE_OBJ) $(BPF_KPROBE_SKEL) $(BPF_NET_OBJ) $(BPF_NET_SKEL)

-include $(DEPS)