CXX = g++
CC = gcc
BPF_CC = clang

INCLUDE_DIRS = -I./include \
               -I./src \
               -I./src/alerts \
               -I./src/baseline \
               -I./src/check \
               -I./src/cli \
               -I./src/common \
               -I./src/monitor \
               -I./src/report \
               -I./src/stats \
               -I./src/storage \
               -I./bpf

CXXFLAGS = -std=c++17 -Wall -Wextra -g -MMD -MP $(INCLUDE_DIRS)
BPF_CFLAGS = -target bpf -D__TARGET_ARCH_x86 \
             -I/usr/include/x86_64-linux-gnu \
             -I/usr/include/bpf -g -O2

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

# 用户态源文件
MAIN_SRCS = src/main.cpp \
            src/alerts/alert_manager.cpp \
            src/baseline/baseline_check.cpp \
            src/baseline/baseline_clean.cpp \
            src/baseline/baseline_delete.cpp \
            src/baseline/baseline_list.cpp \
            src/baseline/baseline_snapshot.cpp \
            src/check/check.cpp \
            src/cli/config.cpp \
            src/common/commonfun.cpp \
            src/common/utils.cpp \
            src/monitor/monitor_baseline.cpp \
            src/report/report_generator.cpp \
            src/storage/baseline_db.cpp
MONITOR_SRC = src/monitor/monitor.cpp src/monitor/watermark_backpressure.cpp
STATS_SRC = src/stats/stats.cpp

OBJS = $(MAIN_SRCS:.cpp=.o) $(MONITOR_SRC:.cpp=.o) $(STATS_SRC:.cpp=.o)
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

# 编译用户态源文件
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# monitor 依赖生成的 skeleton 头文件
src/monitor/monitor.o: src/monitor/monitor.cpp $(BPF_SKEL) $(BPF_SKEL_PERF) $(BPF_KPROBE_SKEL)
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
	rm -f $(TARGET) $(BPF_OBJ) $(BPF_SKEL) $(BPF_OBJ_PERF) $(BPF_SKEL_PERF) $(BPF_KPROBE_OBJ) $(BPF_KPROBE_SKEL)

-include $(DEPS)