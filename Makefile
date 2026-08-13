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
               -I./src/storage \
               -I./bpf

CXXFLAGS = -std=c++17 -Wall -Wextra -g -MMD -MP $(INCLUDE_DIRS)
BPF_CFLAGS = -target bpf -D__TARGET_ARCH_x86_64 \
             -I/usr/include/x86_64-linux-gnu \
             -I/usr/include/bpf -g -O2

LDFLAGS = -lbpf -lssl -lcrypto -lfmt -lyaml-cpp -lsqlite3 -lcurl

TARGET = baseline-guard

BPF_SRC = bpf/lsm_file.bpf.c
BPF_OBJ = bpf/lsm_file.bpf.o
BPF_SKEL = bpf/lsm_file.skel.h

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
MONITOR_SRC = src/monitor/monitor.cpp

OBJS = $(MAIN_SRCS:.cpp=.o) $(MONITOR_SRC:.cpp=.o)
DEPS = $(OBJS:.o=.d)

.PHONY: all clean test test-monitor test-snapshot

all: $(TARGET)

# BPF 编译
$(BPF_OBJ): $(BPF_SRC) bpf/event.h
	$(BPF_CC) $(BPF_CFLAGS) -c -o $@ $<

$(BPF_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

# 编译用户态源文件
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# monitor 依赖生成的 skeleton 头文件
src/monitor/monitor.o: src/monitor/monitor.cpp $(BPF_SKEL)
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
	rm -f $(TARGET) $(BPF_OBJ) $(BPF_SKEL)

-include $(DEPS)