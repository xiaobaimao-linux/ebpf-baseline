CXX = g++
CC = gcc
BPF_CC = clang

CXXFLAGS = -std=c++17 -Wall -Wextra -g -I./include -I./src -I./bpf
BPF_CFLAGS = -target bpf -D__TARGET_ARCH_x86_64 \
             -I/usr/include/x86_64-linux-gnu \
             -I/usr/include/bpf -g -O2

LDFLAGS = -lbpf -lssl -lcrypto -lfmt -lyaml-cpp -lsqlite3 -lcurl

TARGET = baseline-guard

BPF_SRC = bpf/lsm_file.bpf.c
BPF_OBJ = bpf/lsm_file.bpf.o
BPF_SKEL = bpf/lsm_file.skel.h

# 用户态源文件
MAIN_SRCS = src/main.cpp src/config.cpp src/check.cpp src/utils.cpp src/commonfun.cpp src/alert_manager.cpp src/report_generator.cpp
MONITOR_SRC = src/monitor.cpp

OBJS = $(MAIN_SRCS:.cpp=.o) $(MONITOR_SRC:.cpp=.o)

.PHONY: all clean test test-monitor

all: $(TARGET)

# BPF 编译
$(BPF_OBJ): $(BPF_SRC) bpf/event.h
	$(BPF_CC) $(BPF_CFLAGS) -c -o $@ $<

$(BPF_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

# 不依赖 skel.h 的源文件
src/main.o: src/main.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

src/config.o: src/config.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

src/check.o: src/check.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

src/utils.o: src/utils.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

src/commonfun.o: src/commonfun.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

src/alert_manager.o: src/alert_manager.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

src/report_generator.o: src/report_generator.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# 依赖 skel.h 的源文件
src/monitor.o: src/monitor.cpp $(BPF_SKEL)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# 链接
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

test: $(TARGET)
	./$(TARGET) check -c test/baseline.ini

test-monitor: $(TARGET)
	sudo timeout 5 ./$(TARGET) monitor -c test/baseline.ini || true

clean:
	rm -f $(OBJS) $(TARGET) $(BPF_OBJ) $(BPF_SKEL)