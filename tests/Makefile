# baseline-guard 测试 Makefile

CXX = g++
CXXFLAGS = -std=c++17 -Wall -I../include -I../src -I../src/cli -I../src/common -I../src/baseline \
           -I../src/alerts -I../src/storage -I../bpf -I/usr/include/x86_64-linux-gnu -g
LDFLAGS_COMMON = -lfmt -lyaml-cpp -lsqlite3 -g
LDFLAGS_SSL = -lssl -lcrypto -g

PROJECT_ROOT = $(shell dirname $(PWD))
SRC_DIR = $(PROJECT_ROOT)/src

# 源文件
CONFIG_SRCS = $(SRC_DIR)/cli/config.cpp $(SRC_DIR)/common/utils.cpp

.PHONY: all unit integration e2e clean

all: unit integration

# ====== 单元测试 ======
unit: test_config test_utils test_watermark
	@echo "=== Running unit tests ==="
	./test_config
	./test_utils
	./test_watermark

test_config: unit/test_config.cpp $(CONFIG_SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $< $(CONFIG_SRCS) $(LDFLAGS_COMMON) $(LDFLAGS_SSL)

test_utils: unit/test_utils.cpp $(SRC_DIR)/common/utils.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(SRC_DIR)/common/utils.cpp $(LDFLAGS_COMMON) $(LDFLAGS_SSL)

test_watermark: unit/test_watermark.cpp $(SRC_DIR)/baseline/watermark_backpressure.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(SRC_DIR)/baseline/watermark_backpressure.cpp $(LDFLAGS_COMMON) $(LDFLAGS_SSL) -lbpf

# ====== 集成测试 ======
integration:
	@echo "=== Running integration tests ==="
	@echo "Note: monitor tests require root and BPF LSM support"
	bash integration/test_check.sh
	@echo "To run monitor tests: sudo bash integration/test_monitor.sh"

# ====== 端到端测试 ======
e2e:
	@echo "=== Running E2E tests ==="
	bash e2e/test_workflow.sh

clean:
	rm -f test_config test_utils test_watermark
	rm -rf /tmp/baseline_test_* /tmp/baseline_monitor_test_*
