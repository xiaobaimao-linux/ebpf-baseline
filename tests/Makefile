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
unit: test_config test_utils test_watermark test_event_bus test_process_tree test_whitelist test_rule_dsl test_gpu_collector test_model_files test_ai_workload
	@echo "=== Running unit tests ==="
	./test_config
	./test_utils
	./test_watermark
	./test_event_bus
	./test_process_tree
	./test_whitelist
	./test_rule_dsl
	./test_gpu_collector
	./test_model_files
	./test_ai_workload

test_config: unit/test_config.cpp $(CONFIG_SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $< $(CONFIG_SRCS) $(LDFLAGS_COMMON) $(LDFLAGS_SSL)

test_utils: unit/test_utils.cpp $(SRC_DIR)/common/utils.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(SRC_DIR)/common/utils.cpp $(LDFLAGS_COMMON) $(LDFLAGS_SSL)

test_watermark: unit/test_watermark.cpp $(SRC_DIR)/baseline/watermark_backpressure.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(SRC_DIR)/baseline/watermark_backpressure.cpp $(LDFLAGS_COMMON) $(LDFLAGS_SSL) -lbpf

test_event_bus: unit/test_event_bus.cpp $(SRC_DIR)/telemetry/event_bus.cpp
	$(CXX) $(CXXFLAGS) -I$(SRC_DIR)/telemetry -o $@ $< $(SRC_DIR)/telemetry/event_bus.cpp -lpthread

test_process_tree: unit/test_process_tree.cpp $(SRC_DIR)/telemetry/process_tree.cpp $(SRC_DIR)/common/container.cpp
	$(CXX) $(CXXFLAGS) -I$(SRC_DIR)/telemetry -o $@ $< $(SRC_DIR)/telemetry/process_tree.cpp $(SRC_DIR)/common/container.cpp $(LDFLAGS_COMMON)

test_whitelist: unit/test_whitelist.cpp $(SRC_DIR)/baseline/whitelist.cpp $(SRC_DIR)/common/container.cpp $(CONFIG_SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $< $(SRC_DIR)/baseline/whitelist.cpp $(SRC_DIR)/common/container.cpp $(CONFIG_SRCS) $(LDFLAGS_COMMON) $(LDFLAGS_SSL)

DETECT_SRCS = $(SRC_DIR)/detect/condition_parser.cpp $(SRC_DIR)/detect/rule_loader.cpp $(SRC_DIR)/detect/rule_engine.cpp

test_rule_dsl: unit/test_rule_dsl.cpp $(DETECT_SRCS)
	$(CXX) $(CXXFLAGS) -I$(SRC_DIR)/detect -o $@ $< $(DETECT_SRCS) $(LDFLAGS_COMMON)

test_gpu_collector: unit/test_gpu_collector.cpp $(SRC_DIR)/asset/gpu_collector.cpp
	$(CXX) $(CXXFLAGS) -I$(SRC_DIR)/asset -o $@ $< $(SRC_DIR)/asset/gpu_collector.cpp $(LDFLAGS_COMMON)

test_model_files: unit/test_model_files.cpp $(SRC_DIR)/asset/model_file_collector.cpp
	$(CXX) $(CXXFLAGS) -I$(SRC_DIR)/asset -o $@ $< $(SRC_DIR)/asset/model_file_collector.cpp $(LDFLAGS_COMMON)

test_ai_workload: unit/test_ai_workload.cpp $(SRC_DIR)/asset/asset_collector.cpp
	$(CXX) $(CXXFLAGS) -I$(SRC_DIR)/asset -o $@ $< $(SRC_DIR)/asset/asset_collector.cpp $(LDFLAGS_COMMON)

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
	rm -f test_config test_utils test_watermark test_event_bus test_rule_dsl test_process_tree test_whitelist test_gpu_collector test_model_files test_ai_workload
	rm -rf /tmp/baseline_test_* /tmp/baseline_monitor_test_* /tmp/baseline_rdsl_* /tmp/baseline_guard_modeltest_*
