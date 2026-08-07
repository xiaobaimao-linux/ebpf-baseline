#!/bin/bash
# 测试运行脚本

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 清理并编译
rm -f test_config test_utils
make unit 2>&1

# 运行单元测试
./test_config > /tmp/test_results.txt 2>&1
echo "test_config exit: $?" >> /tmp/test_results.txt

./test_utils >> /tmp/test_results.txt 2>&1
echo "test_utils exit: $?" >> /tmp/test_results.txt

# 运行集成测试
echo "" >> /tmp/test_results.txt
echo "=== Integration Tests ===" >> /tmp/test_results.txt
bash integration/test_check.sh >> /tmp/test_results.txt 2>&1
echo "integration exit: $?" >> /tmp/test_results.txt

# 运行端到端测试
echo "" >> /tmp/test_results.txt
echo "=== E2E Tests ===" >> /tmp/test_results.txt
bash e2e/test_workflow.sh >> /tmp/test_results.txt 2>&1
echo "e2e exit: $?" >> /tmp/test_results.txt

echo "All tests completed" >> /tmp/test_results.txt
