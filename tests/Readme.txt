cd tests

# 运行所有单元测试
make unit

# 运行集成测试（check命令）
make integration

# 运行monitor集成测试（需要root）
make integration-monitor

# 运行端到端测试
make e2e

# 一键运行全部
make all