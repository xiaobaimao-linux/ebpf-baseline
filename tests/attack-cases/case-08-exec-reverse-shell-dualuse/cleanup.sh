#!/bin/bash
# 用例 08 清理：杀掉残留的 nc 监听
pkill -f "nc -l 127.0.0.1 4408" 2>/dev/null
exit 0
