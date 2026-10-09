#!/bin/bash
# 用例 07 清理：杀掉残留的 nc 监听
pkill -f "nc -l 127.0.0.1 4407" 2>/dev/null
exit 0
