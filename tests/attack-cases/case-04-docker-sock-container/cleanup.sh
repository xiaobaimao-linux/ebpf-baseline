#!/bin/bash
# 用例 04 清理：容器以 --rm 运行，无残留
docker rm -f $(docker ps -aq --filter ancestor=docker) 2>/dev/null
exit 0
