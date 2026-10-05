#!/bin/bash
# 用例 04 容器内执行 docker 命令（挂载 docker.sock）：攻击动作
# 优先用官方 docker 镜像；拉取失败时降级为 baseline-guard:dev（Ubuntu/glibc）挂载宿主机 docker 客户端
source "$(dirname "$0")/../lib.sh"
tag="${1:-case-04-r1}"
mark_begin "$tag"

run_in_docker_image() {
    docker run --rm \
        -v /var/run/docker.sock:/var/run/docker.sock \
        docker sh -c "docker ps" >/dev/null 2>&1
}

run_fallback() {
    docker run --rm \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v /usr/bin/docker:/usr/bin/docker:ro \
        -e HOME=/tmp \
        --entrypoint docker \
        baseline-guard:dev ps >/dev/null 2>&1
}

if docker image inspect docker >/dev/null 2>&1; then
    run_in_docker_image
elif docker pull docker >/dev/null 2>&1; then
    run_in_docker_image
else
    echo "WARN: docker 镜像不可用，降级为 baseline-guard:dev + 挂载宿主机 docker 客户端" >&2
    run_fallback
fi
exit 0
