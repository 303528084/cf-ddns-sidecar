#!/usr/bin/env sh
# 本地多架构构建脚本（不依赖 GitHub Actions 时使用）。
# 工单 04 验收产物：供无 CI 环境时手动构建 amd64 + arm64 双架构镜像。
#
# 用法：
#   DOCKERHUB_REPO=yourname/cf-ddns-sidecar IMAGE_TAG=v1.0.0 ./scripts/build-multiarch.sh
#   加 PUSH=1 同时推送到 DockerHub（需先 docker login）
set -e

REPO="${DOCKERHUB_REPO:?请设置 DOCKERHUB_REPO，例如 yourname/cf-ddns-sidecar}"
TAG="${IMAGE_TAG:-latest}"

ARGS="--platform linux/amd64,linux/arm64 \
  --build-arg VERSION=${TAG#v} \
  -t ${REPO}:${TAG} \
  -t ${REPO}:latest"

if [ "${PUSH:-0}" = "1" ]; then
  echo "[build] 构建并推送 ${REPO}:${TAG} (amd64+arm64)"
  # shellcheck disable=SC2086
  docker buildx build $ARGS --push .
else
  echo "[build] 本地构建 ${REPO}:${TAG} (amd64+arm64，仅加载 amd64 到本地)"
  # shellcheck disable=SC2086
  docker buildx build $ARGS --load .
fi
