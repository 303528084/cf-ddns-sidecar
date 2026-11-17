# ===== 阶段 1：交叉编译主程序（Go，适配 buildx 多架构） =====
FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY config/ config/
COPY ddns/ ddns/
COPY dns/ dns/
COPY engine/ engine/
COPY web/ web/
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /cf-ddns-sidecar .

# ===== 阶段 2：运行镜像 =====
# 基础镜像用 Python：测速引擎是 cfnb 的 Python 脚本（已经过大量真实网络验证），
# 直接复用它比自己用 Go 重写一套测速更可靠。
FROM python:3.12-alpine AS allinone

RUN apk add --no-cache ca-certificates tzdata curl su-exec && \
    pip install --no-cache-dir aiohttp requests && \
    addgroup -S -g 1000 app && adduser -S -u 1000 -G app app

WORKDIR /app

# 主程序：统一后台 + AdGuard 写入 + DDNS 推送
COPY --from=builder /cf-ddns-sidecar /usr/local/bin/cf-ddns-sidecar

# 测速引擎：cfnb（MIT，见 third_party/cfnb/LICENSE）
COPY third_party/cfnb/main.py /app/cfnb/main.py

# 入口脚本：以 root 修正挂载目录所有权后降权运行（见脚本内注释）
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

RUN mkdir -p /app/data && chown -R app:app /app

ENV TZ=Asia/Shanghai \
    CFDDNS_ENGINE=/app/cfnb/main.py

EXPOSE 8080

# 端口可配置，所以健康检查不能写死 8080：跟随 ddns.env 里的 CFDDNS_PORT。
HEALTHCHECK --interval=60s --timeout=5s --start-period=20s \
    CMD sh -c 'p=$(grep -E "^CFDDNS_PORT=" /app/data/ddns.env 2>/dev/null | tail -n 1 | cut -d= -f2 | tr -d " \r"); case "$p" in ""|*[!0-9]*) p=8080 ;; esac; wget -qO- "http://127.0.0.1:$p/api/health" >/dev/null 2>&1 || exit 1'

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
