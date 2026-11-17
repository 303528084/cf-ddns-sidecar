# ===== 阶段 1：交叉编译旁路二进制（适配 buildx 多架构） =====
FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /ddns-sidecar .

# ===== 阶段 2：从上游官方镜像取主体二进制（主体源码零改动） =====
# 主体 cf-dns-select 是独立开源项目，此处只取它的可执行文件与 IP 段文件，
# 不 fork、不改源码，上游更新后重新构建本镜像即可跟进。
FROM ghcr.io/neon9809/cf-dns-select:latest AS subject

# ===== 可选目标：只跑旁路的精简镜像（高级用户单独部署时用） =====
# 构建：docker build --target sidecar -t cf-ddns-sidecar:sidecar .
FROM alpine:3.20 AS sidecar

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S -g 1000 ddns && adduser -S -u 1000 -G ddns ddns

WORKDIR /app
COPY --from=builder /ddns-sidecar /usr/local/bin/ddns-sidecar
RUN mkdir -p /app/config /app/data /app/subject && chown -R ddns:ddns /app
USER ddns

ENV TZ=Asia/Shanghai
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null 2>&1 || exit 1

ENTRYPOINT ["ddns-sidecar"]
CMD ["-c", "/app/config/config.yaml"]

# ===== 阶段 3（默认目标）：一体化运行镜像，单容器跑两个进程 =====
FROM alpine:3.20 AS allinone

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S -g 1000 app && adduser -S -u 1000 -G app app

WORKDIR /app

# 主体：Dashboard + 测速 + 写 AdGuard Home
COPY --from=subject /usr/local/bin/cf-dns-select /usr/local/bin/cf-dns-select
COPY --from=subject /app/ip.txt /app/ip.txt
COPY --from=subject /app/ipv6.txt /app/ipv6.txt

# 旁路：读最优 IP 推送 DDNS
COPY --from=builder /ddns-sidecar /usr/local/bin/ddns-sidecar
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod 0755 /usr/local/bin/entrypoint.sh && \
    mkdir -p /app/data && chown -R app:app /app

USER app

# 两个进程的路径约定：数据统一放在 /app/data（宿主机一个目录挂进来即可）。
# 旁路监听 18080 只用于健康检查，避开主体的 8080。
ENV TZ=Asia/Shanghai \
    DSA_CONFIG=/app/data/config.json \
    CFDDNS_SUBJECT_CONFIG_PATH=/app/data/config.json \
    CFDDNS_STATE_PATH=/app/data/sidecar-state.json \
    CFDDNS_LISTEN=:18080

EXPOSE 8080

# 健康检查打主体的 /api/health（dashboard 存活即代表主体可用）
HEALTHCHECK --interval=60s --timeout=5s --start-period=20s \
    CMD wget -qO- http://127.0.0.1:8080/api/health >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
