# ===== 构建阶段（交叉编译，适配 buildx 多架构） =====
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

# ===== 运行阶段 =====
FROM alpine:3.20
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
