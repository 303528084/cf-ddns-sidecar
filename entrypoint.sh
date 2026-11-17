#!/bin/sh
# 一体化容器的启动入口：同一容器内同时运行两个进程。
#
#   1) cf-dns-select   主体：测速 + 写入 AdGuard Home，提供 Dashboard（:8080）
#   2) ddns-sidecar    旁路：读取主体产出的最优 IP，推送到自有域名 DDNS
#
# 之所以合进一个容器而不是拆成两个：对飞牛用户来说「一个应用 = 一个容器」，
# 只看到一个容器、一个数据目录、一个后台入口，心智负担最小。
# 两个进程共享同一个数据目录 /app/data，主体写 config.json，旁路读它。
set -u

log() { echo "[entrypoint] $*"; }

# Dashboard 登录密码：优先用环境变量；否则读安装时生成一次的随机密码文件。
# 不这么做的话主体每次重启都会重新生成随机密码，用户根本记不住。
if [ -z "${DSA_PASSWORD:-}" ] && [ -f /app/data/dashboard-password ]; then
    DSA_PASSWORD="$(cat /app/data/dashboard-password 2>/dev/null)"
    if [ -n "$DSA_PASSWORD" ]; then
        export DSA_PASSWORD
        log "Dashboard 登录密码取自 /app/data/dashboard-password"
    fi
fi

# ---- 主体：Dashboard（:8080）+ 测速 + 写 AdGuard Home ----
/usr/local/bin/cf-dns-select &
SUBJECT_PID=$!
log "主体 cf-dns-select 已启动 (pid $SUBJECT_PID)，后台地址 http://<NAS的IP>:8080/"

# ---- 旁路：读最优 IP → 推送 DDNS（监听 :18080 仅作健康检查，避开主体的 8080）----
/usr/local/bin/ddns-sidecar &
SIDECAR_PID=$!
log "旁路 ddns-sidecar 已启动 (pid $SIDECAR_PID)"

# 任一进程退出则整体退出，交给 Docker 的 restart 策略重启整个容器。
# 不做单进程重启，是因为两个进程共享数据目录，状态不一致比整体重启更难排查。
while kill -0 "$SUBJECT_PID" 2>/dev/null && kill -0 "$SIDECAR_PID" 2>/dev/null; do
    sleep 5
done

log "检测到子进程退出，容器将在 5 秒后重启..."
kill -TERM "$SUBJECT_PID" "$SIDECAR_PID" 2>/dev/null
wait 2>/dev/null
exit 1
