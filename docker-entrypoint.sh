#!/bin/sh
# 容器入口：先以 root 修正数据目录所有权，再降权到 app 用户运行主程序。
#
# 为什么必须这么做：
#   /app/data 是挂载进来的 NAS 宿主机目录，它的属主和 ACL 由飞牛决定，
#   不受镜像控制。如果直接用非 root 用户启动，会出现
#     mkdir /app/data/cfnb: permission denied
#     open /app/data/.cfddns-xxx: permission denied
#   这两个报错分别对应「测速」和「保存设置」失败。
#
# 权限处理只针对目录本身，不改用户自己放进去的其他文件内容。
set -e

DATA_DIR="${CFDDNS_DATA_DIR:-/app/data}"
APP_BIN="/usr/local/bin/cf-ddns-sidecar"

if [ "$(id -u)" != "0" ]; then
    # 用户显式指定了 --user，尊重它，不再尝试改权限
    exec "$APP_BIN" "$@"
fi

mkdir -p "$DATA_DIR" 2>/dev/null || true

if ! chown -R app:app "$DATA_DIR" 2>/dev/null; then
    echo "[警告] 无法修改 $DATA_DIR 的属主，配置可能保存失败。" >&2
    echo "       请检查该目录是否挂载为可写（不要只读挂载）。" >&2
fi

# 目录给到可读写执行，保证容器内 app 用户能建子目录；
# 已有文件保持自己的权限，仅对含密钥的文件收紧一次。
chmod 0777 "$DATA_DIR" 2>/dev/null || true
for f in ddns.env config.json dashboard-password; do
    [ -f "$DATA_DIR/$f" ] && chmod 0600 "$DATA_DIR/$f" 2>/dev/null || true
done

exec su-exec app:app "$APP_BIN" "$@"
