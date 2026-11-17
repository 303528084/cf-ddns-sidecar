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

chown_ok=0
if chown -R app:app "$DATA_DIR" 2>/dev/null; then
    chown_ok=1
else
    echo "[警告] 无法修改 $DATA_DIR 的属主，配置可能保存失败。" >&2
    echo "       请检查该目录是否挂载为可写（不要只读挂载）。" >&2
fi

# 目录给到可读写执行，保证容器内 app 用户能建子目录。
chmod 0777 "$DATA_DIR" 2>/dev/null || true

# 含密钥/密码的三个文件单独收紧权限。
# 属主改成功了就用 0600（仅 app 可读）；改失败说明文件还是 root 的，
# 这时必须给其他用户读权限，否则 app 用户读不到密码，会误判成
# 「未设置后台密码」而以无密码方式启动。
for f in ddns.env config.json dashboard-password; do
    [ -f "$DATA_DIR/$f" ] || continue
    if [ "$chown_ok" = "1" ]; then
        chmod 0600 "$DATA_DIR/$f" 2>/dev/null || true
    else
        chmod 0644 "$DATA_DIR/$f" 2>/dev/null || true
    fi
done

exec su-exec app:app "$APP_BIN" "$@"
