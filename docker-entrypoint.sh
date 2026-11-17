#!/bin/sh
# 容器入口：先以 root 修正数据目录和备份目录的所有权，再降权到 app 用户运行主程序。
#
# 为什么必须这么做：
#   /app/data 是挂载进来的 NAS 宿主机目录，它的属主和 ACL 由飞牛决定，
#   不受镜像控制。如果直接用非 root 用户启动，会出现
#     mkdir /app/data/cfnb: permission denied
#     open /app/data/.cfddns-xxx: permission denied
#   这两个报错分别对应「测速」和「保存设置」失败。
#
# 备份目录为什么也要管（v1.4.1 补的）：
#   真机 2026-11-17 19:51 打出了
#     [警告] 备份目录 /app/backup 在，但容器里写不进去（权限或只读挂载）
#   数据目录一切正常、只有备份目录写不进去，差别就在这段代码——以前只 chown 了
#   /app/data。备份目录的权限全靠宿主机脚本 cmd/main 去改，而那个脚本是用
#   package 用户跑的：目录一旦属于 root（上一版留下来的、或者平台建的），
#   package 用户 chown/chmod 都改不动，于是「目录在、就是写不进去」。
#   容器内的 root 能改——对挂载点 chown 会直接作用到宿主机上的真实目录。
#
# 权限处理只针对目录本身，不改用户自己放进去的其他文件内容。
set -e

DATA_DIR="${CFDDNS_DATA_DIR:-/app/data}"
BACKUP_DIR="${CFDDNS_BACKUP_DIR:-/app/backup}"
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

# —— 备份目录（v1.4.1）——
#
# 跟数据目录同一套逻辑，但有一处刻意不同：**不把里面的文件放开权限**。
# 备份里放的是配置副本（含密钥），只需要目录本身可写就够了；文件保持
# writeSnapshot 写下的原权限（config.json 0600、其余 0644）。
mkdir -p "$BACKUP_DIR" 2>/dev/null || true
if [ -d "$BACKUP_DIR" ]; then
    if chown -R app:app "$BACKUP_DIR" 2>/dev/null; then
        chmod 0755 "$BACKUP_DIR" 2>/dev/null || true
    else
        # 属主改不动（目录属于宿主机上别的用户，且连容器内 root 都没权限，
        # 比如 root-squash 的 NFS）→ 放开写权限当兜底。
        # 宁可权限宽一点，也不要让「每次保存都备不了份」这件事安静发生。
        chmod 0777 "$BACKUP_DIR" 2>/dev/null || true
        echo "[警告] 无法修改 $BACKUP_DIR 的属主，已尝试开放写权限。" >&2
    fi
fi

exec su-exec app:app "$APP_BIN" "$@"
