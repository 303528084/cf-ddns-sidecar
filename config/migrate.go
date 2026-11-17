package config

import (
	"os"
	"path/filepath"
	"strings"
)

// 这个文件解决的是 v1.5.1 自己带来的问题：**换了数据目录，老数据不会自己过去**。
//
// v1.5.0 探针把数据挂载源从 `/var/apps/<app>-data` 换成飞牛官方的
// `${TRIM_PKGVAR}`（真机上核实是 `/vol1/@appdata/<app>`）。方向是对的——官方目录
// 平台升级时不会删，而自造的 `<app>-data` 一直在赌「平台只删 `<app>` 那一层」，
// 赌了三个版本。
//
// 但对老用户来说，配置还住在旧目录里，新目录天然是空的。现成的兜底是 restore.go
// 那套「空了就从备份捡」：**能救，但那是「捡」不是「搬」**。备份是空的
// （刚装完还没点过保存）、或者备份也在同一次清理里没了的时候，配置就真丢。
// 而「升级一次丢一次配置」正是这个应用被投诉最狠的事，不能让它换个形式再来一遍。
//
// 所以启动时先搬一次。三条刻意这么定：
//  1. **搬之前先看新目录有没有配置**。有就一律不动——搬迁和恢复一样，最怕的
//     就是把用户正在用的配置盖成旧的。
//  2. **旧目录不删**。搬完留着当回退点，日志会点名提醒，由用户自己决定何时清。
//  3. **只认「有 config.json 的旧目录」**。只有一个空 ddns.env 不算数，否则会把
//     空壳搬过来、把后面正规的恢复流程堵死。

// legacyDataDir 返回 v1.4.x 数据目录在容器里的挂载点。
//
// 默认 /app/legacy-data，由 compose 把宿主机的 `/var/apps/<app>-data` **只读**
// 挂进来。用环境变量覆盖是为了能在本地测试，也让自建用户能自己指定。
func legacyDataDir() string {
	if p := strings.TrimSpace(os.Getenv("CFDDNS_LEGACY_DATA_DIR")); p != "" {
		return p
	}
	return "/app/legacy-data"
}

// MigrateFromLegacyData 在「新数据目录还是空的、旧目录里有真配置」时把配置搬过来。
// 返回搬来的源目录；没做事时返回空字符串。
//
// 与 RestoreFromUpgradeBackup 的关系：**必须排在它前面**。搬成功之后，那边看到
// `config.json` 已经在就什么都不会做，用户也就不会有「配置被清空过」的红条。
// 搬不动（旧目录不存在 / 只读挂载失败 / 权限不够）才轮到备份兜底。
func MigrateFromLegacyData() string {
	dst := filepath.Dir(resolvePath())

	if fileExists(filepath.Join(dst, "config.json")) ||
		fileExists(filepath.Join(dst, "config.json"+backupSuffix)) {
		return ""
	}

	src := legacyDataDir()
	if !fileExists(filepath.Join(src, "config.json")) {
		return ""
	}

	copied := 0
	for _, f := range restoreFiles {
		from := filepath.Join(src, f)
		if !fileExists(from) {
			continue
		}
		mode := os.FileMode(0o644)
		if f == "config.json" {
			// 和 Save() 保持一致：配置文件里有 AdGuard 密码，不该对同机其他用户可读。
			mode = 0o600
		}
		if err := copyFile(from, filepath.Join(dst, f), mode); err == nil {
			copied++
		}
	}
	if copied == 0 {
		return ""
	}
	return src
}
