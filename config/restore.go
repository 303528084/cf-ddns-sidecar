package config

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// 这个文件解决 2026-11-17 第二次发生的事故：覆盖升级把整个应用目录删了。
//
// 时间线（有日志为证）：17:04 用户导出配置 → 17:2x 覆盖升级到 v1.3.0 → 17:27:59 程序
// 启动，日志出现「已把安装向导里填的端口写入 ddns.env」，这两句只在文件里还没有值时
// 才打印，所以那一刻数据目录是空的。
//
// 原来三道防线为什么没兜住：uninstall_callback 不删文件（代码已确认）；config.json.bak
// 和数据目录同层，目录整层没了 .bak 也没了；upgrade_init 的备份放在
// /var/apps/<app>/share/<app>-backup-<时间>/，还在 <app> 目录里，平台删的是整个
// /var/apps/<app>，等于把保险柜放在要拆的楼里。
//
// 所以这一版做两件事：upgrade_init 把备份搬到 /var/apps/<app>-backup/<时间>/（<app> 的
// 兄弟，不在里面）；程序启动时发现数据目录空了而备份还在，就自己恢复并挂红条。
// 恢复必须写在容器里的程序而不是宿主机脚本：容器是 appcenter 先拉起来的，cmd/main start
// 晚一步，等脚本动手程序早就用空配置跑起来了。

// RestoreMarker 是「这份配置是从升级前备份捡回来的」这个事实的落盘标记。
// 放文件而不是只放内存：程序可能在恢复后很快因为改端口等原因重启一次，
// 内存里的标志一丢，红条就再也不出现了。
const RestoreMarker = ".restored-from-backup"

// restoreFiles 是恢复时要一起搬回来的文件。config.json 是必须的（没有它就不算备份），
// 其余「有就搬、没有跳过」。别漏 .wizard-env-applied：少搬它，下次启动会拿容器里
// 烘死的环境变量把端口再覆盖一遍。
var restoreFiles = []string{"config.json", "ddns.env", "dashboard-password", ".wizard-env-applied"}

// BackupDir 返回「升级前备份」的根目录。
//
// 默认 /app/backup 是容器内路径，由 compose 把宿主机的
// /var/apps/<app>-backup 只读挂进来。用环境变量覆盖是为了能在本地测试，
// 也让用户自己 docker compose 部署时不依赖飞牛那套目录。
func BackupDir() string {
	if p := strings.TrimSpace(os.Getenv("CFDDNS_BACKUP_DIR")); p != "" {
		return p
	}
	return "/app/backup"
}

// RestoreFromUpgradeBackup 在「数据目录是空的、但升级前备份还在」时把配置捡回来。
// 返回恢复来源目录；没做事时返回空字符串。
//
// 三条刻意的约束：
//  1. **只在真的空了的时候动手**。已经有 config.json 或 config.json.bak 就一律不碰，
//     恢复逻辑最怕的就是「手一抖把用户现在的配置盖成旧的」。
//  2. **按目录名倒序取最新的那份**。目录名是 `<年月日>-<时分秒>`，字典序就等于时间序。
//  3. **备份里没有 config.json 的目录不算备份**，跳过（那多半是建到一半失败了）。
func RestoreFromUpgradeBackup() string {
	dataDir := filepath.Dir(resolvePath())

	if fileExists(filepath.Join(dataDir, "config.json")) ||
		fileExists(filepath.Join(dataDir, "config.json"+backupSuffix)) {
		return ""
	}

	root := BackupDir()
	entries, err := os.ReadDir(root)
	if err != nil {
		// 备份目录不存在是完全正常的情况（首次安装、没升级过）。
		return ""
	}

	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if fileExists(filepath.Join(root, e.Name(), "config.json")) {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	src := filepath.Join(root, names[0])

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
		if err := copyFile(from, filepath.Join(dataDir, f), mode); err == nil {
			copied++
		}
	}
	if copied == 0 {
		return ""
	}

	// 标记写失败不算失败：配置已经回来了，红条只是提示。
	_ = os.WriteFile(
		filepath.Join(dataDir, RestoreMarker),
		[]byte(src+"\n"+time.Now().Format(time.RFC3339)+"\n"),
		0o644,
	)
	return src
}

// ClearRestoreMarker 在用户主动「保存全部设置」之后调用，表示他已经看过并确认了。
func ClearRestoreMarker() {
	_ = os.Remove(filepath.Join(filepath.Dir(resolvePath()), RestoreMarker))
}

// restoredFromUpgradeBackup 判断这次是不是从升级备份捡回来的。
func restoredFromUpgradeBackup() bool {
	return fileExists(filepath.Join(filepath.Dir(resolvePath()), RestoreMarker))
}

// RestoreMarkerSource 读回标记里的来源目录，供日志和界面说清楚「从哪儿捡回来的」。
// 标记格式两行：第一行来源目录，第二行时间。
func RestoreMarkerSource() string {
	b, err := os.ReadFile(filepath.Join(filepath.Dir(resolvePath()), RestoreMarker))
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimSpace(line)
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func copyFile(from, to string, mode os.FileMode) error {
	src, err := os.Open(from)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.OpenFile(to, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return err
	}
	return dst.Close()
}
