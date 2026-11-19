package config

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// 这一组测试守的是 2026-11-17 第二次配置丢失事故的修复：
// 覆盖升级把整个 /var/apps/<app> 删了，备份也被一起删掉，用户只能靠手动导出恢复。
//
// 逻辑本身很容易写错到「看着对、实际把用户现在的配置盖成旧的」，所以这里
// 重点不是「能恢复」，而是**在不该恢复的时候一条都不许动**。

// useConfigPath 把包内的配置文件路径指到测试临时目录。
//
// resolvePath 用 sync.Once 缓存路径，这里先手动置好再让 Once 认为已经跑过，
// 否则第一个调用方（可能是别的测试）会把路径定在别处。
func useConfigPath(t *testing.T, p string) {
	t.Helper()
	cfgPath = p
	cfgPathOnce = sync.Once{}
	cfgPathOnce.Do(func() {})
}

// writeBackup 造一份「升级前备份」，files 是 文件名 → 内容。
func writeBackup(t *testing.T, root, name string, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("建备份目录失败: %v", err)
	}
	for n, body := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(body), 0o600); err != nil {
			t.Fatalf("写备份文件 %s 失败: %v", n, err)
		}
	}
	return dir
}

const sampleConfig = `{"domains":["forum.example.com"],"ddns":{"enabled":true,"provider":"cloudflare","domain":"forum.example.com","ip_count":3}}`

// 数据目录是空的 + 备份还在 → 四个文件都搬回来，并留下「这是捡回来的」标记。
func TestRestoreFromUpgradeBackup(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")
	backupRoot := filepath.Join(tmp, "backup")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CFDDNS_BACKUP_DIR", backupRoot)

	src := writeBackup(t, backupRoot, "20261117-151200", map[string]string{
		"config.json":          sampleConfig,
		"ddns.env":             "CFDDNS_PORT=8880\n",
		"dashboard-password":   "Test123456\n",
		".wizard-env-applied":  "2026-11-17T15:00:00+08:00\n",
		"unrelated-not-backup": "这个文件不该被搬",
	})
	useConfigPath(t, filepath.Join(dataDir, "config.json"))

	if got := RestoreFromUpgradeBackup(); got != src {
		t.Fatalf("恢复来源应为 %s，实际 %q", src, got)
	}

	for _, f := range []string{"config.json", "ddns.env", "dashboard-password", ".wizard-env-applied"} {
		if !fileExists(filepath.Join(dataDir, f)) {
			t.Fatalf("%s 没被恢复", f)
		}
	}
	// 备份目录里的其他文件不要顺手搬过来——只搬白名单里的四个。
	if fileExists(filepath.Join(dataDir, "unrelated-not-backup")) {
		t.Fatal("不该把备份目录里的其他文件也搬进数据目录")
	}

	got, err := os.ReadFile(filepath.Join(dataDir, "config.json"))
	if err != nil || string(got) != sampleConfig {
		t.Fatalf("恢复的 config.json 内容不对: %q (%v)", string(got), err)
	}

	// config.json 里有 AdGuard 密码和各家密钥，不能比 Save() 写的更宽松。
	checkPerm(t, "恢复出来的 config.json", filepath.Join(dataDir, "config.json"), 0o600)

	// 标记必须落盘：程序可能马上因为改端口重启一次，只在内存里会丢。
	if !restoredFromUpgradeBackup() {
		t.Fatal("没有写 .restored-from-backup 标记")
	}
	if got := RestoreMarkerSource(); got != src {
		t.Fatalf("标记里的来源应为 %s，实际 %q", src, got)
	}

	// Load 要把这件事反映到配置上，界面才挂得出红条。
	cfg, err := Load()
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}
	if !cfg.RestoredFromBackup || !cfg.RestoredFromUpgradeBackup {
		t.Fatalf("恢复标志没置上: %+v", cfg)
	}
	if cfg.DDNS.IPCount != 3 || !cfg.DDNS.Enabled {
		t.Fatalf("恢复出来的配置内容不对: %+v", cfg.DDNS)
	}
}

// 有 config.json 就绝不许动——这是本功能最危险的地方：手一抖把用户
// 现在的配置盖成上一次升级前的旧版本，比不恢复糟糕得多。
func TestRestoreSkipsWhenConfigExists(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")
	backupRoot := filepath.Join(tmp, "backup")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CFDDNS_BACKUP_DIR", backupRoot)

	writeBackup(t, backupRoot, "20260101-000000", map[string]string{"config.json": sampleConfig})
	current := `{"domains":["now.example.com"]}`
	if err := os.WriteFile(filepath.Join(dataDir, "config.json"), []byte(current), 0o600); err != nil {
		t.Fatal(err)
	}
	useConfigPath(t, filepath.Join(dataDir, "config.json"))

	if got := RestoreFromUpgradeBackup(); got != "" {
		t.Fatalf("已有 config.json 时不该恢复，实际从 %q 恢复了", got)
	}
	body, _ := os.ReadFile(filepath.Join(dataDir, "config.json"))
	if string(body) != current {
		t.Fatalf("现有配置被覆盖了: %q", string(body))
	}
	if restoredFromUpgradeBackup() {
		t.Fatal("没恢复却写了标记，界面会误报")
	}
}

// 只剩 config.json.bak 时走原来那条恢复路（Load 自己处理），
// 升级备份这条不许抢先——.bak 更新，是用户上次保存的那一版。
func TestRestoreSkipsWhenBakExists(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")
	backupRoot := filepath.Join(tmp, "backup")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CFDDNS_BACKUP_DIR", backupRoot)

	writeBackup(t, backupRoot, "20260101-000000", map[string]string{"config.json": sampleConfig})
	if err := os.WriteFile(filepath.Join(dataDir, "config.json"+backupSuffix), []byte(sampleConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	useConfigPath(t, filepath.Join(dataDir, "config.json"))

	if got := RestoreFromUpgradeBackup(); got != "" {
		t.Fatalf("有 .bak 时不该动升级备份，实际从 %q 恢复了", got)
	}
}

// 备份目录里那些「建到一半失败」的空目录不算备份：没有 config.json 就跳过。
func TestRestoreIgnoresBackupWithoutConfig(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")
	backupRoot := filepath.Join(tmp, "backup")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CFDDNS_BACKUP_DIR", backupRoot)

	// 名字更新，但里面是空的——如果按「取最新」盲目挑，就会挑到它。
	writeBackup(t, backupRoot, "20261231-235959", map[string]string{"ddns.env": "CFDDNS_PORT=1\n"})
	good := writeBackup(t, backupRoot, "20260101-000000", map[string]string{"config.json": sampleConfig})
	useConfigPath(t, filepath.Join(dataDir, "config.json"))

	if got := RestoreFromUpgradeBackup(); got != good {
		t.Fatalf("应跳过没有 config.json 的目录，取 %s，实际 %q", good, got)
	}
}

// 备份目录根本不存在（首次安装、从没升级过）：静默返回，不许报错刷日志。
func TestRestoreWithoutBackupDir(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CFDDNS_BACKUP_DIR", filepath.Join(tmp, "nope"))
	useConfigPath(t, filepath.Join(dataDir, "config.json"))

	if got := RestoreFromUpgradeBackup(); got != "" {
		t.Fatalf("没有备份目录时应返回空，实际 %q", got)
	}
}

// 用户点了「保存全部设置」= 已经看过确认了：标记要清掉，否则红条会一直挂着。
func TestClearRestoreMarker(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	useConfigPath(t, filepath.Join(dataDir, "config.json"))

	if err := os.WriteFile(filepath.Join(dataDir, RestoreMarker), []byte("/x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !restoredFromUpgradeBackup() {
		t.Fatal("标记文件写了却读不到")
	}
	ClearRestoreMarker()
	if restoredFromUpgradeBackup() {
		t.Fatal("清标记失败")
	}
	if src := RestoreMarkerSource(); src != "" {
		t.Fatalf("标记清掉后不该还能读到来源，实际 %q", src)
	}
}

// CFDDNS_BACKUP_DIR 未设置时走容器里的固定路径，compose 会把宿主机目录挂到那儿。
func TestBackupDirDefault(t *testing.T) {
	t.Setenv("CFDDNS_BACKUP_DIR", "")
	if got := BackupDir(); got != "/app/backup" {
		t.Fatalf("默认备份目录应为 /app/backup，实际 %q", got)
	}
	t.Setenv("CFDDNS_BACKUP_DIR", "  /data/backups  ")
	if got := BackupDir(); got != "/data/backups" {
		t.Fatalf("环境变量应能覆盖（且去空格），实际 %q", got)
	}
}
