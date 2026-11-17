package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 这一组测试守的是 2026-11-17 第三次「升级后配置空了」的修复。
//
// 前两次修的是「备份放错地方」（放进了会被删的那一层），这次暴露的是另一个
// 更根本的问题：**备份到底有没有生成，全看宿主机脚本跑不跑**。真机上它没跑，
// 于是程序手里什么都没有，连「恢复失败」的提示都出不来——安静地变成空配置。
//
// 修法是把「生成备份」这件事收回到程序自己手里：每次保存成功就备一份。
// 所以这里重点测两件事：
//  1. 保存之后备份**真的**落在备份目录里，而且四个文件都在；
//  2. 不该备的时候一份都别多——尤其是「内容没变」时不能反复写，
//     否则测速每跑一次就把三份历史刷光，真出事时反而没有可用的旧版本。

// snapshotEnv 准备一个「数据目录 + 备份目录」的干净现场。
func snapshotEnv(t *testing.T) (dataDir, backupRoot string) {
	t.Helper()
	tmp := t.TempDir()
	dataDir = filepath.Join(tmp, "data")
	backupRoot = filepath.Join(tmp, "backup")
	for _, d := range []string{dataDir, backupRoot} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("建目录 %s 失败: %v", d, err)
		}
	}
	t.Setenv("CFDDNS_BACKUP_DIR", backupRoot)
	useConfigPath(t, filepath.Join(dataDir, "config.json"))
	return dataDir, backupRoot
}

// snapshotDirs 列出备份根目录下所有「长得像备份」的子目录名。
func snapshotDirs(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("读备份目录失败: %v", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && snapshotPattern.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out
}

// 保存一次配置 → 备份目录里出现一份，四个文件都在，config.json 权限 0600。
func TestSaveWritesSnapshot(t *testing.T) {
	dataDir, backupRoot := snapshotEnv(t)

	// 数据目录里除了 config.json 之外的三个文件也要被一起备走，
	// 否则恢复回来的配置会缺端口/密码。
	for name, body := range map[string]string{
		"ddns.env":            "CFDDNS_PORT=8880\n",
		"dashboard-password":  "Test123456\n",
		".wizard-env-applied": "2026-11-17T18:00:00+08:00\n",
	} {
		if err := os.WriteFile(filepath.Join(dataDir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cfg := Default()
	cfg.DDNS.IPCount = 3
	if err := cfg.Save(); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	dirs := snapshotDirs(t, backupRoot)
	if len(dirs) != 1 {
		t.Fatalf("保存后应有 1 份备份，实际 %d 份: %v", len(dirs), dirs)
	}

	snap := filepath.Join(backupRoot, dirs[0])
	for _, f := range []string{"config.json", "ddns.env", "dashboard-password", ".wizard-env-applied"} {
		if !fileExists(filepath.Join(snap, f)) {
			t.Fatalf("备份里缺 %s", f)
		}
	}

	// 和 Save() 保持一致：这一份里有 AdGuard 密码，不能写成同机人人可读。
	st, err := os.Stat(filepath.Join(snap, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("备份里的 config.json 权限应为 0600，实际 %o", perm)
	}

	// 模拟真机上发生的事情：整个数据目录被删掉，然后容器重建。
	// 这一步是整条链路的意义所在——备份必须能把它救回来。
	if err := os.RemoveAll(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := RestoreFromUpgradeBackup(); got != snap {
		t.Fatalf("应能从 %s 恢复，实际 %q", snap, got)
	}
	back, err := Load()
	if err != nil {
		t.Fatalf("恢复后加载失败: %v", err)
	}
	if back.DDNS.IPCount != 3 {
		t.Fatalf("恢复出来的内容不对: ip_count=%d", back.DDNS.IPCount)
	}
}

// 内容没变就不该再备一份。
//
// 这是最容易写错、代价又最大的一处：测速每跑一次都会改 config.json 里的
// last_ip，如果每次都无条件备一份，三份历史几分钟就被刷完——真出问题时
// 能捡到的只是「三分钟前」，而不是「上次改设置那一刻」。
func TestSaveSkipsIdenticalSnapshot(t *testing.T) {
	_, backupRoot := snapshotEnv(t)

	cfg := Default()
	for i := 0; i < 3; i++ {
		if err := cfg.Save(); err != nil {
			t.Fatalf("第 %d 次保存失败: %v", i+1, err)
		}
	}
	if dirs := snapshotDirs(t, backupRoot); len(dirs) != 1 {
		t.Fatalf("内容没变时不该新增备份，实际有 %d 份: %v", len(dirs), dirs)
	}
}

// 内容真的变了 → 新的一份。老的那份要还在，不能就地覆盖。
func TestSaveSnapshotsAgainWhenChanged(t *testing.T) {
	_, backupRoot := snapshotEnv(t)

	cfg := Default()
	cfg.Domains = []string{"first.example.com"}
	if err := cfg.Save(); err != nil {
		t.Fatalf("第一次保存失败: %v", err)
	}
	firstDirs := snapshotDirs(t, backupRoot)

	// 目录名只精确到秒，同一秒内两次保存会落进同一个目录（这是有意的：
	// 同一秒内的新旧两份，留新的那份才对）。为了测「真的产生第二份」，
	// 这里必须跨过一秒。
	time.Sleep(1100 * time.Millisecond)

	cfg.Domains = []string{"second.example.com"}
	if err := cfg.Save(); err != nil {
		t.Fatalf("第二次保存失败: %v", err)
	}

	dirs := snapshotDirs(t, backupRoot)
	if len(dirs) != 2 {
		t.Fatalf("内容变了应新增一份，实际 %d 份: %v", len(dirs), dirs)
	}
	// 老的那份还在，里面还应该是旧内容。
	body, err := os.ReadFile(filepath.Join(backupRoot, firstDirs[0], "config.json"))
	if err != nil {
		t.Fatalf("旧备份不见了: %v", err)
	}
	if !strings.Contains(string(body), "first.example.com") {
		t.Fatalf("旧备份内容被覆盖了: %s", string(body))
	}
}

// 备份根目录不存在（用户自己写 compose 时没挂 /app/backup）：
// 保存照样成功，而且**不许**替用户凭空建一个目录。
//
// 为什么不建：建出来的目录在容器自己的临时层里，容器一重建就没了，
// 却会让启动日志显示「有 3 份备份」——那比没有备份更误导人。
func TestSaveWithoutBackupRootDoesNotCreateIt(t *testing.T) {
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(tmp, "no-such-backup")
	t.Setenv("CFDDNS_BACKUP_DIR", missing)
	useConfigPath(t, filepath.Join(dataDir, "config.json"))

	cfg := Default()
	if err := cfg.Save(); err != nil {
		t.Fatalf("备份目录不在不该影响保存，却失败了: %v", err)
	}
	if _, err := os.Stat(missing); err == nil {
		t.Fatal("不该替用户创建备份目录")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "config.json")); err != nil {
		t.Fatalf("配置本身没落盘: %v", err)
	}
}

// 只留最新 3 份，更老的清掉；名字不像时间戳的东西一律不碰。
func TestPruneSnapshotsKeepsNewestThree(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "backup")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	stamps := []string{
		"20260101-000000", "20260102-000000", "20260103-000000",
		"20260104-000000", "20260105-000000",
	}
	for _, s := range stamps {
		dir := filepath.Join(root, s)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// 用户自己放进来的东西，不能被当成备份清掉。
	keep := filepath.Join(root, "我手动导出的.json")
	if err := os.WriteFile(keep, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	pruneSnapshots(root)

	got := snapshotDirs(t, root)
	if len(got) != 3 {
		t.Fatalf("应只留 3 份，实际 %d 份: %v", len(got), got)
	}
	for _, want := range stamps[2:] {
		found := false
		for _, g := range got {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("最新的 %s 被误删了，剩下 %v", want, got)
		}
	}
	if !fileExists(keep) {
		t.Fatal("不该动名字不像时间戳的文件")
	}
}

// 启动诊断日志要能分辨三种完全不同的状况：目录没有、目录在但写不进去、
// 目录在但还空着。三种的修法不一样，混成一句就没法指导排查。
func TestInspectBackupDir(t *testing.T) {
	tmp := t.TempDir()
	missing := filepath.Join(tmp, "nope")
	t.Setenv("CFDDNS_BACKUP_DIR", missing)
	if st := InspectBackupDir(); st.Exists || st.Writable || st.Count != 0 {
		t.Fatalf("目录不存在时应全是假值，实际 %+v", st)
	}

	root := filepath.Join(tmp, "backup")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CFDDNS_BACKUP_DIR", root)

	st := InspectBackupDir()
	if !st.Exists || !st.Writable {
		t.Fatalf("空目录应存在且可写，实际 %+v", st)
	}
	if st.Count != 0 || st.Newest != "" {
		t.Fatalf("空目录不该有备份，实际 %+v", st)
	}

	// 三份「看着像备份」的目录里只有一份真能用：一份没有 config.json、
	// 一份名字不像时间戳。它们都不该被算进 Count。
	writeBackup(t, root, "20260101-000000", map[string]string{"config.json": sampleConfig})
	writeBackup(t, root, "20260102-000000", map[string]string{"ddns.env": "x"})
	writeBackup(t, root, "手工备份", map[string]string{"config.json": sampleConfig})

	st = InspectBackupDir()
	if st.Count != 1 {
		t.Fatalf("只应算 1 份可用备份，实际 %d 份", st.Count)
	}
	if st.Newest != "20260101-000000" {
		t.Fatalf("最新一份应是 20260101-000000，实际 %q", st.Newest)
	}
}

// 目录名必须和 upgrade_init 的 `date +%Y%m%d-%H%M%S` 完全一致，
// 否则两边的备份混在同一个目录里就没法按名字排出新旧。
func TestSnapshotPattern(t *testing.T) {
	good := []string{"20261117-190500", "20260101-000000"}
	bad := []string{"20261117-190500-1", "2026-11-17", "20261117190500", "backup", ""}
	for _, s := range good {
		if !snapshotPattern.MatchString(s) {
			t.Fatalf("%q 应被认作备份目录名", s)
		}
	}
	for _, s := range bad {
		if snapshotPattern.MatchString(s) {
			t.Fatalf("%q 不该被认作备份目录名", s)
		}
	}
}
