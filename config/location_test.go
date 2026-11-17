package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 这一组测试守的是 2026-11-17 20:35 的那次「实测推翻」。
//
// v1.3.2～v1.4.1 三个版本的日志都在说「数据目录已搬到存储卷」，
// 而用户翻遍 /vol1 根、@appcenter、@appshare 都没有那两个文件夹。
// 原因是脚本里 mkdir 带着 2>/dev/null，权限不够时错误被吞掉，
// 随后走了一个正确的兜底分支——**兜底是对的，但它不说话**。
//
// 修法：脚本把真相写进 location-status.txt，程序读出来念。所以这里重点测：
//  1. 账本能被正确处理（含 CRLF、含值里带 = 的路径、含空文件）；
//  2. 读不到时不能装作读到了（Found=false），否则又变成「照想象打印」；
//  3. 「本该在卷上的路径」是拿挂载路径的 basename 拼的，不是写死应用名。

// writeLocation 在数据目录里落一份账本，返回账本路径。
func writeLocation(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	useConfigPath(t, filepath.Join(dir, "config.json"))

	p := filepath.Join(dir, locationFile)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("写账本失败: %v", err)
	}
	return p
}

// 正常情况：数据已经在卷上（symlink），备份也在卷上，两处都没有错误。
func TestInspectLocationSymlinked(t *testing.T) {
	writeLocation(t, "time=2026-11-17 21:30:00\n"+
		"volume_root=/vol1\n"+
		"data_host=/var/apps/cf-ddns-sidecar-data\n"+
		"data_kind=symlink\n"+
		"data_real=/vol1/cf-ddns-sidecar-data\n"+
		"data_error=\n"+
		"backup_host=/var/apps/cf-ddns-sidecar-backup\n"+
		"backup_kind=symlink\n"+
		"backup_real=/vol1/cf-ddns-sidecar-backup\n"+
		"backup_error=\n")

	st := InspectLocation()
	if !st.Found {
		t.Fatal("账本存在却说没读到")
	}
	if st.DataKind != "symlink" {
		t.Errorf("data_kind = %q，期望 symlink", st.DataKind)
	}
	if st.DataError != "" {
		t.Errorf("data_error 应为空，实际 %q", st.DataError)
	}
	if st.BackupError != "" {
		t.Errorf("backup_error 应为空，实际 %q", st.BackupError)
	}
	if got, want := st.DataWhere(), "/vol1/cf-ddns-sidecar-data"; got != want {
		t.Errorf("DataWhere = %q，期望 %q", got, want)
	}
}

// 真机现场：/vol1 根属于 root，普通用户建不了目录，脚本退回真实目录并把原因记下来。
// 这一段是本次修复的核心——**原因必须能原样带出来**，不能只剩一个空字段。
func TestInspectLocationNotMigrated(t *testing.T) {
	writeLocation(t, "time=2026-11-17 20:35:00\n"+
		"volume_root=/vol1\n"+
		"data_host=/var/apps/cf-ddns-sidecar-data\n"+
		"data_kind=real\n"+
		"data_real=/var/apps/cf-ddns-sidecar-data\n"+
		"data_error=在 /vol1/cf-ddns-sidecar-data 建不了目录（mkdir: can't create directory: Permission denied），数据只能留在 /var/apps/cf-ddns-sidecar-data\n"+
		"backup_host=/var/apps/cf-ddns-sidecar-backup\n"+
		"backup_kind=real\n"+
		"backup_real=/var/apps/cf-ddns-sidecar-backup\n"+
		"backup_error=在 /vol1/cf-ddns-sidecar-backup 建不了目录（mkdir: can't create directory: Permission denied），备份只能留在 /var/apps/cf-ddns-sidecar-backup\n")

	st := InspectLocation()
	if !st.Found {
		t.Fatal("账本存在却说没读到")
	}
	if st.DataKind != "real" {
		t.Errorf("data_kind = %q，期望 real", st.DataKind)
	}
	if st.DataError == "" {
		t.Fatal("data_error 为空——这正是上一版的毛病：搬失败了却没人说")
	}
	if !strings.Contains(st.DataError, "Permission denied") {
		t.Errorf("data_error 里应保留原始错误，实际 %q", st.DataError)
	}
	if st.BackupError == "" {
		t.Error("backup_error 为空，备份没搬上去这件事也会被漏掉")
	}
	// 实际位置要能拿到，不然日志里只能写「搬失败了」，用户不知道东西在哪。
	if got, want := st.DataWhere(), "/var/apps/cf-ddns-sidecar-data"; got != want {
		t.Errorf("DataWhere = %q，期望 %q", got, want)
	}
}

// 值里带 "=" 不能被切坏（路径里可能带，错误信息里更可能带）。
func TestInspectLocationValueWithEquals(t *testing.T) {
	writeLocation(t, "data_host=/var/apps/a=b-data\n"+
		"data_error=cp 失败（src=/x/dst=/y）\n")

	st := InspectLocation()
	if got, want := st.DataHost, "/var/apps/a=b-data"; got != want {
		t.Errorf("DataHost = %q，期望 %q", got, want)
	}
	if got, want := st.DataError, "cp 失败（src=/x/dst=/y）"; got != want {
		t.Errorf("DataError = %q，期望 %q", got, want)
	}
}

// CRLF：脚本用 echo 写出来在 Linux 上不会带 \r，但用户可能用记事本改过，
// 那种情况下每一行末尾都会多一个 \r，拼进日志的路径就带着一个看不见的字符。
func TestInspectLocationCRLF(t *testing.T) {
	writeLocation(t, "data_host=/var/apps/cf-ddns-sidecar-data\r\n"+
		"volume_root=/vol1\r\n")

	st := InspectLocation()
	if got, want := st.DataHost, "/var/apps/cf-ddns-sidecar-data"; got != want {
		t.Errorf("DataHost = %q，期望 %q（\\r 没被去掉）", got, want)
	}
	if got, want := st.VolumeRoot, "/vol1"; got != want {
		t.Errorf("VolumeRoot = %q，期望 %q", got, want)
	}
}

// 账本不存在（自己写 compose 部署、或脚本没跑到）：必须老实说没读到，
// 不能返回一个「字段全空的成功结果」——那样日志会安静得像一切正常。
func TestInspectLocationMissing(t *testing.T) {
	useConfigPath(t, filepath.Join(t.TempDir(), "config.json"))

	st := InspectLocation()
	if st.Found {
		t.Fatal("账本不存在却报 Found=true")
	}
	if st.File == "" {
		t.Error("File 应给出「该去哪儿找」，即使没找到")
	}
}

// 空文件 / 只有垃圾行：不 panic、不把垃圾当字段。
func TestInspectLocationGarbage(t *testing.T) {
	writeLocation(t, "\n\n这不是键值对\n=没有键\n只有键没有等号\n")

	st := InspectLocation()
	if !st.Found {
		t.Fatal("空账本也算读到了")
	}
	if st.DataHost != "" || st.DataError != "" {
		t.Errorf("垃圾行不该被当成字段：DataHost=%q DataError=%q", st.DataHost, st.DataError)
	}
}

// 探不到卷根时日志里那句原因要走另一套措辞（不能说「/vol1 属于 root」，
// 因为这台机器压根没有 /vol1）。这里只守解析层：volume_root 空就是空，
// 不许拿别的字段凑一个出来。
func TestInspectLocationNoVolumeRoot(t *testing.T) {
	writeLocation(t, "volume_root=\n"+
		"data_host=/var/apps/cf-ddns-sidecar-data\n"+
		"data_kind=real\n"+
		"data_error=没探到存储卷（/vol1～/vol9 都不在），数据只能留在 /var/apps/cf-ddns-sidecar-data\n")

	st := InspectLocation()
	if st.VolumeRoot != "" {
		t.Errorf("VolumeRoot 应为空，实际 %q", st.VolumeRoot)
	}
	if st.DataError == "" {
		t.Error("没探到卷根也是一件要说出来的事，data_error 不该为空")
	}
}
