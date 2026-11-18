package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// setPath 把配置路径指到临时目录。
//
// resolvePath() 内部用 sync.Once 缓存，但只在 CFDDNS_CONFIG 非空时才覆盖
// 默认值；测试里直接把 cfgPath 赋好，Once 执行时环境变量为空、不会改动它。
func setPath(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	cfgPath = p
	return p
}

// TestSaveWritesBackup 验证：每次落盘前都会把上一版留在 .bak 里。
// 这是「文件被写坏」和「文件被删」两种事故的共同兜底。
func TestSaveWritesBackup(t *testing.T) {
	p := setPath(t)

	first := Default()
	first.Domains = []string{"first.example.com"}
	first.AdGuard.URL = "http://10.0.0.1:3000"
	if err := first.Save(); err != nil {
		t.Fatalf("第一次保存失败: %v", err)
	}
	// 第一版落盘时磁盘上还没有旧文件，此时不该有 .bak
	if _, err := os.Stat(p + backupSuffix); err == nil {
		t.Fatal("第一次保存不该产生 .bak（没有旧内容可备份）")
	}

	second := Default()
	second.Domains = []string{"second.example.com"}
	if err := second.Save(); err != nil {
		t.Fatalf("第二次保存失败: %v", err)
	}

	bak, err := os.ReadFile(p + backupSuffix)
	if err != nil {
		t.Fatalf("第二次保存后应有 .bak: %v", err)
	}
	var got Config
	if err := json.Unmarshal(bak, &got); err != nil {
		t.Fatalf(".bak 不是合法 JSON: %v", err)
	}
	if len(got.Domains) != 1 || got.Domains[0] != "first.example.com" {
		t.Fatalf(".bak 里应该是上一版内容，实际域名=%v", got.Domains)
	}
	if got.AdGuard.URL != "http://10.0.0.1:3000" {
		t.Fatalf(".bak 里 AdGuard 地址丢了，实际=%q", got.AdGuard.URL)
	}

	// 主文件仍应是最新一版
	main, _ := os.ReadFile(p)
	var cur Config
	if err := json.Unmarshal(main, &cur); err != nil {
		t.Fatalf("主文件不是合法 JSON: %v", err)
	}
	if len(cur.Domains) != 1 || cur.Domains[0] != "second.example.com" {
		t.Fatalf("主文件应该是新一版，实际域名=%v", cur.Domains)
	}
}

// TestLoadRestoresFromBackup 是 2026-11-17 那次事故的回归测试。
//
// 当时的现场：升级把数据目录清空，config.json 不存在，程序当成「首次启动」
// 用默认值继续跑，用户看到一个空白后台但没有任何提示。
// 现在要求：只要有 .bak，就必须恢复，并且把 RestoredFromBackup 置起来
// 让上层显式告警。
func TestLoadRestoresFromBackup(t *testing.T) {
	p := setPath(t)

	saved := Default()
	saved.Domains = []string{"keep.example.com", "also.example.com"}
	saved.AdGuard.URL = "http://192.168.1.9:3000"
	saved.AdGuard.Username = "admin"
	saved.AdGuard.Password = "secret"
	saved.DDNS.Provider = "dnspod"
	saved.DDNS.Domain = "home.example.com"
	saved.DDNS.Enabled = true
	saved.Speed.IntervalMinutes = 15

	data, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p+backupSuffix, data, 0o600); err != nil {
		t.Fatal(err)
	}
	// 主文件故意不建——模拟被清空

	got, err := Load()
	if err != nil {
		t.Fatalf("Load 不应报错: %v", err)
	}
	if !got.RestoredFromBackup {
		t.Fatal("从 .bak 恢复时 RestoredFromBackup 必须为 true（否则用户看不到任何提示）")
	}
	if !got.PendingSave {
		t.Fatal("恢复后必须置 PendingSave，把内容重新写回主文件")
	}
	if len(got.Domains) != 2 {
		t.Fatalf("域名列表没恢复，实际=%v", got.Domains)
	}
	if got.AdGuard.URL != "http://192.168.1.9:3000" {
		t.Fatalf("AdGuard 地址没恢复，实际=%q", got.AdGuard.URL)
	}
	if got.AdGuard.Password != "secret" {
		t.Fatal("AdGuard 密码没恢复")
	}
	if got.DDNS.Provider != "dnspod" || got.DDNS.Domain != "home.example.com" || !got.DDNS.Enabled {
		t.Fatalf("DDNS 配置没恢复: %+v", got.DDNS)
	}
	if got.Speed.IntervalMinutes != 15 {
		t.Fatalf("测速间隔没恢复，实际=%d", got.Speed.IntervalMinutes)
	}
}

// TestLoadFirstRunWithoutBackup 验证真正的首次启动仍按默认值走，
// 不会被「恢复提示」误伤（否则每个新装用户开机就看到一条警告）。
func TestLoadFirstRunWithoutBackup(t *testing.T) {
	setPath(t)

	got, err := Load()
	if err != nil {
		t.Fatalf("Load 不应报错: %v", err)
	}
	if got.RestoredFromBackup {
		t.Fatal("没有 .bak 时不该标记为「已从备份恢复」")
	}
	if got.Speed.TopN != 5 || got.Speed.BandwidthCandidates != 100 {
		t.Fatalf("默认值不对: %+v", got.Speed)
	}
	if got.DDNS.Provider != "cloudflare" {
		t.Fatalf("默认服务商应为 cloudflare，实际=%q", got.DDNS.Provider)
	}
}

// TestLoadIgnoresBrokenBackup 验证 .bak 本身坏掉时不能把程序带崩，
// 也不能让用户卡在启动失败上——退回默认值继续跑，比起不来好。
func TestLoadIgnoresBrokenBackup(t *testing.T) {
	p := setPath(t)

	if err := os.WriteFile(p+backupSuffix, []byte("{ 这不是 JSON"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := Load()
	if err != nil {
		t.Fatalf("坏备份不该让 Load 报错: %v", err)
	}
	if got.RestoredFromBackup {
		t.Fatal("备份解析失败时不该声称恢复成功")
	}
	if got.Speed.TopN != 5 {
		t.Fatalf("应退回默认值，实际 TopN=%d", got.Speed.TopN)
	}
}

// TestEffectiveRecordMode：老配置（没有 record_type 字段）必须还是按 A 写，
// 升级不能改变用户现有记录的任何一行；只有明确写了 AAAA / A+AAAA 才走 v6。
func TestEffectiveRecordMode(t *testing.T) {
	cases := map[string]string{
		"":          "A", // 零值 = 老配置
		"A":         "A",
		"a":         "A",
		"AAAA":      "AAAA",
		"aaaa":      "AAAA",
		"  AAAA ":   "AAAA",
		"A+AAAA":    "A+AAAA", // 两族都写
		"a+aaaa":    "A+AAAA",
		"AAAA+A":    "A+AAAA", // 顺序反了也认，别让手写配置的人莫名其妙
		" A + AAAA": "A+AAAA", // 带空格也认
		"CNAME":     "A",      // 读进来的路径不报错，保存时才会拦（见 web/saveConfig）
		"TRUST ME ": "A",
	}
	for in, want := range cases {
		got := DDNSConfig{RecordType: in}.EffectiveRecordMode()
		if got != want {
			t.Errorf("RecordType=%q 应得到 %q，实际 %q", in, want, got)
		}
	}
}
