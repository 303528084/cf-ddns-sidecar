package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/303528084/cf-ddns-sidecar/config"
	"github.com/303528084/cf-ddns-sidecar/ddns"
)

// TestMain 把全局配置路径钉在一个临时目录里。
//
// config 包解析路径用了 sync.Once（进程内只认第一次），而导入接口写的是
// 「配置文件的同目录」，所以必须在任何测试跑之前就定下来，否则第几个测试
// 先碰到就会把后面的写到 /app/data 去。
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cfddns-web-test-*")
	if err != nil {
		panic(err)
	}
	_ = os.Setenv("CFDDNS_CONFIG", filepath.Join(dir, "config.json"))
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func sampleConfig() config.Config {
	c := config.Default()
	c.AdGuard.URL = "http://192.168.1.2:3000"
	c.AdGuard.Username = "admin"
	c.AdGuard.Password = "adg-pass"
	c.Domains = []string{"openai.com", "openrouter.ai"}
	c.Speed.IntervalMinutes = 30
	c.DDNS.Enabled = true
	c.DDNS.Provider = "cloudflare"
	c.DDNS.Domain = "cf.example.com"
	// 运行状态：不该出现在导出文件里
	c.LastIP = "203.0.113.9"
	c.LastTime = "2026-11-17 15:00:00"
	return *c
}

// TestBuildBundleOmitsRuntimeState 导出文件里不能有 last_ip（换机器后照搬只会误导人）。
func TestBuildBundleOmitsRuntimeState(t *testing.T) {
	b := buildBundle(sampleConfig(), map[string]string{"CF_API_TOKEN": "tok", "CF_ZONE_ID": "zid"},
		"1.2.0", time.Date(2026, 11, 17, 16, 0, 0, 0, time.UTC))
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	s := string(raw)
	for _, banned := range []string{"last_ip", "last_time", "203.0.113.9"} {
		if strings.Contains(s, banned) {
			t.Errorf("导出文件里不该出现 %q：%s", banned, s)
		}
	}
	if !strings.Contains(s, `"openai.com"`) || !strings.Contains(s, `"CF_API_TOKEN"`) {
		t.Errorf("导出文件少了应带的内容：%s", s)
	}
	if b.Note == "" {
		t.Error("导出文件应带一句「请当密码保管」的提醒")
	}
}

// TestParseBundleRoundTrip 导出的东西必须能被自己导入回来。
func TestParseBundleRoundTrip(t *testing.T) {
	in := buildBundle(sampleConfig(), map[string]string{"CF_API_TOKEN": "tok", "CF_ZONE_ID": "zid"},
		"1.2.0", time.Now())
	raw, _ := json.Marshal(in)

	out, warns, err := parseBundle(raw)
	if err != nil {
		t.Fatalf("解析自己的导出文件失败: %v", err)
	}
	if len(warns) != 0 {
		t.Errorf("正常文件不该有提示: %v", warns)
	}
	if out.Config.AdGuardURL != in.Config.AdGuardURL || out.Config.DDNSDomain != in.Config.DDNSDomain {
		t.Errorf("往返后内容变了: %+v", out.Config)
	}
	if len(out.Config.Domains) != 2 {
		t.Errorf("域名数量不对: %v", out.Config.Domains)
	}
	if out.Secrets["CF_API_TOKEN"] != "tok" {
		t.Errorf("密钥丢了: %v", out.Secrets)
	}
}

func TestParseBundleRejects(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"空文件", "", "空"},
		{"不是 JSON", "{{{", "不是有效的 JSON"},
		{"别的应用的文件", `{"app":"other","format":1}`, "不是本应用"},
		{"格式版本太新", `{"app":"cf-ddns-sidecar","format":99}`, "请先升级应用"},
	}
	for _, c := range cases {
		_, _, err := parseBundle([]byte(c.raw))
		if err == nil {
			t.Errorf("%s：应当报错却通过了", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s：错误信息应含 %q，实际 %q", c.name, c.want, err.Error())
		}
	}
}

// TestParseBundleCorrectsAndWarns 能修的直接修，修不了的给提示。
func TestParseBundleCorrectsAndWarns(t *testing.T) {
	raw := `{
	  "app":"cf-ddns-sidecar","format":1,
	  "config":{
	    "domains":["https://OpenAI.com/x","","1.2.3.4","bad domain","openai.com"],
	    "top_n":-3,"bandwidth_candidates":0,"interval_minutes":-10,
	    "ddns_provider":"WEIRD","ddns_domain":"https://cf.Example.com/"
	  },
	  "secrets":{"CF_API_TOKEN":"tok","TOTALLY_UNKNOWN_KEY":"x","CF_ZONE_ID":""}
	}`
	b, warns, err := parseBundle([]byte(raw))
	if err != nil {
		t.Fatalf("不该报错: %v", err)
	}
	if len(b.Config.Domains) != 1 || b.Config.Domains[0] != "openai.com" {
		t.Errorf("域名归一化不对: %v", b.Config.Domains)
	}
	if b.Config.TopN != 5 || b.Config.Candidates != 100 || b.Config.IntervalMinutes != 0 {
		t.Errorf("越界数值没归位: %+v", b.Config)
	}
	if b.Config.DDNSProvider != "cloudflare" {
		t.Errorf("不认识的服务商应退回 cloudflare，实际 %q", b.Config.DDNSProvider)
	}
	if b.Config.DDNSDomain != "cf.example.com" {
		t.Errorf("优选域名没归一化: %q", b.Config.DDNSDomain)
	}
	if _, ok := b.Secrets["TOTALLY_UNKNOWN_KEY"]; ok {
		t.Error("白名单外的密钥不该被收下")
	}
	if _, ok := b.Secrets["CF_ZONE_ID"]; ok {
		t.Error("空值不该写进密钥表")
	}
	joined := strings.Join(warns, "|")
	for _, want := range []string{"忽略了", "不认识", "TOTALLY_UNKNOWN_KEY"} {
		if !strings.Contains(joined, want) {
			t.Errorf("提示里应含 %q，实际：%v", want, warns)
		}
	}
}

// fullConfig 是「每一项用户能改的设置都不是默认值」的配置。
//
// 导出/导入的用例都拿它当基准，理由很实在：如果拿默认值去验，漏导一项
// 也看不出来——漏了以后读到的是零值，而零值恰好等于默认值，测试全绿。
// v1.7.4 之前漏了六项就是这么活下来的。
func fullConfig() config.Config {
	c := config.Default()
	c.AdGuard.URL = "http://192.168.1.2:3000"
	c.AdGuard.Username = "admin"
	c.AdGuard.Password = "adg-pass"
	c.Domains = []string{"openai.com", "cf.example.com"}
	c.DomainMeta = map[string]config.DomainMeta{
		"openai.com":     {Wildcard: true, AddedAt: "2026-11-17 10:00:00"},
		"cf.example.com": {AddedAt: "2026-11-18 09:30:00"},
	}
	c.Speed.IntervalMinutes = 30
	c.Speed.TopN = 7
	c.Speed.BandwidthCandidates = 80
	c.Speed.ExtraSources = []string{"104.16.0.0/13", "https://example.com/ips.txt"}
	c.Speed.EngineOverrides = map[string]any{"IP_CALIBRATION_ENABLED": true}
	c.IPv6ProbeURL = "https://example.com/v6.txt\n# 备用源\nhttps://example.com/v6-2.txt"
	// hosts 源那一块：开关必须开着（关着的值等于默认值，漏导也看不出来），
	// 链接里也带一行注释，顺便验注释会不会被拆坏。
	c.HostsEnabled = true
	c.HostsSource = "https://hosts.gitcdn.top/hosts.txt\n# 备用源\nhttps://example.com/hosts.txt"
	// hosts 账本：上一轮写进 AdGuard 的域名 → IP。它决定「源里删掉一个域名之后
	// 能不能把旧记录清掉」，和 RewrittenDomains 一样必须跟着备份走。
	c.HostsEntries = map[string]string{"github.com": "140.82.113.4", "raw.githubusercontent.com": "185.199.108.133"}
	c.DDNS.Enabled = true
	c.DDNS.Provider = "cloudflare"
	c.DDNS.Domain = "cf.example.com"
	c.DDNS.TTL = 600
	c.DDNS.Proxied = true
	c.DDNS.IPCount = 3
	c.DDNS.RecordType = ddns.ModeBoth
	// 账本：本工具在 AdGuard 上认领过的域名（含通配符，也含一个已经从列表里
	// 删掉的）。它决定「下次同步能清掉哪些旧记录」，所以必须跟着备份走。
	c.RewrittenDomains = []string{"openai.com", "*.openai.com", "cf.example.com", "old.example.com"}
	return *c
}

// TestBuildBundleCarriesEveryUserSetting 导出文件里必须逐项带上这些设置。
//
// 这是一张「清单」而不是逻辑测试：config.Config 里多一个用户能改的字段，
// 这里就得加一行。bundleConfig 是手写的显式清单，不加不会报错——只会静默丢。
func TestBuildBundleCarriesEveryUserSetting(t *testing.T) {
	in := fullConfig()
	b := buildBundle(in, map[string]string{"CF_API_TOKEN": "tok"}, "1.7.4",
		time.Date(2026, 11, 18, 17, 0, 0, 0, time.UTC))
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}

	var doc struct {
		Config map[string]any `json:"config"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("反解失败: %v", err)
	}
	c := doc.Config

	for _, k := range []string{
		"ipv6_probe_url", "ddns_ttl", "ddns_proxied", "ddns_ip_count",
		"ddns_record_type", "domain_meta", "rewritten_domains",
		"hosts_enabled", "hosts_source", "hosts_entries",
	} {
		if _, ok := c[k]; !ok {
			t.Errorf("导出文件里少了 %q —— 恢复之后这一项会被静默重置：%s", k, raw)
		}
	}
	// 账本丢了不会让界面出错，但会让「删掉的域名」在 AdGuard 上留下永久残留，
	// 所以同样算必须带上的项。
	if got, _ := c["rewritten_domains"].([]any); len(got) != 4 {
		t.Errorf("AdGuard 域名账本应带 4 条，实际 %v", c["rewritten_domains"])
	}
	if got := c["ddns_record_type"]; got != ddns.ModeBoth {
		t.Errorf("记录类型应为 %q，实际 %v（丢了会让 v6 记录停止写入）", ddns.ModeBoth, got)
	}
	if got, _ := c["ddns_ttl"].(float64); got != 600 {
		t.Errorf("TTL 应为 600，实际 %v", c["ddns_ttl"])
	}
	if got := c["ddns_proxied"]; got != true {
		t.Errorf("橙云开关应为 true，实际 %v", got)
	}
	if got, _ := c["ddns_ip_count"].(float64); got != 3 {
		t.Errorf("同步条数应为 3，实际 %v", c["ddns_ip_count"])
	}
	if got := c["ipv6_probe_url"]; got != in.IPv6ProbeURL {
		t.Errorf("IPv6 段链接没原样带上: %q", got)
	}
	if got := c["hosts_enabled"]; got != true {
		t.Errorf("hosts 源开关没带上: %v —— 恢复后这一块会整块被跳过", got)
	}
	if got := c["hosts_source"]; got != in.HostsSource {
		t.Errorf("hosts 源链接没原样带上: %q", got)
	}
	if got, _ := c["hosts_entries"].(map[string]any); len(got) != 2 {
		t.Errorf("hosts 账本应带 2 条，实际 %v", c["hosts_entries"])
	}
	meta, _ := c["domain_meta"].(map[string]any)
	if len(meta) != 2 {
		t.Fatalf("域名的附加设置应带 2 条，实际 %v", meta)
	}
	if m, _ := meta["openai.com"].(map[string]any); m["wildcard"] != true {
		t.Errorf("「包含子域」勾选没带上: %v", meta["openai.com"])
	}
}

// TestImportRestoresEverySetting 导出再导入，每一项都要回到原值。
func TestImportRestoresEverySetting(t *testing.T) {
	s, _ := newPasswordTestServer(t, "")
	token := s.signToken()
	want := fullConfig()

	raw, err := json.Marshal(buildBundle(want, nil, "1.7.4", time.Now()))
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}

	// 先把当前设置改成「和备份完全不同的另一套」。不这么做的话，就算导入
	// 什么都没干，后面的断言也会因为「本来就是原值」而全绿。
	s.mu.Lock()
	s.cfg.AdGuard.URL = "http://127.0.0.1:1/"
	s.cfg.Domains = []string{"other.example.com"}
	s.cfg.DomainMeta = map[string]config.DomainMeta{"other.example.com": {Wildcard: true}}
	s.cfg.IPv6ProbeURL = ""
	s.cfg.HostsEnabled = false
	s.cfg.HostsSource = "https://other.example.com/hosts.txt"
	s.cfg.HostsEntries = map[string]string{"other.example.com": "1.2.3.4"}
	s.cfg.DDNS.TTL = 0
	s.cfg.DDNS.Proxied = false
	s.cfg.DDNS.IPCount = 1
	s.cfg.DDNS.RecordType = ddns.TypeA
	s.cfg.RewrittenDomains = []string{"other.example.com"}
	s.mu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/api/config/import", strings.NewReader(string(raw)))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("导入应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Warnings []string `json:"warnings"`
		Restored []string `json:"restored"`
		Kept     []string `json:"kept"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应解析失败: %s", rec.Body.String())
	}
	if len(resp.Warnings) != 0 {
		t.Errorf("正常备份不该有提示: %v", resp.Warnings)
	}
	if len(resp.Kept) != 0 {
		t.Errorf("新备份里每一项都在，不该有「保持原值」的项: %v", resp.Kept)
	}

	s.mu.Lock()
	got := *s.cfg
	s.mu.Unlock()

	if got.AdGuard.URL != want.AdGuard.URL {
		t.Errorf("AdGuard 地址: %q ≠ %q", got.AdGuard.URL, want.AdGuard.URL)
	}
	if got.IPv6ProbeURL != want.IPv6ProbeURL {
		t.Errorf("IPv6 段链接: %q ≠ %q", got.IPv6ProbeURL, want.IPv6ProbeURL)
	}
	// hosts 源：开关 + 链接 + 账本全都要回来。开关丢了会导致 AdGuard 上那几十条
	// 在下一轮被整份清掉；账本丢了则相反——源里删掉的域名会永远留在 AdGuard 上。
	if !got.HostsEnabled || got.HostsSource != want.HostsSource {
		t.Errorf("hosts 源没恢复: enabled=%v source=%q", got.HostsEnabled, got.HostsSource)
	}
	if len(got.HostsEntries) != 2 || got.HostsEntries["github.com"] != "140.82.113.4" {
		t.Errorf("hosts 账本没恢复: %v", got.HostsEntries)
	}
	if got.DDNS.TTL != 600 || !got.DDNS.Proxied || got.DDNS.IPCount != 3 {
		t.Errorf("DDNS 三项没恢复: TTL=%d proxied=%v 条数=%d",
			got.DDNS.TTL, got.DDNS.Proxied, got.DDNS.IPCount)
	}
	if got.DDNS.RecordType != ddns.ModeBoth {
		t.Errorf("记录类型应为 %q，实际 %q —— 恢复后 v6 记录会停写", ddns.ModeBoth, got.DDNS.RecordType)
	}
	if m, ok := got.DomainMeta["openai.com"]; !ok || !m.Wildcard {
		t.Errorf("「包含子域」标记丢了: %v", got.DomainMeta)
	}
	// 账本要跟着文件走：否则换机恢复后，已经不在这份清单里的域名会在 AdGuard
	// 上留下一条指向旧 IP 的永久残留。
	if len(got.RewrittenDomains) != 4 || got.RewrittenDomains[3] != "old.example.com" {
		t.Errorf("AdGuard 域名账本没恢复: %v", got.RewrittenDomains)
	}
	// 删掉的域名不该留下元信息（否则下次同名域名会「继承」上一次的勾选）。
	if _, ok := got.DomainMeta["other.example.com"]; ok {
		t.Errorf("旧域名的附加设置没清掉: %v", got.DomainMeta)
	}

	// 落盘的 config.json 也要有，重启之后不能又变回去。
	saved, err := os.ReadFile(filepath.Join(filepath.Dir(config.EnvFilePath()), "config.json"))
	if err != nil {
		t.Fatalf("读回 config.json 失败: %v", err)
	}
	for _, want := range []string{`"record_type": "A+AAAA"`, `"ttl": 600`, `"ip_count": 3`, `"wildcard": true`} {
		if !strings.Contains(string(saved), want) {
			t.Errorf("config.json 里少了 %s：%s", want, saved)
		}
	}
}

// TestImportOldBundleKeepsNewSettings 老备份（这八项之外的一切都有、这八项都没有）
// 导入时，这八项必须保持当前值，而且要在响应里明说「没有恢复」。
//
// 用户 2026-11-18 导出的那份 1.7.3 备份正是这个形状。若不这样处理，一次
// 「恢复备份」会把记录类型拨回 A、v6 段链接清空——界面只说「已恢复」。
//
// 八项而不是六项：v1.7.6 加了 hosts 源那一块（开关 + 链接），老文件里同样
// 没有它，所以「文件里没有、保持原值」的清单跟着变成 8 项。这个数字每加一个
// 用户能设的项就会变——它变了不是坏事，说明清单确实在跟着配置走。
func TestImportOldBundleKeepsNewSettings(t *testing.T) {
	s, _ := newPasswordTestServer(t, "")
	token := s.signToken()

	s.mu.Lock()
	s.cfg.Domains = []string{"keep.example.com"}
	s.cfg.DomainMeta = map[string]config.DomainMeta{"keep.example.com": {Wildcard: true}}
	s.cfg.IPv6ProbeURL = "https://example.com/keep-v6.txt"
	s.cfg.HostsEnabled = true
	s.cfg.HostsSource = "https://hosts.example.com/hosts.txt"
	s.cfg.DDNS.TTL = 3600
	s.cfg.DDNS.Proxied = true
	s.cfg.DDNS.IPCount = 5
	s.cfg.DDNS.RecordType = ddns.TypeAAAA
	s.mu.Unlock()

	// v1.7.3 那代导出的文件：用户在界面上能改的其它项都在，只缺下面这八项。
	// 形状照用户 2026-11-18 那份真实备份抄的，不是凭空编的。
	old := `{
	  "app":"cf-ddns-sidecar","format":1,"version":"1.7.3",
	  "config":{
	    "adguard_url":"http://10.0.0.9:3000","adguard_username":"u",
	    "adguard_password":"adg-pass",
	    "domains":["keep.example.com"],
	    "top_n":3,"bandwidth_candidates":50,"interval_minutes":20,
	    "extra_sources":["https://example.com/ips.txt"],
	    "engine_overrides":{"IP_CALIBRATION_ENABLED":true},
	    "ddns_enabled":true,"ddns_provider":"cloudflare","ddns_domain":"cf.example.com"
	  }
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/config/import", strings.NewReader(old))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("导入应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Kept     []string `json:"kept"`
		Restored []string `json:"restored"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应解析失败: %s", rec.Body.String())
	}
	if len(resp.Kept) != 8 {
		t.Errorf("应明确列出 8 项「文件里没有、保持原值」，实际 %v", resp.Kept)
	}

	s.mu.Lock()
	got := *s.cfg
	s.mu.Unlock()

	if got.DDNS.RecordType != ddns.TypeAAAA {
		t.Errorf("记录类型被老备份改掉了：%q —— 这正是「恢复后 v6 停写」的来源", got.DDNS.RecordType)
	}
	if got.IPv6ProbeURL != "https://example.com/keep-v6.txt" {
		t.Errorf("IPv6 段链接被清空了: %q", got.IPv6ProbeURL)
	}
	if got.DDNS.TTL != 3600 || !got.DDNS.Proxied || got.DDNS.IPCount != 5 {
		t.Errorf("DDNS 三项被改掉了: TTL=%d proxied=%v 条数=%d",
			got.DDNS.TTL, got.DDNS.Proxied, got.DDNS.IPCount)
	}
	// hosts 那一块：老文件里没有它，所以「开着」和「填了链接」都得留着。
	// 关掉等于用户下次测速时 AdGuard 上那几十条被整份清掉，而界面写着「已恢复」。
	if !got.HostsEnabled || got.HostsSource != "https://hosts.example.com/hosts.txt" {
		t.Errorf("hosts 源被老备份改掉了: enabled=%v source=%q", got.HostsEnabled, got.HostsSource)
	}
	if m, ok := got.DomainMeta["keep.example.com"]; !ok || !m.Wildcard {
		t.Errorf("「包含子域」标记被清掉了: %v", got.DomainMeta)
	}
	// 账本不在 restored/kept 两本账里（它不是用户设的项），但老文件里没有它时
	// 必须保持当前值——清了就等于下次同步要把自己刚写的记录再删一遍。
	if len(got.RewrittenDomains) != 0 && got.RewrittenDomains[0] != "keep.example.com" {
		t.Errorf("账本被老备份改掉了: %v", got.RewrittenDomains)
	}
	// 文件里有的那些照旧要被覆盖。
	if got.Speed.TopN != 3 || got.Speed.IntervalMinutes != 20 {
		t.Errorf("老文件里有的项应照常恢复: top_n=%d 间隔=%d", got.Speed.TopN, got.Speed.IntervalMinutes)
	}
}

// TestExportImportEndToEnd 走真实 HTTP：导出拿到的文件，改一改再导入回来。
func TestExportImportEndToEnd(t *testing.T) {
	s, _ := newPasswordTestServer(t, "")
	s.mu.Lock()
	s.cfg.AdGuard.URL = "http://10.0.0.5:3000"
	s.cfg.Domains = []string{"openai.com"}
	s.cfg.DDNS.Provider = "cloudflare"
	s.mu.Unlock()

	envPath := config.EnvFilePath()
	if err := os.WriteFile(envPath, []byte("CF_API_TOKEN=old-token\nCF_ZONE_ID=old-zone\n"), 0o644); err != nil {
		t.Fatalf("准备 ddns.env 失败: %v", err)
	}
	token := s.signToken()

	// ---- 导出 ----
	req := httptest.NewRequest(http.MethodGet, "/api/config/export", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("导出应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") ||
		!strings.Contains(cd, ".json") {
		t.Errorf("Content-Disposition 不对: %q", cd)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("带密钥的响应必须 no-store，实际 %q", cc)
	}
	exported := rec.Body.String()
	if !strings.Contains(exported, "old-token") {
		t.Errorf("导出文件里没有密钥：%s", exported)
	}

	// ---- 导入（用导出内容改几处）----
	var b bundle
	if err := json.Unmarshal([]byte(exported), &b); err != nil {
		t.Fatalf("导出的内容解析失败: %v", err)
	}
	b.Config.AdGuardURL = "http://10.0.0.77:3000"
	b.Config.Domains = []string{"restored.example.com"}
	b.Config.IntervalMinutes = 45
	b.Secrets["CF_API_TOKEN"] = "new-token"

	body, _ := json.Marshal(b)
	ireq := httptest.NewRequest(http.MethodPost, "/api/config/import", strings.NewReader(string(body)))
	ireq.Header.Set("Authorization", "Bearer "+token)
	irec := httptest.NewRecorder()
	s.Handler().ServeHTTP(irec, ireq)

	if irec.Code != 200 {
		t.Fatalf("导入应 200，实际 %d：%s", irec.Code, irec.Body.String())
	}

	// 内存里的配置要立刻变（界面刷新就能看到）
	s.mu.Lock()
	gotURL, gotDomains, gotInterval := s.cfg.AdGuard.URL, s.cfg.Domains, s.cfg.Speed.IntervalMinutes
	s.mu.Unlock()
	if gotURL != "http://10.0.0.77:3000" {
		t.Errorf("AdGuard 地址没更新: %q", gotURL)
	}
	if len(gotDomains) != 1 || gotDomains[0] != "restored.example.com" {
		t.Errorf("域名没更新: %v", gotDomains)
	}
	if gotInterval != 45 {
		t.Errorf("间隔没更新: %d", gotInterval)
	}

	// 落盘的 config.json 也要变
	saved, err := os.ReadFile(filepath.Join(filepath.Dir(envPath), "config.json"))
	if err != nil {
		t.Fatalf("读回 config.json 失败: %v", err)
	}
	if !strings.Contains(string(saved), "restored.example.com") {
		t.Errorf("config.json 没落盘新域名：%s", saved)
	}

	// ddns.env 里的密钥也要更新，而且不能多出乱七八糟的东西
	kv := config.LoadEnvFile(envPath)
	if kv["CF_API_TOKEN"] != "new-token" {
		t.Errorf("密钥没写进 ddns.env: %v", kv)
	}
	if kv["CF_ZONE_ID"] != "old-zone" {
		t.Errorf("备份里没带的旧密钥应保留，实际 %v", kv)
	}
}
