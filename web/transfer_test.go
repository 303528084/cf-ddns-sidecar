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
