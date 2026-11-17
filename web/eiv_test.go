package web

// 1034 预筛与实测的测试。
//
// 这一层的错误方向不对称：漏掉一个坏 IP，用户会在浏览器里看到 1034；
// 误杀一个好 IP，用户只会觉得「怎么速度变差了」，而且永远查不出原因。
// 所以下面的用例重点守两件事：**只认确定的 1034**、**只删确定有问题的网段**。

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/303528084/cf-ddns-sidecar/config"
)

func TestInOfficialV4(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
		why  string
	}{
		{"104.16.132.229", true, "官方 104.16.0.0/13"},
		{"172.64.229.179", true, "官方 172.64.0.0/13"},
		{"162.159.5.114", true, "官方 162.158.0.0/15"},
		{"1.1.1.1", false, "官方文档点名的保留地址，正是 1034 的典型来源"},
		{"8.8.8.8", false, "根本不是 Cloudflare"},
		{"104.28.0.1", false, "不在 15 个官方段里的野 IP"},
		{"2606:4700::1", true, "IPv6 不做段判断，放行交给实测"},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("测试数据写错了: %s", c.ip)
		}
		if got := inOfficialV4(ip); got != c.want {
			t.Errorf("%s 应为 %v（%s），实际 %v", c.ip, c.want, c.why, got)
		}
	}
}

func TestIsEIVBlock(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   bool
	}{
		{403, "<html>... error code: 1034 ...</html>", true},
		{403, "Error Code: 1034", true},
		{403, `{"error_code":1034}`, true},
		{200, "error code: 1034", false}, // 200 的页面里出现这串字不能算
		{403, "error code: 1020", false}, // 别的错误码不归这一步管
		{403, "Access denied", false},
		{503, "upstream timeout", false},
	}
	for _, c := range cases {
		if got := isEIVBlock(c.status, c.body); got != c.want {
			t.Errorf("status=%d body=%q 应为 %v，实际 %v", c.status, c.body, c.want, got)
		}
	}
}

func TestCidr24(t *testing.T) {
	if got := cidr24(net.ParseIP("104.16.132.229")); got != "104.16.132.0/24" {
		t.Errorf("应归到 104.16.132.0/24，实际 %s", got)
	}
	// 同 /24 的两个 IP 必须归到同一组，否则「抽一个代表全组」就不成立。
	if a, b := cidr24(net.ParseIP("104.16.132.1")), cidr24(net.ParseIP("104.16.132.254")); a != b {
		t.Errorf("同 /24 应同组，实际 %s != %s", a, b)
	}
	// IPv6 各自成组。
	if got := cidr24(net.ParseIP("2606:4700::1")); got != "2606:4700::1" {
		t.Errorf("IPv6 应各自成组，实际 %s", got)
	}
}

func TestParseCandLine(t *testing.T) {
	cases := []struct {
		in   string
		ip   string
		port int
	}{
		{"104.16.132.229:443#US", "104.16.132.229", 443},
		{"104.16.132.229:8443#JP", "104.16.132.229", 8443},
		{"104.16.132.229", "104.16.132.229", 443},
		{"104.16.132.229#HK", "104.16.132.229", 443},
	}
	for _, c := range cases {
		got := parseCandLine(c.in)
		if got.ip == nil || got.ip.String() != c.ip {
			t.Errorf("%s 的 IP 应为 %s，实际 %v", c.in, c.ip, got.ip)
		}
		if got.port != c.port {
			t.Errorf("%s 的端口应为 %d，实际 %d", c.in, c.port, got.port)
		}
		if got.text != c.in {
			t.Errorf("原文必须原样保留（端口和国家标签不能丢）：%q", got.text)
		}
	}
	// 认不出的行不能崩，ip 为 nil 由调用方放行。
	if got := parseCandLine("这不是一个 IP"); got.ip != nil {
		t.Errorf("认不出的行 ip 应为 nil，实际 %v", got.ip)
	}
}

func TestEIVProbeHosts(t *testing.T) {
	t.Run("自有域名开着云朵才拿去问", func(t *testing.T) {
		cfg := config.Default()
		cfg.DDNS.Enabled = true
		cfg.DDNS.Provider = "cloudflare"
		cfg.DDNS.Proxied = true
		cfg.DDNS.Domain = "cf.example.com"
		got := eivProbeHosts(cfg)
		if len(got) != 1 || got[0] != "cf.example.com" {
			t.Fatalf("应为 [cf.example.com]，实际 %v", got)
		}
	})
	t.Run("关着云朵就不问", func(t *testing.T) {
		// 灰云压根不经过 Cloudflare 边缘，问它只会拿到源站的响应，
		// 那个响应里永远不会有 1034。
		cfg := config.Default()
		cfg.DDNS.Enabled = true
		cfg.DDNS.Provider = "cloudflare"
		cfg.DDNS.Proxied = false
		cfg.DDNS.Domain = "cf.example.com"
		if got := eivProbeHosts(cfg); len(got) != 0 {
			t.Fatalf("灰云不该被拿去探测，实际 %v", got)
		}
	})
	t.Run("两个都测且去重", func(t *testing.T) {
		cfg := config.Default()
		cfg.DDNS.Enabled = true
		cfg.DDNS.Provider = "cloudflare"
		cfg.DDNS.Proxied = true
		cfg.DDNS.Domain = "cf.example.com"
		cfg.Domains = []string{"openai.com", "openrouter.ai"}
		got := eivProbeHosts(cfg)
		if len(got) != 2 || got[0] != "cf.example.com" || got[1] != "openai.com" {
			t.Fatalf("应为 [cf.example.com openai.com]，实际 %v", got)
		}
		cfg.Domains = []string{"cf.example.com"}
		if got := eivProbeHosts(cfg); len(got) != 1 {
			t.Fatalf("同一个域名不该测两遍，实际 %v", got)
		}
	})
	t.Run("带路径的写法不是域名", func(t *testing.T) {
		cfg := config.Default()
		cfg.Domains = []string{"https://openai.com/chat"}
		if got := eivProbeHosts(cfg); len(got) != 0 {
			t.Fatalf("带路径的应被跳过，实际 %v", got)
		}
	})
}

// TestScreenCandidatesRangeOnly 没有可探测的域名时，只做段预筛。
func TestScreenCandidatesRangeOnly(t *testing.T) {
	s := newToolsTestServer(t, func(c *config.Config) {
		c.Domains = nil
		c.DDNS.Enabled = false
	})
	in := strings.Join([]string{
		"104.16.132.229:443#US",
		"1.1.1.1:443#US", // 官方文档点名的 1034 来源
		"8.8.8.8:443#US", // 根本不是 Cloudflare
		"172.64.229.179:443#US",
	}, "\n") + "\n"

	out := s.screenCandidates(context.Background(), s.cfg, in)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("应只剩 2 条官方段内的，实际 %d 条：%v", len(lines), lines)
	}
	for _, ln := range lines {
		if strings.HasPrefix(ln, "1.1.1.1") || strings.HasPrefix(ln, "8.8.8.8") {
			t.Errorf("不在官方段内的没被剔除: %s", ln)
		}
	}
	// 端口和国家标签必须原样保留。
	if !strings.Contains(out, "172.64.229.179:443#US") {
		t.Errorf("端口/国家标签被改动了: %s", out)
	}
	if !strings.Contains(strings.Join(s.logs, "\n"), "候选预筛") {
		t.Errorf("剔除动作必须有日志，实际日志：%v", s.logs)
	}
}

// TestScreenCandidatesDropsBlockedGroup 命中 1034 的网段要整组剔除，
// 并且写进黑名单——下一轮不再重复问。
func TestScreenCandidatesDropsBlockedGroup(t *testing.T) {
	s := newToolsTestServer(t, func(c *config.Config) {
		c.Domains = []string{"openai.com"}
		c.DDNS.Enabled = false
	})

	old := eivProbeFunc
	defer func() { eivProbeFunc = old }()

	var (
		mu   sync.Mutex
		seen []string
	)
	eivProbeFunc = func(ctx context.Context, host, ip string, port int) (int, string, error) {
		mu.Lock()
		seen = append(seen, ip)
		mu.Unlock()
		// 只有 104.16.7.x 这个网段被 EIV 拦，其它正常。
		if strings.HasPrefix(ip, "104.16.7.") {
			return http.StatusForbidden, "blocked: error code: 1034", nil
		}
		return http.StatusOK, "fl=1\nloc=JP\ncolo=NRT", nil
	}

	in := strings.Join([]string{
		"104.16.7.10:443#US",
		"104.16.7.11:443#US", // 同 /24，不该再被探一次
		"104.16.8.10:443#US",
		"104.16.9.10:443#US",
	}, "\n") + "\n"

	out := s.screenCandidates(context.Background(), s.cfg, in)
	if strings.Contains(out, "104.16.7.") {
		t.Errorf("命中 1034 的网段应整组剔除，实际输出：\n%s", out)
	}
	if !strings.Contains(out, "104.16.8.10") || !strings.Contains(out, "104.16.9.10") {
		t.Errorf("其它网段不该被牵连，实际输出：\n%s", out)
	}
	// 同一个 /24 只探一次：这是「按 /24 抽样」的核心，否则等于逐个探。
	mu.Lock()
	defer mu.Unlock()
	n7 := 0
	for _, ip := range seen {
		if strings.HasPrefix(ip, "104.16.7.") {
			n7++
		}
	}
	if n7 != 1 {
		t.Errorf("同一个 /24 应只探 1 次，实际 %d 次（探测列表 %v）", n7, seen)
	}

	// 黑名单落盘，且内容对得上。
	blPath := filepath.Join(filepath.Dir(s.configPath), eivBlockFile)
	raw, err := os.ReadFile(blPath)
	if err != nil {
		t.Fatalf("黑名单没落盘: %v", err)
	}
	var bl eivBlocklist
	if err := json.Unmarshal(raw, &bl); err != nil {
		t.Fatal(err)
	}
	if len(bl.Entries) != 1 || bl.Entries[0].CIDR != "104.16.7.0/24" {
		t.Errorf("黑名单内容不对: %+v", bl.Entries)
	}
	if bl.Entries[0].Host != "openai.com" {
		t.Errorf("应记下是拿哪个域名测出来的，实际 %q", bl.Entries[0].Host)
	}
}

// TestScreenCandidatesProbeErrorKeeps 探测失败（超时/连不上）不是证据，
// 必须原样保留。否则一次网络抖动就会把候选池吃掉一大半，用户只看到
// 「速度变差了」，永远查不出原因。
func TestScreenCandidatesProbeErrorKeeps(t *testing.T) {
	s := newToolsTestServer(t, func(c *config.Config) {
		c.Domains = []string{"openai.com"}
		c.DDNS.Enabled = false
	})

	old := eivProbeFunc
	defer func() { eivProbeFunc = old }()
	eivProbeFunc = func(ctx context.Context, host, ip string, port int) (int, string, error) {
		return 0, "", context.DeadlineExceeded
	}

	in := "104.16.7.10:443#US\n104.16.8.10:443#US\n"
	out := s.screenCandidates(context.Background(), s.cfg, in)
	if strings.Count(out, "\n") != 2 {
		t.Errorf("探测失败不该剔除任何 IP，实际输出：\n%s", out)
	}
	if !strings.Contains(strings.Join(s.logs, "\n"), "未做判断") {
		t.Errorf("该说明「没探通、没做判断」，实际日志：%v", s.logs)
	}
}

// TestEIVBlocklistExpiry 过期记录必须失效：Cloudflare 的分配会变，
// 永久拉黑会让候选池越用越少。
func TestEIVBlocklistExpiry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, eivBlockFile)

	bl := &eivBlocklist{}
	bl.mark("104.16.7.0/24", "openai.com", time.Now())
	bl.save(path)

	ours := map[string]bool{"openai.com": true}
	again := loadEIVBlocklist(path)
	if !again.bad("104.16.7.0/24", ours) {
		t.Fatal("刚写进去的记录应该还在")
	}

	// 换了域名就不该沿用：EIV 是按 zone 判的，这个网段对 openai.com
	// 被拦，不代表对自己的站也被拦。
	if again.bad("104.16.7.0/24", map[string]bool{"mysite.com": true}) {
		t.Error("域名不同时不该拿旧记录去剔除")
	}

	// 手工把时间改成 25 小时前，再读一次。
	again.Entries[0].LastAt = time.Now().Add(-25 * time.Hour).Format(time.RFC3339)
	again.save(path)
	fresh := loadEIVBlocklist(path)
	if fresh.bad("104.16.7.0/24", ours) {
		t.Error("超过 24 小时的记录应失效")
	}
}

// TestEIVProbeReadsBody 真发一次 HTTPS 请求（本地自签服务器），
// 确认「钉 IP + SNI 用 host + 读到 403 正文」这条链路本身是通的。
func TestEIVProbeReadsBody(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cdn-cgi/trace" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html>edge validation failed, error code: 1034</html>"))
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	port := 0
	for _, ch := range portStr {
		port = port*10 + int(ch-'0')
	}

	status, body, err := eivProbe(context.Background(), "example.com", host, port)
	if err != nil {
		t.Fatalf("探测失败: %v", err)
	}
	if status != http.StatusForbidden {
		t.Errorf("状态码应为 403，实际 %d", status)
	}
	if !isEIVBlock(status, body) {
		t.Errorf("应判定为 1034，正文：%s", body)
	}
}
