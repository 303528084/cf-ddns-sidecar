package web

// 第三波三个接口的测试。
//
// 这里刻意分成两类：
//   ① 「配错了会怎么说」——用户填密钥时看到的每一句话都是这里断言的，
//      因为 2026-11-17 那次事故里最折磨人的就是「填了，但不知道对不对」。
//   ② 「没准备好时不许乱发请求」——密钥没填全、还没测出 IP、正在测速中，
//      这三种情况都必须当场拒绝，绝不能闷着头去调服务商。
//
// 真正调服务商那段（Verify 只读、EnsureARecord 会写）在 ddns 包里测，
// 那里能替换 API 地址；这一层只测「门口的把关」和 AdGuard 的真实往返。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/303528084/cf-ddns-sidecar/config"
)

// newToolsTestServer 造一个登录态可用的 Server，并允许调用方继续改配置。
func newToolsTestServer(t *testing.T, mutate func(*config.Config)) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	if mutate != nil {
		mutate(cfg)
	}
	return New(cfg, filepath.Join(dir, "config.json"), "", dir,
		Auth{Fallback: "Test-Pass-123"}, "", nil)
}

// call 以已登录身份打一个请求。method 决定用的是 GET 还是 POST。
func call(s *Server, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = "192.168.1.10:5000"
	req.Header.Set("Authorization", "Bearer "+s.signToken())
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// TestDDNSHint 原始错误后面那句人话：这两种归类最有价值，
// 一个是「密钥不对」，一个是「根本连不上」，用户的动作完全不同。
func TestDDNSHint(t *testing.T) {
	cases := []struct {
		err  string
		want string
	}{
		{"api 401: invalid token", "密钥不对"},
		{"HTTP 403 Forbidden", "密钥不对"},
		{"InvalidAccessKeyId.NotFound", "密钥不对"},
		{"AuthFailure.SignatureFailure", "密钥不对"},
		// 网络问题不能被说成密钥问题，否则用户会白改半天密钥
		{"dial tcp: lookup api.cloudflare.com: no such host", "外网出口"},
		{"context deadline exceeded: timeout", "外网出口"},
		{"connection refused", "外网出口"},
		// 认不出来的错误原样返回，不要硬猜
		{"云厂商返回了别的什么", ""},
	}
	for _, c := range cases {
		got := ddnsHint(errStr(c.err))
		if !strings.Contains(got, c.err) {
			t.Errorf("ddnsHint(%q) 丢了原始信息: %q", c.err, got)
		}
		if c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("ddnsHint(%q) 应包含 %q，实际 %q", c.err, c.want, got)
		}
		if c.want == "" && got != c.err {
			t.Errorf("认不出的错误应原样返回，实际 %q", got)
		}
	}
}

type errStr string

func (e errStr) Error() string { return string(e) }

// TestDDNSCheckGuards 配置没到位时，「测试密钥」要当场说清缺什么，
// 而且不能去连服务商（连了也只能得到一句没用的超时）。
func TestDDNSCheckGuards(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*config.Config)
		want   string
	}{
		{
			name:   "没启用",
			mutate: func(c *config.Config) { c.DDNS.Enabled = false },
			want:   "启用",
		},
		{
			name: "没选服务商",
			mutate: func(c *config.Config) {
				c.DDNS.Enabled = true
				c.DDNS.Provider = ""
			},
			want: "服务商",
		},
		{
			name: "没填域名",
			mutate: func(c *config.Config) {
				c.DDNS.Enabled = true
				c.DDNS.Provider = "cloudflare"
				c.DDNS.Domain = ""
			},
			want: "服务商",
		},
		{
			name: "密钥不全",
			mutate: func(c *config.Config) {
				c.DDNS.Enabled = true
				c.DDNS.Provider = "cloudflare"
				c.DDNS.Domain = "cf.example.com"
			},
			want: "缺少密钥",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// 显式清空，免得开发机上的环境变量把「密钥不全」这条测成别的结果
			t.Setenv("CF_API_TOKEN", "")
			t.Setenv("CF_ZONE_ID", "")

			s := newToolsTestServer(t, c.mutate)
			rec := call(s, http.MethodPost, "/api/ddns/check")
			if rec.Code != 400 {
				t.Fatalf("应返回 400，实际 %d，body=%s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), c.want) {
				t.Fatalf("提示应包含 %q，实际 %s", c.want, rec.Body.String())
			}
		})
	}
}

// TestDDNSUpdateRefusesWithoutIP 还没测出最优 IP 时点「立即更新一次」，
// 必须给一句有用的指引，而不是把空 IP 写进解析（那会把域名解析打坏）。
func TestDDNSUpdateRefusesWithoutIP(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "dummy-token")
	t.Setenv("CF_ZONE_ID", "dummy-zone")

	s := newToolsTestServer(t, func(c *config.Config) {
		c.DDNS.Enabled = true
		c.DDNS.Provider = "cloudflare"
		c.DDNS.Domain = "cf.example.com"
		c.LastIP = "" // 关键：还没测过
	})

	rec := call(s, http.MethodPost, "/api/ddns/update")
	if rec.Code != 400 {
		t.Fatalf("没有最优 IP 时应返回 400，实际 %d，body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "立即测速") {
		t.Fatalf("应告诉用户先测速，实际 %s", body)
	}
	if !strings.Contains(body, "测试密钥") {
		t.Fatalf("应提示「只想验密钥就用测试密钥」，实际 %s", body)
	}
}

// TestDDNSUpdateRefusesWhileRunning 正在测速时不许手动推：
// 那一轮结束自己会推，两边同时写同一条记录只会打架。
func TestDDNSUpdateRefusesWhileRunning(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "dummy-token")
	t.Setenv("CF_ZONE_ID", "dummy-zone")

	s := newToolsTestServer(t, func(c *config.Config) {
		c.DDNS.Enabled = true
		c.DDNS.Provider = "cloudflare"
		c.DDNS.Domain = "cf.example.com"
		c.LastIP = "104.16.0.1"
	})
	s.mu.Lock()
	s.running = true
	s.mu.Unlock()

	rec := call(s, http.MethodPost, "/api/ddns/update")
	if rec.Code != 409 {
		t.Fatalf("测速中应返回 409，实际 %d，body=%s", rec.Code, rec.Body.String())
	}
}

// TestDDNSCheckMethodGuard 只接受 POST：这是会碰密钥的操作，
// 挂成 GET 意味着可以被 <img src> 之类的请求顺手触发。
func TestDDNSCheckMethodGuard(t *testing.T) {
	s := newToolsTestServer(t, nil)
	for _, path := range []string{"/api/ddns/check", "/api/ddns/update"} {
		rec := call(s, http.MethodGet, path)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s 用 GET 应返回 405，实际 %d", path, rec.Code)
		}
	}
}

// TestAdguardRewritesPreview 预览要如实反映「下次同步会保留哪几条、改掉哪几条、
// 哪几条根本不归本工具管」。
//
// 这是第 8 项缺口的全部意义：界面必须和真实行为一致。2026-11-18 之前
// ReplaceRewrites 会清空整张表，所以「不归本工具管」和「会被清掉」是同一件事；
// 改成只动自己认领的域名之后，这两种结局必须分开说——把安全的东西标成危险，
// 和把危险的东西标成安全，一样是骗人。
func TestAdguardRewritesPreview(t *testing.T) {
	var gotAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/control/rewrite/list" {
			t.Errorf("意外的请求路径 %s", r.URL.Path)
		}
		if _, _, ok := r.BasicAuth(); ok {
			gotAuth = true
		}
		w.Header().Set("Content-Type", "application/json")
		// 四条：一条会保留、一条同域名但旧 IP（会被改掉）、
		// 一条别人手工加的（不归本工具管，永远不碰）、
		// 一条以前管过但现在已从域名列表删掉的（会被清掉）。
		_, _ = w.Write([]byte(`[
			{"domain":"openai.com","answer":"104.16.0.1","enabled":true},
			{"domain":"openai.com","answer":"1.2.3.4","enabled":true},
			{"domain":"my-printer.lan","answer":"192.168.1.9","enabled":true},
			{"domain":"old.example.com","answer":"104.16.0.9","enabled":true}
		]`))
	}))
	defer srv.Close()

	s := newToolsTestServer(t, func(c *config.Config) {
		c.AdGuard.URL = srv.URL
		c.AdGuard.Username = "admin"
		c.AdGuard.Password = "secret"
		c.Domains = []string{"openai.com", "openrouter.ai"}
		c.LastIP = "104.16.0.1"
		// v6 也写上：以前这里只放 v4 的 IP，导致 v6 那条明明会保留、界面上
		// 却被标成「会被清掉」。
		c.LastIPv6IPs = []string{"2606:4700::1"}
		// 账本里记着 old.example.com，但它已经不在 Domains 里了 → 下次同步清掉。
		c.RewrittenDomains = []string{"openai.com", "openrouter.ai", "old.example.com"}
	})

	rec := call(s, http.MethodGet, "/api/adguard/rewrites")
	if rec.Code != 200 {
		t.Fatalf("应成功，实际 %d，body=%s", rec.Code, rec.Body.String())
	}
	if !gotAuth {
		t.Fatal("没有把 AdGuard 的用户名密码带上，真实环境会 401")
	}

	var resp struct {
		OK      bool                `json:"ok"`
		Entries []json.RawMessage   `json:"entries"`
		Managed map[string][]string `json:"managed"`
		Stale   []string            `json:"stale"`
		LastIP  string              `json:"last_ip"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("返回的不是合法 JSON: %v，body=%s", err, rec.Body.String())
	}
	if !resp.OK || len(resp.Entries) != 4 {
		t.Fatalf("应原样返回 4 条重写，实际 %d 条", len(resp.Entries))
	}
	if resp.LastIP != "104.16.0.1" {
		t.Fatalf("last_ip 不对: %q", resp.LastIP)
	}

	// 归本工具管的两条域名，答案必须同时包含 v4 和 v6
	for _, d := range []string{"openai.com", "openrouter.ai"} {
		got := resp.Managed[d]
		if len(got) != 2 || got[0] != "104.16.0.1" || got[1] != "2606:4700::1" {
			t.Fatalf("%s 的期望答案应是 v4 + v6 两条，实际 %#v", d, got)
		}
	}
	// 别人手工加的域名绝不能出现在 managed 里——出现了就意味着它会被改掉
	if _, ok := resp.Managed["my-printer.lan"]; ok {
		t.Fatal("my-printer.lan 不归本工具管，不该出现在 managed 里")
	}
	// 已删掉的域名要单独列出来，前端据此标「会清掉」
	if len(resp.Stale) != 1 || resp.Stale[0] != "old.example.com" {
		t.Fatalf("stale 应只有 old.example.com，实际 %#v", resp.Stale)
	}
}

// TestAdguardRewritesEmptyManagedWithoutIP 还没测出 IP 时 managed 必须是空的：
// 这时「下次同步会把我们写过的记录改掉」也就是实话，界面上的黄色标记并不夸张。
func TestAdguardRewritesEmptyManagedWithoutIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"domain":"openai.com","answer":"104.16.0.1","enabled":true}]`))
	}))
	defer srv.Close()

	s := newToolsTestServer(t, func(c *config.Config) {
		c.AdGuard.URL = srv.URL
		c.Domains = []string{"openai.com"}
		c.LastIP = ""
	})

	var resp struct {
		Managed map[string][]string `json:"managed"`
		Stale   []string            `json:"stale"`
	}
	rec := call(s, http.MethodGet, "/api/adguard/rewrites")
	if rec.Code != 200 {
		t.Fatalf("应成功，实际 %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(resp.Managed) != 0 {
		t.Fatalf("没有最优 IP 时 managed 应为空，实际 %#v", resp.Managed)
	}
	if len(resp.Stale) != 0 {
		t.Fatalf("没有账本时 stale 应为空，实际 %#v", resp.Stale)
	}
}

// TestAdguardRewritesErrors 三种失败要说清是哪一种，不能都说「出错了」。
func TestAdguardRewritesErrors(t *testing.T) {
	t.Run("没填地址", func(t *testing.T) {
		s := newToolsTestServer(t, nil)
		rec := call(s, http.MethodGet, "/api/adguard/rewrites")
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), "AdGuard 地址") {
			t.Fatalf("应提示没填地址，实际 %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("连不上", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "nope", http.StatusUnauthorized)
		}))
		defer srv.Close()

		s := newToolsTestServer(t, func(c *config.Config) { c.AdGuard.URL = srv.URL })
		rec := call(s, http.MethodGet, "/api/adguard/rewrites")
		if rec.Code != 502 {
			t.Fatalf("上游报错应映射成 502，实际 %d，body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("方法不对", func(t *testing.T) {
		s := newToolsTestServer(t, nil)
		rec := call(s, http.MethodPost, "/api/adguard/rewrites")
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST 应返回 405，实际 %d", rec.Code)
		}
	})
}

// TestPickForWrite 只锁一件事：门槛怎么筛，其中「不补位」和「速度不能张冠李戴」
// 是两条最容易写错、写错了也不报错的规矩。
func TestPickForWrite(t *testing.T) {
	ips := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}
	nodes := []config.NodeStat{
		{IP: "1.1.1.1", Speed: 20},
		{IP: "2.2.2.2", Speed: 4}, // 低于 10
		{IP: "3.3.3.3", Speed: 0}, // 没测到
		{IP: "4.4.4.4", Speed: 30},
	}

	t.Run("门槛为 0 时原样取前 n 条", func(t *testing.T) {
		got := pickForWrite(ips, nodes, 0, 3)
		if strings.Join(got.IPs, ",") != "1.1.1.1,2.2.2.2,3.3.3.3" {
			t.Fatalf("门槛不限时应原样截前 3 条，实际 %#v", got.IPs)
		}
		if got.dropped() != 0 {
			t.Fatalf("门槛不限时不该有剔除，实际 low=%d nodata=%d", got.Low, got.NoData)
		}
	})

	t.Run("低于门槛和没测到的都剔掉", func(t *testing.T) {
		got := pickForWrite(ips, nodes, 10, 3)
		if strings.Join(got.IPs, ",") != "1.1.1.1" {
			t.Fatalf("应只剩 1.1.1.1，实际 %#v", got.IPs)
		}
		if got.Low != 1 || got.NoData != 1 {
			t.Fatalf("应记 1 条低速 1 条无数据，实际 low=%d nodata=%d", got.Low, got.NoData)
		}
	})

	t.Run("不补位：第 n+1 条再快也不许顶上来", func(t *testing.T) {
		// 4.4.4.4 有 30 Mbps，比谁都快，但它是第 4 条；只要前 3 条。
		// 补位会让「设了 3 条」变成「写了 2 条还说不出为什么」，所以严禁。
		got := pickForWrite(ips, nodes, 10, 3)
		for _, ip := range got.IPs {
			if ip == "4.4.4.4" {
				t.Fatal("不允许从第 n+1 条补位")
			}
		}
	})

	t.Run("全部不达标时返回空", func(t *testing.T) {
		got := pickForWrite(ips, nodes, 100, 4)
		if len(got.IPs) != 0 {
			t.Fatalf("全不达标应为空，实际 %#v", got.IPs)
		}
		if got.dropped() != 4 {
			t.Fatalf("应记 4 条被剔除，实际 %d", got.dropped())
		}
	})

	t.Run("速度按 IP 匹配，不能按下标顶上", func(t *testing.T) {
		// 只有第 2 个 IP 有速度数据。按下标取的话，第 1 个会拿到 100 Mbps
		// 被判成达标——把慢的说成快的，是这里最坏的一种错。
		sparse := []config.NodeStat{{IP: "2.2.2.2", Speed: 100}}
		got := pickForWrite(ips[:2], sparse, 10, 2)
		if len(got.IPs) != 1 || got.IPs[0] != "2.2.2.2" {
			t.Fatalf("只有 2.2.2.2 带自己的速度，应只剩它，实际 %#v", got.IPs)
		}
		if got.NoData != 1 {
			t.Fatalf("1.1.1.1 没有自己的速度数据，应记 1 条无数据，实际 %d", got.NoData)
		}
	})

	t.Run("排名为空时不炸", func(t *testing.T) {
		got := pickForWrite(nil, nil, 10, 5)
		if len(got.IPs) != 0 || got.dropped() != 0 {
			t.Fatalf("空输入应返回空结果，实际 %#v", got)
		}
	})
}

// TestPickOutcomeSkipReason 日志里那句「为什么少写了几条」必须分得清，
// 因为「低于门槛」要改门槛、「没测出速度」要查测速，动作完全不同。
func TestPickOutcomeSkipReason(t *testing.T) {
	if got := (pickOutcome{Low: 2}).skipReason(10); got != "2 条低于 10 Mbps" {
		t.Fatalf("文案不对: %q", got)
	}
	if got := (pickOutcome{NoData: 3}).skipReason(10); got != "3 条没测出速度" {
		t.Fatalf("文案不对: %q", got)
	}
	if got := (pickOutcome{Low: 1, NoData: 2}).skipReason(7.5); got != "1 条低于 7.5 Mbps、2 条没测出速度" {
		t.Fatalf("文案不对: %q", got)
	}
	if got := (pickOutcome{}).skipReason(10); got != "" {
		t.Fatalf("没剔除时不该有文案，实际 %q", got)
	}
}

// TestPickForWriteWithRealRound 用 2026-11-19 那轮真机测速的实际结果锁行为：
// 5 条候选、速度 8.65 / 8.17 / 8.14 / 7.79 / 7.61，从快到慢排好。
// 门槛 8 时该写 3 条，门槛 8.5 时该只写 1 条——「设 5 条写了 3 条」正是
// 用户要的那种结果，不是 bug。
func TestPickForWriteWithRealRound(t *testing.T) {
	ips := []string{"172.64.230.230", "190.93.248.225", "172.64.168.12", "172.64.143.28", "172.64.195.9"}
	nodes := []config.NodeStat{
		{IP: "172.64.230.230", Speed: 8.65, Delay: 23.24},
		{IP: "190.93.248.225", Speed: 8.17, Delay: 26.46},
		{IP: "172.64.168.12", Speed: 8.14, Delay: 20.51},
		{IP: "172.64.143.28", Speed: 7.79, Delay: 23.72},
		{IP: "172.64.195.9", Speed: 7.61, Delay: 19.73},
	}

	if got := pickForWrite(ips, nodes, 8, 5); len(got.IPs) != 3 || got.Low != 2 {
		t.Fatalf("门槛 8 应写 3 条、剔 2 条，实际 %v（low=%d）", got.IPs, got.Low)
	}
	if got := pickForWrite(ips, nodes, 8.5, 5); len(got.IPs) != 1 {
		t.Fatalf("门槛 8.5 应只写 1 条，实际 %v", got.IPs)
	}
	if got := pickForWrite(ips, nodes, 0, 5); len(got.IPs) != 5 {
		t.Fatalf("门槛 0 应原样写 5 条，实际 %v", got.IPs)
	}
	// 门槛比最慢的那条还低一点，一条都不该被剔。
	if got := pickForWrite(ips, nodes, 7.5, 5); len(got.IPs) != 5 {
		t.Fatalf("门槛 7.5 应 5 条全留，实际 %v", got.IPs)
	}
}

// TestDDNSUpdateAllBelowMinSpeed 全部低于门槛时，一条都不能写。
//
// 这里防的是两件事：① 退回 lastIP 把最慢的那条悄悄写上去（那等于绕过用户
// 刚设的标准，而且他还要过半小时才发现）；② 提示成「还没有测出最优 IP」，
// 让人去重跑一轮测速白等两分钟。测出来的地址是有的，只是都不够快。
func TestDDNSUpdateAllBelowMinSpeed(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "dummy-token")
	t.Setenv("CF_ZONE_ID", "dummy-zone")

	s := newToolsTestServer(t, func(c *config.Config) {
		c.DDNS.Enabled = true
		c.DDNS.Provider = "cloudflare"
		c.DDNS.Domain = "cf.example.com"
		c.DDNS.IPCount = 2
		c.DDNS.MinSpeedMbps = 50 // 远高于下面两条
		c.LastIP = "1.1.1.1"
		c.LastIPs = []string{"1.1.1.1", "1.1.1.2"}
		c.LastNodes = []config.NodeStat{
			{IP: "1.1.1.1", Speed: 8.65},
			{IP: "1.1.1.2", Speed: 9.1},
		}
	})

	// 门槛把两条都刷掉，所以根本走不到调服务商那一步，不需要真网络。
	rec := call(s, http.MethodPost, "/api/ddns/update")
	if rec.Code != 400 {
		t.Fatalf("应返回 400，实际 %d，body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "最低下载速度") {
		t.Fatalf("提示该说清是门槛的事，实际 %s", body)
	}
	if strings.Contains(body, "立即测速") {
		t.Fatalf("不该让人去重跑测速——地址有，只是不够快，实际 %s", body)
	}
}
