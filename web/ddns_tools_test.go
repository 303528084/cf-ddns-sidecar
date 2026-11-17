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

// TestAdguardRewritesPreview 预览要能如实反映「下次测速会保留哪几条、清掉哪几条」。
// 这是第 8 项缺口的全部意义：ReplaceRewrites 会清空整张表。
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
		// 三条：一条会被保留、一条同域名但旧 IP（会被清）、一条别人手工加的（也会被清）
		_, _ = w.Write([]byte(`[
			{"domain":"openai.com","answer":"104.16.0.1","enabled":true},
			{"domain":"openai.com","answer":"1.2.3.4","enabled":true},
			{"domain":"my-printer.lan","answer":"192.168.1.9","enabled":true}
		]`))
	}))
	defer srv.Close()

	s := newToolsTestServer(t, func(c *config.Config) {
		c.AdGuard.URL = srv.URL
		c.AdGuard.Username = "admin"
		c.AdGuard.Password = "secret"
		c.Domains = []string{"openai.com", "openrouter.ai"}
		c.LastIP = "104.16.0.1"
	})

	rec := call(s, http.MethodGet, "/api/adguard/rewrites")
	if rec.Code != 200 {
		t.Fatalf("应成功，实际 %d，body=%s", rec.Code, rec.Body.String())
	}
	if !gotAuth {
		t.Fatal("没有把 AdGuard 的用户名密码带上，真实环境会 401")
	}

	var resp struct {
		OK       bool              `json:"ok"`
		Entries  []json.RawMessage `json:"entries"`
		Expected map[string]string `json:"expected"`
		LastIP   string            `json:"last_ip"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("返回的不是合法 JSON: %v，body=%s", err, rec.Body.String())
	}
	if !resp.OK || len(resp.Entries) != 3 {
		t.Fatalf("应原样返回 3 条重写，实际 %d 条", len(resp.Entries))
	}
	if resp.LastIP != "104.16.0.1" {
		t.Fatalf("last_ip 不对: %q", resp.LastIP)
	}
	// 期望集合是「每个要加速的域名 → 当前最优 IP」，前端靠它判断哪几条会被保留
	if len(resp.Expected) != 2 || resp.Expected["openai.com"] != "104.16.0.1" {
		t.Fatalf("expected 不对: %#v", resp.Expected)
	}
}

// TestAdguardRewritesEmptyExpectedWithoutIP 还没测出 IP 时，期望集合必须是空的：
// 这时「下次测速会把所有现存记录清掉」就是实话，界面上的黄色标记并不夸张。
func TestAdguardRewritesEmptyExpectedWithoutIP(t *testing.T) {
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
		Expected map[string]string `json:"expected"`
	}
	rec := call(s, http.MethodGet, "/api/adguard/rewrites")
	if rec.Code != 200 {
		t.Fatalf("应成功，实际 %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(resp.Expected) != 0 {
		t.Fatalf("没有最优 IP 时期望集合应为空，实际 %#v", resp.Expected)
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
