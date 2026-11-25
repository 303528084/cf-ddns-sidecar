package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/303528084/cf-ddns-sidecar/config"
)

func mkReq(method, target, remote string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = remote
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// TestIsLocalRequest 验证「进程内调用」和「经反代进来的公网请求」能被区分开。
//
// 这是整个加固里最关键的一条：只判 RemoteAddr 是不是 127.0.0.1 的话，
// 加了隧道/反代之后公网请求也会满足条件，接口就对全网敞开。
func TestIsLocalRequest(t *testing.T) {
	cases := []struct {
		name    string
		remote  string
		headers map[string]string
		want    bool
	}{
		{"真本机无转发头", "127.0.0.1:5000", nil, true},
		{"真本机 IPv6 回环", "[::1]:5000", nil, true},
		{"隧道转发带 CF-Connecting-IP", "127.0.0.1:5000", map[string]string{"CF-Connecting-IP": "1.2.3.4"}, false},
		{"反代带 X-Forwarded-For", "127.0.0.1:5000", map[string]string{"X-Forwarded-For": "1.2.3.4"}, false},
		{"反代带 X-Real-IP", "127.0.0.1:5000", map[string]string{"X-Real-IP": "1.2.3.4"}, false},
		{"反代带 Forwarded", "127.0.0.1:5000", map[string]string{"Forwarded": "for=1.2.3.4"}, false},
		{"局域网直连", "192.168.1.5:5000", nil, false},
		{"公网直连", "8.8.8.8:5000", nil, false},
	}
	for _, c := range cases {
		if got := isLocalRequest(mkReq("GET", "/api/candidates", c.remote, c.headers)); got != c.want {
			t.Errorf("%s: isLocalRequest = %v，期望 %v", c.name, got, c.want)
		}
	}
}

// TestClientIP 验证取真实来源 IP 的规则：只有来路是本机（反代/隧道）才采信转发头。
// 直连时如果也采信，攻击者每次伪造一个不同的 X-Forwarded-For 就能绕过限流。
func TestClientIP(t *testing.T) {
	cases := []struct {
		name    string
		remote  string
		headers map[string]string
		want    string
	}{
		{"直连不采信伪造的 XFF", "8.8.8.8:1234", map[string]string{"X-Forwarded-For": "9.9.9.9"}, "8.8.8.8"},
		{"隧道优先用 CF-Connecting-IP", "127.0.0.1:1234", map[string]string{"CF-Connecting-IP": "5.5.5.5", "X-Forwarded-For": "9.9.9.9"}, "5.5.5.5"},
		{"XFF 多值时取第一个", "127.0.0.1:1234", map[string]string{"X-Forwarded-For": "8.8.8.8, 10.0.0.1"}, "8.8.8.8"},
		{"回环无头就用回环", "127.0.0.1:1234", nil, "127.0.0.1"},
	}
	for _, c := range cases {
		if got := clientIP(mkReq("POST", "/api/login", c.remote, c.headers)); got != c.want {
			t.Errorf("%s: clientIP = %q，期望 %q", c.name, got, c.want)
		}
	}
}

// TestLoginThrottle 验证失败计数、锁定、解锁、指数退避和成功清零。
func TestLoginThrottle(t *testing.T) {
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	th := newLoginThrottle()
	th.now = func() time.Time { return clock }

	const ip = "1.2.3.4"

	// 前 4 次失败：还不该锁
	for i := 0; i < throttleMaxFail-1; i++ {
		th.fail(ip)
		if ok, _ := th.allow(ip); !ok {
			t.Fatalf("第 %d 次失败后就被锁了，太早", i+1)
		}
	}
	// 第 5 次失败：锁 5 分钟
	th.fail(ip)
	ok, wait := th.allow(ip)
	if ok {
		t.Fatal("连续失败 5 次后应当锁定，实际仍放行")
	}
	if wait <= 0 || wait > throttleBaseLock {
		t.Fatalf("首次锁定应约 %v，实际 %v", throttleBaseLock, wait)
	}

	// 时间过去 4 分钟：仍在锁
	clock = clock.Add(4 * time.Minute)
	if ok, _ := th.allow(ip); ok {
		t.Fatal("锁定期内不应放行")
	}

	// 过去 6 分钟：解锁
	clock = clock.Add(2 * time.Minute)
	if ok, _ := th.allow(ip); !ok {
		t.Fatal("锁定到期后应放行")
	}

	// 再攒满一轮失败：这次应锁更久（指数退避）
	for i := 0; i < throttleMaxFail; i++ {
		th.fail(ip)
	}
	ok, wait2 := th.allow(ip)
	if ok {
		t.Fatal("第二轮失败应当再次锁定")
	}
	if wait2 <= throttleBaseLock {
		t.Fatalf("第二轮锁定应大于 %v，实际 %v", throttleBaseLock, wait2)
	}

	// 锁定不会无限增长
	for i := 0; i < 20; i++ {
		for j := 0; j < throttleMaxFail; j++ {
			th.fail(ip)
		}
		clock = clock.Add(throttleMaxLock + time.Minute)
	}
	for i := 0; i < throttleMaxFail; i++ {
		th.fail(ip)
	}
	if _, w := th.allow(ip); w > throttleMaxLock {
		t.Fatalf("锁定时间应有上限 %v，实际 %v", throttleMaxLock, w)
	}

	// 成功登录应当清零：另一个 IP 不应受影响
	th.reset(ip)
	if ok, _ := th.allow(ip); !ok {
		t.Fatal("reset 之后应放行")
	}
	for i := 0; i < throttleMaxFail; i++ {
		th.fail("5.6.7.8")
	}
	if ok, _ := th.allow(ip); !ok {
		t.Fatal("别的 IP 被锁不应牵连这个 IP")
	}
}

// TestSecurityHeaders 验证安全头。
//
// 其中「不能出现 X-Frame-Options」是硬性回归保护：飞牛桌面用 iframe 嵌入后台，
// 一旦禁止被嵌入，点桌面图标就是白屏。
func TestSecurityHeaders(t *testing.T) {
	h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, mkReq("GET", "/", "1.2.3.4:1", nil))

	if v := rec.Header().Get("X-Frame-Options"); v != "" {
		t.Fatalf("不能设置 X-Frame-Options（会让飞牛 iframe 图标白屏），实际=%q", v)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("缺少 Content-Security-Policy")
	}
	if !strings.Contains(csp, "frame-ancestors *") {
		t.Errorf("CSP 应允许被 iframe 嵌入，实际=%q", csp)
	}
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP 应限制默认来源为同源，实际=%q", csp)
	}
	if rec.Header().Get("Referrer-Policy") == "" {
		t.Error("缺少 Referrer-Policy")
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("缺少 X-Content-Type-Options: nosniff")
	}
}

func newTestServer(pass string) *Server {
	return &Server{
		pass:     Auth{Fallback: pass},
		throttle: newLoginThrottle(),
	}
}

// TestLoginCookieSecure 验证 Cookie 的 Secure 标记只在 HTTPS 下出现。
// HTTP 下打了 Secure，浏览器会直接丢弃这个 Cookie，表现为「登录成功但下一个请求又 401」。
func TestLoginCookieSecure(t *testing.T) {
	login := func(headers map[string]string, remote string) string {
		s := newTestServer("pw")
		body := strings.NewReader(`{"password":"pw"}`)
		r := httptest.NewRequest("POST", "/api/login", body)
		r.RemoteAddr = remote
		r.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		s.handleLogin(rec, r)
		if rec.Code != 200 {
			t.Fatalf("登录应成功，实际 %d: %s", rec.Code, rec.Body.String())
		}
		return rec.Header().Get("Set-Cookie")
	}

	if c := login(nil, "192.168.1.5:1000"); strings.Contains(c, "Secure") {
		t.Errorf("HTTP 下不应带 Secure，实际=%q", c)
	}
	if c := login(map[string]string{"X-Forwarded-Proto": "https"}, "127.0.0.1:1000"); !strings.Contains(c, "Secure") {
		t.Errorf("HTTPS 下应带 Secure，实际=%q", c)
	}
	if c := login(nil, "127.0.0.1:1000"); !strings.Contains(c, "HttpOnly") {
		t.Errorf("Cookie 应带 HttpOnly，实际=%q", c)
	}
}

// TestLoginThrottleEndToEnd 验证「连着输错密码会被锁」这条用户能感知的行为。
func TestLoginThrottleEndToEnd(t *testing.T) {
	old := loginFailDelay
	loginFailDelay = 0
	defer func() { loginFailDelay = old }()

	s := newTestServer("right-password")
	attempt := func() (int, map[string]string) {
		r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"password":"wrong"}`))
		r.RemoteAddr = "9.9.9.9:1000"
		rec := httptest.NewRecorder()
		s.handleLogin(rec, r)
		var body map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body
	}

	for i := 0; i < throttleMaxFail; i++ {
		if code, _ := attempt(); code != http.StatusUnauthorized {
			t.Fatalf("第 %d 次失败应返回 401，实际 %d", i+1, code)
		}
	}
	code, body := attempt()
	if code != http.StatusTooManyRequests {
		t.Fatalf("连续失败 %d 次后应返回 429，实际 %d", throttleMaxFail, code)
	}
	if body["error"] == "" {
		t.Error("429 响应应带可读的提示文案")
	}

	// 被锁期间即使密码正确也进不去（否则锁就没意义）
	r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"password":"right-password"}`))
	r.RemoteAddr = "9.9.9.9:1000"
	rec := httptest.NewRecorder()
	s.handleLogin(rec, r)
	if rec.Code == 200 {
		t.Fatal("锁定期间即使密码正确也不应放行")
	}
}

// TestCandidatesGuardToken 验证候选接口不再「只要是本机就放行」。
//
// 背景：network_mode: host 下，NAS 上任何本地进程直连 127.0.0.1 都满足
// isLocalRequest，以前那等于把这个接口的认证整个取消。现在除了来源，还必须对上
// 这一轮测速现发的口令；口令随 unstage 失效，且 v4 / v6 各管各的入口。
func TestCandidatesGuardToken(t *testing.T) {
	newSrv := func(t *testing.T) *Server {
		t.Helper()
		return New(config.Default(), filepath.Join(t.TempDir(), "config.json"), "",
			t.TempDir(), Auth{Fallback: "pw"}, "http://127.0.0.1:8080", nil)
	}
	get := func(t *testing.T, s *Server, target, remote string, headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		s.candidatesGuard(w, mkReq("GET", target, remote, headers))
		return w
	}

	t.Run("没有正在进行的测速时本机也不放行", func(t *testing.T) {
		s := newSrv(t)
		if code := get(t, s, "/api/candidates", "127.0.0.1:5000", nil).Code; code != http.StatusForbidden {
			t.Fatalf("期望 403，实际 %d", code)
		}
	})

	t.Run("本机加正确口令放行", func(t *testing.T) {
		s := newSrv(t)
		token := s.stageCandidates("1.2.3.4:443#US\n")
		w := get(t, s, "/api/candidates?token="+token, "127.0.0.1:5000", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("期望 200，实际 %d %s", w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "1.2.3.4:443#US") {
			t.Errorf("响应里没有暂存的候选：%q", w.Body.String())
		}
	})

	t.Run("口令不对拒绝", func(t *testing.T) {
		s := newSrv(t)
		s.stageCandidates("1.2.3.4:443#US\n")
		if code := get(t, s, "/api/candidates?token=deadbeef", "127.0.0.1:5000", nil).Code; code != http.StatusForbidden {
			t.Fatalf("期望 403，实际 %d", code)
		}
	})

	t.Run("口令对但请求来自局域网拒绝", func(t *testing.T) {
		s := newSrv(t)
		token := s.stageCandidates("1.2.3.4:443#US\n")
		if code := get(t, s, "/api/candidates?token="+token, "192.168.1.5:5000", nil).Code; code != http.StatusForbidden {
			t.Fatalf("期望 403，实际 %d", code)
		}
	})

	t.Run("口令随 unstage 失效", func(t *testing.T) {
		s := newSrv(t)
		token := s.stageCandidates("1.2.3.4:443#US\n")
		s.unstageCandidates()
		if code := get(t, s, "/api/candidates?token="+token, "127.0.0.1:5000", nil).Code; code != http.StatusForbidden {
			t.Fatalf("跑完这一轮之后旧口令必须失效，实际 %d", code)
		}
	})

	t.Run("v4 口令开不了 v6 入口", func(t *testing.T) {
		s := newSrv(t)
		token := s.stageCandidates("1.2.3.4:443#US\n")
		if code := get(t, s, "/api/ipv6/candidates?token="+token, "127.0.0.1:5000", nil).Code; code != http.StatusForbidden {
			t.Fatalf("两族口令必须隔离，期望 403，实际 %d", code)
		}
	})

	t.Run("v6 入口用自己的口令放行", func(t *testing.T) {
		s := newSrv(t)
		if err := s.stageIPv6Candidates(context.Background()); err != nil {
			t.Fatalf("暂存 v6 候选失败: %v", err)
		}
		defer s.unstageIPv6Candidates()
		token := s.v6CandToken
		if token == "" {
			t.Fatal("v6 暂存之后必须发出口令，否则引擎会被自己的 403 挡住")
		}
		if code := get(t, s, "/api/ipv6/candidates?token="+token, "127.0.0.1:5000", nil).Code; code != http.StatusOK {
			t.Fatalf("期望 200，实际 %d", code)
		}
	})

	// 这条盯的是「接线」而不是「校验」：真正交给引擎的地址必须能穿过完整的
	// 中间件链（mux → securityHeaders → candidatesGuard）。口令拼错一个参数名，
	// 上面那些直接调 candidatesGuard 的用例全都还是绿的，只有引擎会在运行时
	// 拉回一个 403、然后这一轮「0 节点」。
	t.Run("candidatesURL 拼出的地址能通过完整处理链", func(t *testing.T) {
		s := newSrv(t)
		token := s.stageCandidates("1.2.3.4:443#US\n")
		defer s.unstageCandidates()
		target := s.candidatesURL("/api/candidates", token)
		if target == "" {
			t.Fatal("有候选时必须给出地址，否则引擎会以为这一轮没有本地来源")
		}

		r := mkReq("GET", target, "127.0.0.1:5000", nil)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("引擎拿到的地址被拒了：%d %s（地址 %s）", w.Code, w.Body.String(), target)
		}
		if !strings.Contains(w.Body.String(), "1.2.3.4:443#US") {
			t.Errorf("响应里没有候选：%q", w.Body.String())
		}
	})

	t.Run("已登录用户不带口令也放行", func(t *testing.T) {
		s := newSrv(t)
		s.stageCandidates("1.2.3.4:443#US\n")
		w := get(t, s, "/api/candidates", "192.168.1.5:5000",
			map[string]string{"Authorization": "Bearer " + s.signToken()})
		if w.Code != http.StatusOK {
			t.Fatalf("期望 200，实际 %d %s", w.Code, w.Body.String())
		}
	})
}
