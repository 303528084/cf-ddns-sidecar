package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
