package web

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// 这一组测的是「各节点实际出口」那行日志。
//
// 为什么值得单测：它存在的唯一目的是**纠正一条会误导人的信息**（结果里那些
// `#US`）。如果它自己也解析错了、或者失败时编了一个国家出来，问题只会更糟。
// 它又偏偏在最不起眼的位置（测速完成之后、写 DNS 之前），出错了没人会注意。

func TestParseTrace(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantLoc  string
		wantColo string
		wantErr  bool
	}{
		{
			name: "真实返回",
			body: "fl=123abc\nh=cloudflare-ech.com\nip=172.64.229.246\nts=1700000000.1\n" +
				"loc=JP\ncolo=NRT\n",
			wantLoc: "JP", wantColo: "NRT",
		},
		{
			// Windows 换行、大小写混写、值前后带空格，都得认。
			name:    "CRLF 与大小写",
			body:    "loc= hk \r\ncolo= hkg \r\n",
			wantLoc: "HK", wantColo: "HKG",
		},
		{
			// 只有 loc 没有 colo：能说「在 JP」，不能说「在某个机房」。
			name:    "只有国家",
			body:    "loc=SG\n",
			wantLoc: "SG", wantColo: "",
		},
		{
			// 没有 loc 就算失败。只有 colo 时说得出机房却说不出来国家，
			// 拼出来的「/NRT」比不说更难看。
			name:    "只有机房",
			body:    "colo=NRT\n",
			wantErr: true,
		},
		{
			name:    "压根不是 trace",
			body:    "<html><body>404 Not Found</body></html>",
			wantErr: true,
		},
		{
			name:    "空内容",
			body:    "",
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			loc, colo, err := parseTrace(c.body)
			if c.wantErr {
				if err == nil {
					t.Fatalf("应当报错，却解析出 %q/%q", loc, colo)
				}
				return
			}
			if err != nil {
				t.Fatalf("不该报错: %v", err)
			}
			if loc != c.wantLoc || colo != c.wantColo {
				t.Fatalf("得到 %q/%q，期望 %q/%q", loc, colo, c.wantLoc, c.wantColo)
			}
		})
	}
}

func TestExitInfo(t *testing.T) {
	cases := []struct{ colo, want string }{
		{"NRT", "日本·东京(NRT)"},
		{"SIN", "新加坡·新加坡(SIN)"},
		{"LAX", "美国·洛杉矶(LAX)"},
		{"HKG", "中国香港·香港(HKG)"},
		// 表里没有的机房：只给代码，不猜国家（编一个比不给更糟）。
		{"ZZZ", "机房 ZZZ（位置未知）"},
		{"", "位置未知"},
	}
	for _, c := range cases {
		if got := exitInfo(c.colo); got != c.want {
			t.Errorf("exitInfo(%q)=%q，期望 %q", c.colo, got, c.want)
		}
	}
}

// TestColoGeoSanity 守住那张对照表不被写坏：国家/城市不能为空，
// 城市里不能混进「location unknown」这类占位话术（那应该走 fallback 分支）。
func TestColoGeoSanity(t *testing.T) {
	if len(coloGeo) < 30 {
		t.Fatalf("机房表只剩 %d 条，八成是被误删了", len(coloGeo))
	}
	for code, g := range coloGeo {
		if len(code) != 3 {
			t.Errorf("机房代码 %q 不是 3 位", code)
		}
		if g.country == "" || g.city == "" {
			t.Errorf("%s 的国家或城市为空: %+v", code, g)
		}
		// code 是给「按国家筛」用的两位代码，写错的表现是「筛了等于没筛」：
		// 拿中文名或三位写法去和 HK/JP 比，永远对不上，而且不报错。
		if len(g.code) != 2 || strings.ToUpper(g.code) != g.code {
			t.Errorf("%s 的两位国家代码不合法: %q（应是大写两位，如 JP / HK）", code, g.code)
		}
		if countryCode(code) != g.code {
			t.Errorf("%s 用 countryCode() 查不到自己的代码", code)
		}
	}
	if countryCode("ZZZ") != "" {
		t.Error("表里没有的机房应返回空串，不能瞎猜一个国家")
	}
}

// TestTraceViaLocalServer 真正跑一遍「穿过某个 IP 去请求一个 HTTPS 主机」。
//
// 这一步是整段代码最容易写错的地方：我们故意让 DialContext 忽略目标地址、
// 一律连到候选 IP 上，同时把 SNI 写成 traceHost——写反了就是「连到候选 IP
// 却拿着 A 主机的 SNI」，真机上表现为永远 403/握手失败。用一个自签证书的
// 本地 TLS 服务器就能把这条链路完整走一遍。
func TestTraceViaLocalServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != tracePath {
			t.Errorf("请求路径 %q，期望 %q", r.URL.Path, tracePath)
		}
		// 请求头里的 Host 必须是我们钉的那个主机名，否则 Cloudflare 会按
		// 别的站点处理，trace 拿不到正确结果。
		if r.Host != "example.com" {
			t.Errorf("Host 是 %q，期望 example.com", r.Host)
		}
		_, _ = w.Write([]byte("loc=JP\ncolo=NRT\n"))
	}))
	defer srv.Close()

	addr, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("拿不到监听端口: %T", srv.Listener.Addr())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	loc, colo, err := traceVia(ctx, "example.com", "127.0.0.1", addr.Port)
	if err != nil {
		t.Fatalf("穿过本地服务器探测失败: %v", err)
	}
	if loc != "JP" || colo != "NRT" {
		t.Fatalf("得到 %q/%q，期望 JP/NRT", loc, colo)
	}
}

// TestTraceViaIPv6Loopback 把上面那条链路换成 v6 再走一遍。
//
// 为什么要专门测：traceVia 里是 net.JoinHostPort(ip, port)，v6 必须由它补上
// 方括号（`[::1]:8443`），否则会拼成 `::1:8443` 这种拆不开的串，连都连不上。
// 而 v6 优选的结果里地址是**不带**方括号的（engine.parseOutput 用 SplitHostPort
// 剥掉了），所以这条转换是必经之路——写错了真机上就是整列「位置未知」，
// 而且日志只会说「探测不到」，看不出是拼串的错。
//
// 没有 v6 回环的环境（不少容器默认关掉）直接跳过，不算失败。
func TestTraceViaIPv6Loopback(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("本机没有 v6 回环，跳过: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com" {
			t.Errorf("Host 是 %q，期望 example.com", r.Host)
		}
		_, _ = w.Write([]byte("loc=JP\ncolo=NRT\n"))
	}))
	_ = srv.Listener.Close()
	srv.Listener = ln
	srv.StartTLS()
	defer srv.Close()

	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("拿不到监听端口: %T", ln.Addr())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	loc, colo, err := traceVia(ctx, "example.com", "::1", addr.Port)
	if err != nil {
		t.Fatalf("穿过本地 v6 服务器探测失败: %v", err)
	}
	if loc != "JP" || colo != "NRT" {
		t.Fatalf("得到 %q/%q，期望 JP/NRT", loc, colo)
	}
}

// TestTraceThroughHostsFallback 验证「主域名失败→换备用域名补一次」这条路径。
// 本机连不上真 Cloudflare，用本地 TLS 服务器按 Host 头区分两个域名：
// main.local 故意返回 500，fb.local 返回正常 trace。穿过的是同一个本地 IP，
// 只是 SNI/Host 不同——正好复刻真机上「主域名不通、备用能通」的情形。
func TestTraceThroughHostsFallback(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "main.local" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("loc=JP\ncolo=NRT\n"))
	}))
	defer srv.Close()

	addr, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("拿不到监听端口: %T", srv.Listener.Addr())
	}
	ctx, cancel := context.WithTimeout(context.Background(), traceTimeout+traceFallbackTimeout)
	defer cancel()
	loc, colo, err := traceThroughHosts(ctx, "127.0.0.1", addr.Port, "main.local", "fb.local")
	if err != nil {
		t.Fatalf("主域名失败后换备用应成功，却报错: %v", err)
	}
	if loc != "JP" || colo != "NRT" {
		t.Fatalf("得到 %q/%q，期望 JP/NRT", loc, colo)
	}
}

// TestTraceThroughHostsAllFail 两个域名都失败时必须如实报错，不能编一个机房出来。
func TestTraceThroughHostsAllFail(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	addr, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("拿不到监听端口: %T", srv.Listener.Addr())
	}
	ctx, cancel := context.WithTimeout(context.Background(), traceTimeout+traceFallbackTimeout)
	defer cancel()
	_, _, err := traceThroughHosts(ctx, "127.0.0.1", addr.Port, "main.local", "fb.local")
	if err == nil {
		t.Fatal("两个域名都返回 500，却没报错")
	}
}

// TestLogExitCountriesNoIP 没有结果时一个字都不该写。
// 否则一次失败的重试也会留下「各节点实际出口：」这种半句话。
func TestLogExitCountriesNoIP(t *testing.T) {
	s := newTestServer("pw")
	s.logExitCountries(context.Background(), nil)

	s.mu.Lock()
	n := len(s.logs)
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("没有 IP 却写了日志: %v", s.logs)
	}
}

// TestLogExitCountriesDeadline 探测不到时要说「探测不到」，不能说成别的。
//
// 这里连的是一个必然拒连的端口（127.0.0.1 上没监听），所以整条链路会快速
// 失败——正是真机上「节点能测速但连不上 trace 域名」的等价情形。
func TestLogExitCountriesDeadline(t *testing.T) {
	s := newTestServer("pw")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s.logExitCountries(ctx, []string{"127.0.0.1", "127.0.0.2"})

	s.mu.Lock()
	logs := append([]string(nil), s.logs...)
	s.mu.Unlock()

	if len(logs) != 1 {
		t.Fatalf("应当只有一行日志，实际 %d 行: %v", len(logs), logs)
	}
	if !strings.Contains(logs[0], "探测不到") {
		t.Fatalf("日志应当说明探测不到，实际: %q", logs[0])
	}
	if strings.Contains(logs[0], "→JP") || strings.Contains(logs[0], "→US") {
		t.Fatalf("探测失败却编了一个国家出来: %q", logs[0])
	}
}

// TestExitProbePlan 探测条数必须跟结果条数走，并且封顶；预算按并发轮数给够。
// 以前写死 5 条、固定 8 秒，结果一多就既漏探又超时。
func TestExitProbePlan(t *testing.T) {
	cases := []struct {
		total      int
		wantN      int
		wantBudget time.Duration
	}{
		{0, 0, 0},
		{5, 5, 14 * time.Second},   // 一轮：主 8 + 备 4 + 2 秒余量
		{8, 8, 14 * time.Second},   // 8 个并发刚好一轮
		{10, 10, 26 * time.Second}, // 两轮
		{20, 20, 38 * time.Second}, // 三轮，正好到上限
		{100, 20, 38 * time.Second},
	}
	for _, tc := range cases {
		gotN, gotBudget := exitProbePlan(tc.total)
		if gotN != tc.wantN || gotBudget != tc.wantBudget {
			t.Errorf("exitProbePlan(%d) = (%d, %v)，期望 (%d, %v)",
				tc.total, gotN, gotBudget, tc.wantN, tc.wantBudget)
		}
	}
}

// TestLogExitCountriesProbeCount 回归用户报的问题：
// 「保留候选 IP 数」设成 10 时，后 5 条不能再是「位置未知」。
func TestLogExitCountriesProbeCount(t *testing.T) {
	old := traceThrough
	defer func() { traceThrough = old }()
	var calls atomic.Int32
	traceThrough = func(_ context.Context, _ string, _ int) (string, string, error) {
		calls.Add(1)
		return "JP", "NRT", nil
	}

	ips := make([]string, 10)
	for i := range ips {
		ips[i] = fmt.Sprintf("127.0.0.%d", i+1)
	}
	s := newTestServer("pw")
	colos := s.logExitCountries(context.Background(), ips)

	if got := int(calls.Load()); got != 10 {
		t.Fatalf("10 个结果应探 10 次，实际 %d 次", got)
	}
	for _, ip := range ips {
		if colos[ip] != "NRT" {
			t.Errorf("%s 没拿到机房代码，界面会显示位置未知：%q", ip, colos[ip])
		}
	}
}

// TestLogExitCountriesCap 超过上限时只探前 20 个，并在日志里说清楚，
// 不能让后半段无声无息地变成「位置未知」。
func TestLogExitCountriesCap(t *testing.T) {
	old := traceThrough
	defer func() { traceThrough = old }()
	var calls atomic.Int32
	traceThrough = func(_ context.Context, _ string, _ int) (string, string, error) {
		calls.Add(1)
		return "JP", "NRT", nil
	}

	ips := make([]string, 100)
	for i := range ips {
		ips[i] = fmt.Sprintf("10.0.0.%d", i+1)
	}
	s := newTestServer("pw")
	s.logExitCountries(context.Background(), ips)

	if got := int(calls.Load()); got != exitProbesMax {
		t.Fatalf("应只探 %d 次，实际 %d 次", exitProbesMax, got)
	}
	s.mu.Lock()
	logs := append([]string(nil), s.logs...)
	s.mu.Unlock()
	if !strings.Contains(strings.Join(logs, " "), fmt.Sprintf("只探前 %d 个", exitProbesMax)) {
		t.Fatalf("超过上限却没有日志说明，实际日志：%v", logs)
	}
}
