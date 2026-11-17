package web

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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
	cases := []struct{ loc, colo, want string }{
		{"JP", "NRT", "JP/NRT"},
		{"JP", "", "JP"},
		{"", "", "未知"},
	}
	for _, c := range cases {
		if got := exitInfo(c.loc, c.colo); got != c.want {
			t.Errorf("exitInfo(%q,%q)=%q，期望 %q", c.loc, c.colo, got, c.want)
		}
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
