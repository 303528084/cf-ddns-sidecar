package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/303528084/cf-ddns-sidecar/config"
)

// handleIPv6 只读，不碰 Server 的任何字段——所以零值 Server 就能测。
// 它读的是 /proc/net/if_inet6，只有 Linux 有；Windows/macOS 上没有这个文件，
// 那边期望的是 503 + ok:false（界面据此提示要去 NAS 上跑）。两条路都算真实行为，分开断言。
func TestHandleIPv6(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/ipv6", nil)
	s.handleIPv6(rec, req)

	if runtime.GOOS != "linux" {
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("非 Linux 上状态码 = %d，期望 503；body=%s", rec.Code, rec.Body.String())
		}
		return
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200；body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		OK     bool `json:"ok"`
		Report struct {
			Available  bool   `json:"available"`
			Total      int    `json:"total"`
			Source     string `json:"source"`
			Candidates []struct {
				Address  string `json:"address"`
				Selected bool   `json:"selected"`
			} `json:"candidates"`
		} `json:"report"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if !resp.OK {
		t.Fatalf("ok 应为 true")
	}
	if resp.Report.Source == "" {
		t.Fatalf("report.source 不该为空")
	}
	// 若真有选中地址，选中标记最多出现一次（与 ipv6 包的单测约定一致）。
	sel := 0
	for _, c := range resp.Report.Candidates {
		if c.Selected {
			sel++
		}
	}
	if sel > 1 {
		t.Fatalf("选中标记出现 %d 次，最多 1 次", sel)
	}
}

// statusLastV6 走一次 /api/status 的响应体，只看概览页那行 v6 读到的地址和位置。
// 直接调 handleStatus：鉴权在包装层，这个函数自己只写 JSON。
func statusLastV6(t *testing.T, s *Server) ([]string, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleStatus(rec, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200", rec.Code)
	}
	var resp struct {
		LastV6IPs   []string `json:"last_v6_ips"`
		LastV6Place string   `json:"last_v6_place"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	return resp.LastV6IPs, resp.LastV6Place
}

// TestStatusLastV6SeededFromConfig 守「重启之后概览页那行 v6 还在」。
//
// 内存里那份重启就没了，而下面那张表有空就回落配置（handleIPv6ProbeResult），
// 于是卡片上的 v6 消失、表格里十条还在。两处说的本该是同一次探测的结果。
func TestStatusLastV6SeededFromConfig(t *testing.T) {
	cfg := config.Default()
	cfg.IPv6SourceMode = config.SourceBuiltin
	cfg.LastIPv6 = "2408:8207:1::1"
	cfg.LastIPv6IPs = []string{"2408:8207:1::1", "2408:8207:1::2"}
	cfg.LastIPv6Nodes = []config.NodeStat{
		{IP: "2408:8207:1::1", Speed: 6.4, Colo: "HKG", Place: "中国香港·香港(HKG)"},
		{IP: "2408:8207:1::2", Speed: 5.1, Colo: "LAX", Place: "美国·洛杉矶(LAX)"},
	}

	s := New(cfg, "", "", t.TempDir(), Auth{}, "", nil)
	got, place := statusLastV6(t, s)
	if len(got) != 2 || got[0] != "2408:8207:1::1" || got[1] != "2408:8207:1::2" {
		t.Fatalf("重启后报出的 v6 = %v，期望接着配置里那两条", got)
	}
	// 位置给的是最快那条的，不是「随便一条」。
	if place != "中国香港·香港(HKG)" {
		t.Fatalf("v6 那行的位置 = %q，期望最快那条的 %q", place, "中国香港·香港(HKG)")
	}

	// 探测跑过之后以内存那份为准：它比配置新，而且 v6 关掉时只有它能被清空。
	s.mu.Lock()
	s.lastV6IPs = []string{"2408:8207:9::9"}
	s.mu.Unlock()
	if got, _ := statusLastV6(t, s); len(got) != 1 || got[0] != "2408:8207:9::9" {
		t.Fatalf("内存里有新结果时 = %v，期望报新的那条", got)
	}
}

// TestStatusLastV6EmptyWhenOff 守「v6 关掉之后卡片不该还挂着上一次的地址」。
// 配置里那份是关掉之前的，接着显示等于告诉用户「你还有 v6」，与开关对着干。
func TestStatusLastV6EmptyWhenOff(t *testing.T) {
	cfg := config.Default()
	cfg.IPv6SourceMode = config.SourceOff
	cfg.LastIPv6IPs = []string{"2408:8207:1::1"}
	cfg.LastIPv6Nodes = []config.NodeStat{{IP: "2408:8207:1::1", Colo: "HKG", Place: "中国香港·香港(HKG)"}}

	s := New(cfg, "", "", t.TempDir(), Auth{}, "", nil)
	got, place := statusLastV6(t, s)
	if len(got) != 0 {
		t.Fatalf("v6 关掉之后报出 %v，期望空", got)
	}
	if place != "" {
		t.Fatalf("v6 关掉之后还报位置 %q，期望空", place)
	}
}
