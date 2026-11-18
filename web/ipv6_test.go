package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// handleIPv6 只读，不碰 Server 的任何字段——所以零值 Server 就能测。
// 这组测试在 Linux 容器里跑（本机 CI 也是），/proc/net/if_inet6 一定存在，
// 因此预期是 200 + ok:true；具体有没有 v6 地址取决于运行容器，不做断言。
func TestHandleIPv6(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/ipv6", nil)
	s.handleIPv6(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200；body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		OK     bool `json:"ok"`
		Report struct {
			Available  bool `json:"available"`
			Total      int  `json:"total"`
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
