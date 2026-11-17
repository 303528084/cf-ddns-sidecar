package web

// TTL / 云朵这两个新配置项的保存测试。
//
// 为什么要单独测一层：这两项是「改线上解析」的参数，填错了后果不是报个错
// 就完了——TTL 填 0 会被服务商当成非法值，填 5 秒会被免费版拒绝。所以
// 明显填错的时候必须在保存这一步就挡住，不能等到下一次测速才在日志里冒出来。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// postConfig 以已登录身份 POST 一份配置，返回响应记录器。
func postConfig(t *testing.T, s *Server, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/config", strings.NewReader(string(raw)))
	req.RemoteAddr = "192.168.1.10:5000"
	req.Header.Set("Authorization", "Bearer "+s.signToken())
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// TestSaveConfigTTLRange TTL 只接受 0（默认）或 60–86400。
func TestSaveConfigTTLRange(t *testing.T) {
	cases := []struct {
		ttl     int
		wantOK  bool
		mustSay string
	}{
		{0, true, ""},
		{60, true, ""},
		{600, true, ""},
		{86400, true, ""},
		{59, false, "TTL"},
		{-1, false, "TTL"},
		{86401, false, "TTL"},
	}
	for _, c := range cases {
		s := newToolsTestServer(t, nil)
		rec := postConfig(t, s, map[string]any{
			"adguard_url": "http://192.168.1.2:3000",
			"domains":     []string{"cf.example.com"},
			"ddns_ttl":    c.ttl,
		})
		if c.wantOK && rec.Code != 200 {
			t.Errorf("ttl=%d 应保存成功，实际 %d: %s", c.ttl, rec.Code, rec.Body.String())
		}
		if !c.wantOK {
			if rec.Code != 400 {
				t.Errorf("ttl=%d 应被拒绝（400），实际 %d", c.ttl, rec.Code)
			}
			if !strings.Contains(rec.Body.String(), c.mustSay) {
				t.Errorf("ttl=%d 的报错里应提到 %q，实际 %s", c.ttl, c.mustSay, rec.Body.String())
			}
		}
	}
}

// TestSaveConfigStoresTTLAndProxied 存下去之后要能读回来——
// 读不回来界面每次刷新都会显示 0，用户会以为没存上。
func TestSaveConfigStoresTTLAndProxied(t *testing.T) {
	s := newToolsTestServer(t, nil)
	rec := postConfig(t, s, map[string]any{
		"adguard_url":   "http://192.168.1.2:3000",
		"domains":       []string{"cf.example.com"},
		"ddns_enabled":  true,
		"ddns_provider": "cloudflare",
		"ddns_domain":   "cf.example.com",
		"ddns_ttl":      3600,
		"ddns_proxied":  true,
	})
	if rec.Code != 200 {
		t.Fatalf("保存失败: %d %s", rec.Code, rec.Body.String())
	}

	get := call(s, http.MethodGet, "/api/config")
	if get.Code != 200 {
		t.Fatalf("读取配置失败: %d", get.Code)
	}
	var got struct {
		TTL     int  `json:"ddns_ttl"`
		Proxied bool `json:"ddns_proxied"`
	}
	if err := json.Unmarshal(get.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.TTL != 3600 {
		t.Errorf("ddns_ttl 应为 3600，实际 %d", got.TTL)
	}
	if !got.Proxied {
		t.Error("ddns_proxied 应为 true")
	}
}

// TestSaveConfigProxiedLogsWarning 开了云朵要留一行日志。
// 以后用户发现「域名解析的 IP 不是我选的那个」时，日志里这行就是答案。
func TestSaveConfigProxiedLogsWarning(t *testing.T) {
	s := newToolsTestServer(t, nil)
	postConfig(t, s, map[string]any{
		"adguard_url":   "http://192.168.1.2:3000",
		"domains":       []string{"cf.example.com"},
		"ddns_enabled":  true,
		"ddns_provider": "cloudflare",
		"ddns_domain":   "cf.example.com",
		"ddns_proxied":  true,
	})
	logs := strings.Join(s.logs, "\n")
	if !strings.Contains(logs, "云朵") {
		t.Errorf("开启云朵后日志里应有提示，实际日志：\n%s", logs)
	}
}

// TestSaveConfigNoCloudFlareWarningForOthers 换到别家就别提云朵了，
// 否则阿里云用户会看到一句与自己无关的话。
func TestSaveConfigNoCloudFlareWarningForOthers(t *testing.T) {
	s := newToolsTestServer(t, nil)
	postConfig(t, s, map[string]any{
		"adguard_url":   "http://192.168.1.2:3000",
		"domains":       []string{"cf.example.com"},
		"ddns_enabled":  true,
		"ddns_provider": "aliyun",
		"ddns_domain":   "cf.example.com",
		"ddns_proxied":  true,
	})
	if strings.Contains(strings.Join(s.logs, "\n"), "云朵") {
		t.Error("非 Cloudflare 服务商不该出现云朵提示")
	}
}
