package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/303528084/cf-ddns-sidecar/config"
	"github.com/303528084/cf-ddns-sidecar/engine"
)

// newSwitchTestServer 造一个带临时数据目录、cfg 已装的 Server。
// handleSwitch 会 cfg.Save()，必须有真实可写的路径。
func newSwitchTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	return New(config.Default(), filepath.Join(dir, "config.json"), "", dir, Auth{}, "", nil)
}

// postSwitch 发一个开关请求，返回状态码和响应体。
func postSwitch(t *testing.T, s *Server, key string, value bool) (int, []byte) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"key": key, "value": value})
	req := httptest.NewRequest(http.MethodPost, "/api/switch", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleSwitch(rec, req)
	return rec.Code, rec.Body.Bytes()
}

// TestSwitchEngineBool 高级设置开关单项保存：只改点名那个键，别的覆盖值原样留着。
func TestSwitchEngineBool(t *testing.T) {
	s := newSwitchTestServer(t)
	// 预置一个别的覆盖值，确认不会被冲掉
	s.cfg.Speed.EngineOverrides = map[string]any{"TCP_PROBES": 2}

	code, _ := postSwitch(t, s, "TEST_AVAILABILITY", false)
	if code != http.StatusOK {
		t.Fatalf("保存反代验证开关失败: HTTP %d", code)
	}
	if got, ok := s.cfg.Speed.EngineOverrides["TEST_AVAILABILITY"]; !ok || got != false {
		t.Fatalf("TEST_AVAILABILITY 应为 false，实际 %v（存在=%v）", got, ok)
	}
	if got := s.cfg.Speed.EngineOverrides["TCP_PROBES"]; got != 2 {
		t.Fatalf("别的覆盖值 TCP_PROBES 被冲掉了，实际 %v", got)
	}

	// 点回默认值（TEST_AVAILABILITY 默认 true），这个键应被去掉
	code, _ = postSwitch(t, s, "TEST_AVAILABILITY", true)
	if code != http.StatusOK {
		t.Fatalf("点回默认失败: HTTP %d", code)
	}
	if _, ok := s.cfg.Speed.EngineOverrides["TEST_AVAILABILITY"]; ok {
		t.Fatalf("已是默认值却还留在覆盖表里: %v", s.cfg.Speed.EngineOverrides)
	}
}

// TestSwitchDDNS DDNS 两个开关单项保存。
func TestSwitchDDNS(t *testing.T) {
	s := newSwitchTestServer(t)
	// 预置别的 DDNS 字段，确认单项保存不动它们
	s.cfg.DDNS.Domain = "keep.example.com"
	s.cfg.DDNS.IPCount = 3

	if code, _ := postSwitch(t, s, "ddns_enabled", true); code != http.StatusOK {
		t.Fatalf("启用 DDNS 失败: HTTP %d", code)
	}
	if !s.cfg.DDNS.Enabled {
		t.Fatal("ddns_enabled 没生效")
	}
	if code, _ := postSwitch(t, s, "ddns_proxied", true); code != http.StatusOK {
		t.Fatalf("开代理失败: HTTP %d", code)
	}
	if !s.cfg.DDNS.Proxied {
		t.Fatal("ddns_proxied 没生效")
	}
	if s.cfg.DDNS.Domain != "keep.example.com" || s.cfg.DDNS.IPCount != 3 {
		t.Fatalf("单项保存冲掉了别的 DDNS 字段: %+v", s.cfg.DDNS)
	}
}

// TestSwitchRejectsBadKey 非布尔参数、未知名字都要挡掉，不能静默写进去。
func TestSwitchRejectsBadKey(t *testing.T) {
	s := newSwitchTestServer(t)
	for _, key := range []string{"", "NOT_A_REAL_KEY", "TCP_PROBES", "ddns_domain"} {
		code, _ := postSwitch(t, s, key, true)
		if code != http.StatusBadRequest {
			t.Errorf("key=%q 应返回 400，实际 %d", key, code)
		}
	}
}

// TestSwitchOnlyPost GET 不该能改设置。
func TestSwitchOnlyPost(t *testing.T) {
	s := newSwitchTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/switch", nil)
	rec := httptest.NewRecorder()
	s.handleSwitch(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET 应返回 405，实际 %d", rec.Code)
	}
}

// TestSwitchBoolKeysAllAccepted 参数表里所有 bool 开关都得接受，
// 免得界面上显示了一个开关、后端却判成非法。
func TestSwitchBoolKeysAllAccepted(t *testing.T) {
	s := newSwitchTestServer(t)
	n := 0
	for _, spec := range engine.Schema {
		if spec.Kind != engine.KindBool {
			continue
		}
		n++
		if code, body := postSwitch(t, s, spec.Key, !spec.Def.(bool)); code != http.StatusOK {
			t.Errorf("开关 %s 被拒绝: HTTP %d %s", spec.Key, code, body)
		}
	}
	if n < 10 {
		t.Fatalf("只测到 %d 个 bool 开关，疑似参数表读取有问题", n)
	}
}
