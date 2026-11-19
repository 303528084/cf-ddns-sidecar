package web

// 来源模式（内置 / 自定义 / 关闭）在接口和运行时的表现。

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/303528084/cf-ddns-sidecar/config"
)

// 老配置里没有这个字段，界面靠 GET 拿到的是「实际生效」的模式，不是空串。
// 这里给错，下拉会画成空白，用户第一眼就知道不对劲，但不知道该怎么选回来。
func TestConfigExposesEffectiveSourceModes(t *testing.T) {
	s := newToolsTestServer(t, nil)

	rec := call(s, http.MethodGet, "/api/config")
	if rec.Code != http.StatusOK {
		t.Fatalf("读取配置失败: %d", rec.Code)
	}
	var got struct {
		SourceMode     string `json:"source_mode"`
		IPv6SourceMode string `json:"ipv6_source_mode"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("响应解析失败: %s", rec.Body.String())
	}
	if got.SourceMode != config.SourceBuiltin {
		t.Errorf("v4 默认应为 builtin，实际 %q", got.SourceMode)
	}
	if got.IPv6SourceMode != config.SourceOff {
		t.Errorf("v6 默认应为 off，实际 %q", got.IPv6SourceMode)
	}
}

// 三个值都存得住、读得回；写坏的值当场退回，不静默改成默认。
func TestSaveSourceModes(t *testing.T) {
	s := newToolsTestServer(t, nil)

	rec := postConfig(t, s, map[string]any{
		"source_mode":          "off",
		"ipv6_source_mode":     "builtin",
		"ipv6_probe_url":       "",
		"adguard_url":          "",
		"adguard_user":         "",
		"adguard_password":     "",
		"top_n":                5,
		"bandwidth_candidates": 100,
		"interval_minutes":     0,
		"extra_sources":        []string{"104.16.0.0/13"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("保存失败: %d %s", rec.Code, rec.Body.String())
	}

	s.mu.Lock()
	got := *s.cfg
	s.mu.Unlock()
	if got.EffectiveSourceMode() != config.SourceOff {
		t.Errorf("v4 应存成 off，实际 %q", got.Speed.SourceMode)
	}
	if got.EffectiveIPv6SourceMode() != config.SourceBuiltin {
		t.Errorf("v6 应存成 builtin，实际 %q", got.IPv6SourceMode)
	}
	// 切到关闭/内置也不能把用户框里的内容清掉：切回自定义时还要能看见。
	if len(got.Speed.ExtraSources) != 1 {
		t.Errorf("自定义内容被顺手清掉了: %v", got.Speed.ExtraSources)
	}

	bad := postConfig(t, s, map[string]any{
		"source_mode": "自动",
	})
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("写坏的模式应退回 400，实际 %d", bad.Code)
	}
	if !strings.Contains(bad.Body.String(), "来源模式") {
		t.Errorf("报错要说清是哪一项：%s", bad.Body.String())
	}
}

// 选了「自定义」却一条都没填，等于这一族没来源：保存时就该退回，
// 而不是等下一轮测速报一句「没解析出任何可用 IP」——那时用户已经忘了改过什么。
func TestSaveCustomWithoutSourcesRejected(t *testing.T) {
	s := newToolsTestServer(t, nil)

	rec := postConfig(t, s, map[string]any{
		"source_mode":   "custom",
		"extra_sources": []string{},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("应退回 400，实际 %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "一条来源都没填") {
		t.Errorf("报错要指出该填还是该换模式：%s", rec.Body.String())
	}

	v6 := postConfig(t, s, map[string]any{
		"ipv6_source_mode": "custom",
		"ipv6_probe_url":   "",
	})
	if v6.Code != http.StatusBadRequest {
		t.Fatalf("v6 选自定义但没填链接也应退回 400，实际 %d", v6.Code)
	}
}

// 两族都关闭时这一轮什么都不做：不跑引擎（引擎路径是坏的也不报错）、不刷失败次数、
// 也不把 last_ok 记成成功——界面上的「上次测速」要停在真跑过的那一次。
func TestRunOnceBothFamiliesOffDoesNothing(t *testing.T) {
	s := newToolsTestServer(t, func(c *config.Config) {
		c.Speed.SourceMode = config.SourceOff
		c.IPv6SourceMode = config.SourceOff
	})
	s.enginePath = filepath.Join(t.TempDir(), "no-such-main.py")

	if err := s.runOnce(s.cfg.Clone(), triggerTimer); err != nil {
		t.Fatalf("两族都关闭不算失败，实际返回 %v", err)
	}

	s.mu.Lock()
	logs := strings.Join(s.logs, "\n")
	failCount, lastOK := s.failCount, s.lastOK
	s.mu.Unlock()

	if !strings.Contains(logs, "这一轮不测速") {
		t.Errorf("日志里要说明为什么没动静：\n%s", logs)
	}
	if failCount != 0 {
		t.Errorf("主动关闭不是失败，不该累加失败次数，实际 %d", failCount)
	}
	if lastOK {
		t.Error("什么都没测却把 last_ok 记成 true，界面会显示「成功」")
	}
}

// 内置来源的地址只活在程序里：日志里写「内置来源」，自定义的照原样写出来
// （链接挂了要能看出是哪一条）。
func TestSourceLabelHidesBuiltin(t *testing.T) {
	if got := sourceLabel(config.SourceBuiltin, config.BuiltinV4Source); got != "内置来源" {
		t.Errorf("内置来源不该打出地址，实际 %q", got)
	}
	u := "https://example.com/ips.txt"
	if got := sourceLabel(config.SourceCustom, u); got != u {
		t.Errorf("自定义来源要原样显示，实际 %q", got)
	}
}
