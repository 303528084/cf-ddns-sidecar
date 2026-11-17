package web

// 「同步几个 IP」这一层：截取逻辑、配置校验、默认值兼容。
//
// 真正把多写出去的测试在 .scratch/e2e_multi（用假 Cloudflare 跑真程序），
// 这一层只保证「按排名截前 N」和「老配置行为不变」。

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/303528084/cf-ddns-sidecar/config"
)

func TestPickIPs(t *testing.T) {
	ranked := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"}
	cases := []struct {
		name string
		ips  []string
		n    int
		want []string
	}{
		{"取前 1 条", ranked, 1, ranked[:1]},
		{"取前 5 条", ranked, 5, ranked},
		{"要的比有的多", ranked, 9, ranked},
		{"零按 1 条算", ranked, 0, ranked[:1]},
		{"负数按 1 条算", ranked, -3, ranked[:1]},
		{"空列表", nil, 5, nil},
		{"跳过空项", []string{"1.1.1.1", "", "2.2.2.2"}, 3, []string{"1.1.1.1", "2.2.2.2"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := pickIPs(c.ips, c.n)
			if len(got) != len(c.want) {
				t.Fatalf("应为 %v，实际 %v", c.want, got)
			}
			for i := range c.want {
				if got[i] != c.want[i] {
					t.Fatalf("应为 %v，实际 %v", c.want, got)
				}
			}
		})
	}
}

// 条数越界要在保存这一步就挡住。
func TestSaveConfigIPCountRange(t *testing.T) {
	cases := []struct {
		count   int
		wantOK  bool
		mustSay string
	}{
		{1, true, ""},
		{5, true, ""},
		{20, true, ""},
		{0, true, ""}, // 没填 = 用默认（1 条），老界面就是这样
		{-1, false, "同步几条"},
		{21, false, "同步几条"},
	}
	for _, c := range cases {
		s := newToolsTestServer(t, nil)
		rec := postConfig(t, s, map[string]any{
			"adguard_url":   "http://192.168.1.2:3000",
			"domains":       []string{"cf.example.com"},
			"ddns_ip_count": c.count,
		})
		if c.wantOK && rec.Code != 200 {
			t.Errorf("count=%d 应保存成功，实际 %d: %s", c.count, rec.Code, rec.Body.String())
		}
		if !c.wantOK {
			if rec.Code != 400 {
				t.Errorf("count=%d 应被拒绝（400），实际 %d", c.count, rec.Code)
			}
			if !strings.Contains(rec.Body.String(), c.mustSay) {
				t.Errorf("count=%d 的报错里应提到 %q，实际 %s", c.count, c.mustSay, rec.Body.String())
			}
		}
	}
}

// 存下去要能读回来；而没存过的时候读回来必须是 1（不是 0）——
// 界面上显示 0 条会让人以为一条都不写。
func TestSaveConfigIPCountRoundTrip(t *testing.T) {
	s := newToolsTestServer(t, nil)

	// 先看默认：什么都没设时应该是 1
	get := call(s, http.MethodGet, "/api/config")
	var got struct {
		Count int `json:"ddns_ip_count"`
	}
	_ = json.Unmarshal(get.Body.Bytes(), &got)
	if got.Count != 1 {
		t.Errorf("默认应为 1 条，实际 %d", got.Count)
	}

	rec := postConfig(t, s, map[string]any{
		"adguard_url":   "http://192.168.1.2:3000",
		"domains":       []string{"cf.example.com"},
		"ddns_ip_count": 5,
	})
	if rec.Code != 200 {
		t.Fatalf("保存失败: %d %s", rec.Code, rec.Body.String())
	}
	get = call(s, http.MethodGet, "/api/config")
	_ = json.Unmarshal(get.Body.Bytes(), &got)
	if got.Count != 5 {
		t.Errorf("读回来应为 5，实际 %d", got.Count)
	}
}

// 老配置文件没有 ip_count 字段：读出来是 0，但有效值必须是 1，
// 否则升级后「一条都不写」，域名解析当场失效。
func TestIPCountZeroMeansOne(t *testing.T) {
	if n := (config.DDNSConfig{}).EffectiveIPCount(); n != 1 {
		t.Fatalf("零值应按 1 条处理，实际 %d", n)
	}
	if n := (config.DDNSConfig{IPCount: 4}).EffectiveIPCount(); n != 4 {
		t.Fatalf("填了 4 就该是 4，实际 %d", n)
	}
	if n := (config.DDNSConfig{IPCount: -1}).EffectiveIPCount(); n != 1 {
		t.Fatalf("负数应按 1 条处理，实际 %d", n)
	}
}
