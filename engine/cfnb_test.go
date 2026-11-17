package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// readSources 读出 cfnb 配置里实际会去拉的数据源地址。
func readSources(t *testing.T, opt Options) []string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := writeCfnbConfig(p, opt); err != nil {
		t.Fatalf("写配置失败: %v", err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("读配置失败: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("配置不是合法 JSON: %v", err)
	}
	list, _ := m["ADDITIONAL_SOURCES"].([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		if obj, ok := item.(map[string]any); ok {
			if u, ok := obj["url"].(string); ok {
				out = append(out, u)
			}
		}
	}
	return out
}

// TestWriteCfnbConfigBuiltinSources 内置聚合源的开关。
//
// 这是「只用我给的」能不能成立的关键一步：那两个源一个能吐 12757 个 IP，
// 只要它们还在列表里，用户划定的范围就会被淹没。表现出来是「我明明填了段，
// 优选出来还是原来那些」——程序一切正常，用户完全无从排查。
func TestWriteCfnbConfigBuiltinSources(t *testing.T) {
	const (
		ipdb = "https://ipdb.api.030101.xyz/?type=bestcf"
		zip  = "https://zip.cm.edu.kg/all.txt"
	)
	local := "http://127.0.0.1:8880/api/candidates"

	t.Run("没指定自定义来源时带上内置源", func(t *testing.T) {
		got := readSources(t, Options{CandidatesURL: local, UseBuiltinSources: true})
		want := []string{local, ipdb, zip}
		if !eq(got, want) {
			t.Errorf("应为 %v，实际 %v", want, got)
		}
	})
	t.Run("用了自定义段就不带内置源", func(t *testing.T) {
		got := readSources(t, Options{CandidatesURL: local, UseBuiltinSources: false})
		if !eq(got, []string{local}) {
			t.Errorf("应只有本地候选列表，实际 %v", got)
		}
	})
	t.Run("只填了链接时只有那个链接", func(t *testing.T) {
		// 此时 CandidatesURL 是空的（本地不出候选），也不能偷偷补内置源。
		got := readSources(t, Options{
			CandidatesURL:     "",
			ExtraURLs:         []string{"https://example.com/all.txt"},
			UseBuiltinSources: false,
		})
		if !eq(got, []string{"https://example.com/all.txt"}) {
			t.Errorf("应只有用户填的链接，实际 %v", got)
		}
	})
	t.Run("链接在前、内置源在后", func(t *testing.T) {
		got := readSources(t, Options{
			CandidatesURL:     local,
			ExtraURLs:         []string{"https://a.example/x.txt", "https://b.example/y.txt"},
			UseBuiltinSources: true,
		})
		want := []string{local, "https://a.example/x.txt", "https://b.example/y.txt", ipdb, zip}
		if !eq(got, want) {
			t.Errorf("应为 %v，实际 %v", want, got)
		}
	})
	t.Run("空链接与纯空白链接都跳过", func(t *testing.T) {
		got := readSources(t, Options{
			CandidatesURL:     local,
			ExtraURLs:         []string{"", "  ", "https://a.example/x.txt"},
			UseBuiltinSources: false,
		})
		if !eq(got, []string{local, "https://a.example/x.txt"}) {
			t.Errorf("空链接应被跳过，实际 %v", got)
		}
	})
	t.Run("强制直连必须开着", func(t *testing.T) {
		// 测速量的必须是「本机到 Cloudflare 边缘」，被代理污染后结果毫无意义。
		p := filepath.Join(t.TempDir(), "config.json")
		if err := writeCfnbConfig(p, Options{UseBuiltinSources: true}); err != nil {
			t.Fatalf("写配置失败: %v", err)
		}
		raw, _ := os.ReadFile(p)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		if v, _ := m["FORCE_DIRECT"].(bool); !v {
			t.Error("FORCE_DIRECT 必须为 true")
		}
	})
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
