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

// TestWriteCfnbConfigOutputsQuality 输出开关必须是打开的。
//
// 界面上的「速度 15.09 Mbps / 延迟 84.71 ms」全部来自 ip.txt 这两列。
// 一旦有人把开关改回 false，界面不会报错、也不会变空白——它会显示一排「—」，
// 看起来像「这次测速没量到」，实际上是我们自己把数据扔了。这种「静默降级」
// 只能靠测试挡住。
func TestWriteCfnbConfigOutputsQuality(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if err := writeCfnbConfig(p, Options{UseBuiltinSources: true}); err != nil {
		t.Fatalf("写配置失败: %v", err)
	}
	raw, _ := os.ReadFile(p)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("配置不是合法 JSON: %v", err)
	}
	for _, k := range []string{"IP_TXT_SHOW_BANDWIDTH", "IP_TXT_SHOW_LATENCY"} {
		if v, _ := m[k].(bool); !v {
			t.Errorf("%s 必须为 true，否则界面拿不到速度/延迟", k)
		}
	}
	// HTTP 延迟要额外开 HTTP_LATENCY_ENABLED（多一轮请求、还会改变排序），
	// 本产品不开，所以这两项必须保持 false——打开就是白让引擎多跑一遍。
	for _, k := range []string{"IP_TXT_SHOW_HTTP_LATENCY", "IP_TXT_SHOW_HTTP_JITTER"} {
		if v, _ := m[k].(bool); v {
			t.Errorf("%s 必须为 false", k)
		}
	}
}

// TestParseOutputQuality 解析 ip.txt 的各种行形。
//
// 行形由 cfnb 的 write_ip_txt 决定，随着「哪些开关打开」而变：
// 带宽测速整轮失败时它会降级成按 TCP 排序，那时行里只有延迟没有速度。
// 解析器必须容忍这几种，否则一次降级就会让整批 IP 都读不出来。
func TestParseOutputQuality(t *testing.T) {
	const content = `
# 这是注释，要跳过
172.64.229.246:443#US 15.09 Mbps 45.23 ms
104.16.0.87:443#US 45.23 ms
162.159.5.114:443#US
172.64.229.246:443#US 9.99 Mbps 1.11 ms
不是IP的一行 12.5 Mbps
`
	p := filepath.Join(t.TempDir(), "ip.txt")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("写文件失败: %v", err)
	}

	ips, nodes, err := parseOutput(p)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	wantIPs := []string{"172.64.229.246", "104.16.0.87", "162.159.5.114"}
	if !eq(ips, wantIPs) {
		t.Fatalf("IP 列表应为 %v，实际 %v", wantIPs, ips)
	}
	if len(nodes) != len(ips) {
		t.Fatalf("节点数应与 IP 数一致：%d vs %d", len(nodes), len(ips))
	}

	if nodes[0].Speed != 15.09 || nodes[0].Delay != 45.23 {
		t.Errorf("第 1 条应为 15.09Mbps/45.23ms，实际 %+v", nodes[0])
	}
	if nodes[1].Speed != 0 || nodes[1].Delay != 45.23 {
		t.Errorf("第 2 条只该有延迟 45.23，实际 %+v", nodes[1])
	}
	if nodes[2].Speed != 0 || nodes[2].Delay != 0 {
		t.Errorf("第 3 条什么都没有，不该凭空补数，实际 %+v", nodes[2])
	}
	// 重复的 IP 只保留第一次出现的那条（速度 15.09，不是后面那行 9.99）。
	if nodes[0].IP != "172.64.229.246" {
		t.Errorf("重复 IP 应保留第一条，实际 %+v", nodes[0])
	}
}

// TestParseOutputIPv6 验证 v6 节点的解析：
// 带方括号的 [v6]:port 应正确拆出裸 v6 地址；裸 v6 串（端口并进地址）应被拒绝，
// 绝不静默当成 IP 收下。
func TestParseOutputIPv6(t *testing.T) {
	const content = `
[2606:4700::1]:443#US 12.34 Mbps 56.78 ms
2606:4700::2:443#US 99.00 Mbps 1.00 ms
1.2.3.4:443#US 5.00 Mbps 10.00 ms
`
	p := filepath.Join(t.TempDir(), "ip.txt")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("写文件失败: %v", err)
	}
	ips, nodes, err := parseOutput(p)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	want := []string{"2606:4700::1", "1.2.3.4"}
	if !eq(ips, want) {
		t.Fatalf("应只收下带方括号的 v6 和正常 v4，裸 v6 串要丢掉；实际 %v", ips)
	}
	if len(nodes) != len(ips) {
		t.Fatalf("节点数应与 IP 数一致：%d vs %d", len(nodes), len(ips))
	}
	if nodes[0].Speed != 12.34 || nodes[0].Delay != 56.78 {
		t.Errorf("v6 节点质量读错: %+v", nodes[0])
	}
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
