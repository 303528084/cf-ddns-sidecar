package web

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/303528084/cf-ddns-sidecar/config"
)

// TestParseSourceTextCidrList 就是用户 2026-11-17 22:01 遇到的那个文件：
// 「高爆IP段.txt」里全是 104.16.0.0/13 这种**段**。
//
// cfnb 自带的解析器只认单个 IP，遇到段整条丢掉，于是拉到内容却解析出 0 节点，
// 日志只说「数据源解析完成（0 节点）」，看起来像地址失效。这里必须先能把段认下来。
func TestParseSourceTextCidrList(t *testing.T) {
	text := `# 高爆IP段
104.16.0.0/13
172.64.0.0/13
131.0.72.0/22
`
	got, st := parseSourceText(text)
	if len(got.cidrs) != 3 {
		t.Fatalf("应当认出 3 个段，实际 %v（认不出 %d 条：%v）", got.cidrs, st.skippedTotal, st.skipped)
	}
	if !got.isEmpty() == false {
		t.Error("有段时不该判成空")
	}
	// 段要能被采样出来，否则等于没认出来
	if out := candidatesText(got, 50); strings.TrimSpace(out) == "" {
		t.Error("从段里采不出候选")
	}
}

// TestParseSourceTextFormats 各种真实会遇到的写法。
func TestParseSourceTextFormats(t *testing.T) {
	cases := []struct {
		name  string
		text  string
		ips   int
		nodes int
		cidrs int
		want  []string // 必须出现在结果里的节点
	}{
		{
			name: "纯单 IP 列表",
			text: "104.20.60.55\n172.67.158.249",
			ips:  2,
		},
		{
			name:  "IP:端口#国家 保留原端口",
			text:  "101.108.49.121:443#TH\n101.99.75.101:8443#NL",
			nodes: 2,
			want:  []string{"101.99.75.101:8443#NL"},
		},
		{
			name: "逗号分隔",
			text: "104.16.1.1,104.16.1.2，104.16.1.3",
			ips:  3,
		},
		{
			name: "每行带中文说明",
			text: "104.16.1.1 美国 高速\n104.16.1.2 日本 低延迟",
			ips:  2,
		},
		{
			name: "/32 当单 IP",
			text: "104.16.1.1/32",
			ips:  1,
		},
		{
			name: "连字符区间",
			text: "104.16.1.1-104.16.1.4",
			ips:  4,
		},
		{
			name:  "混合",
			text:  "104.16.0.0/13\n1.2.3.4\n1.2.3.5:8443#JP",
			ips:   1,
			nodes: 1,
			cidrs: 1,
		},
		{
			name: "空内容",
			text: "   \n\n",
		},
	}

	for _, c := range cases {
		got, st := parseSourceText(c.text)
		if len(got.ips) != c.ips || len(got.nodes) != c.nodes || len(got.cidrs) != c.cidrs {
			t.Errorf("%s：期望 ips=%d nodes=%d cidrs=%d，实际 ips=%d nodes=%d cidrs=%d（认不出 %v）",
				c.name, c.ips, c.nodes, c.cidrs,
				len(got.ips), len(got.nodes), len(got.cidrs), st.skipped)
		}
		for _, want := range c.want {
			found := false
			for _, n := range got.nodes {
				if n == want {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s：结果里应当有 %s，实际 %v", c.name, want, got.nodes)
			}
		}
	}
}

// TestParseSourceTextSkipsGarbage 外行文本要宽容跳过、并把样例留下来。
//
// 宽容是必须的：外面多一行「以下为电信节点」不该让整批来源作废。但样例必须留，
// 否则用户看到「0 节点」时完全不知道对方给的是什么。
func TestParseSourceTextSkipsGarbage(t *testing.T) {
	text := `以下为电信节点
<h1>404 Not Found</h1>
104.16.1.1
请用迅雷下载`
	got, st := parseSourceText(text)
	if len(got.ips) != 1 {
		t.Fatalf("应当只认出 1 个 IP，实际 %v", got.ips)
	}
	if st.skippedTotal == 0 || len(st.skipped) == 0 {
		t.Fatal("认不出的内容必须留样例")
	}
	if !strings.Contains(sampleHint(st.skipped), "「") {
		t.Errorf("样例应当被引号括起来打印，实际 %q", sampleHint(st.skipped))
	}
}

// TestParseSourceTextBase64 订阅类链接常常把整份列表 base64 之后再吐出来。
func TestParseSourceTextBase64(t *testing.T) {
	raw := "104.16.0.0/13\n1.2.3.4\n1.2.3.5:8443#JP\n"
	enc := base64.StdEncoding.EncodeToString([]byte(raw))
	got, _ := parseSourceText(enc)
	if len(got.cidrs) != 1 || len(got.ips) != 1 || len(got.nodes) != 1 {
		t.Fatalf("base64 内容应当能解开再解析，实际 ips=%v nodes=%v cidrs=%v",
			got.ips, got.nodes, got.cidrs)
	}
}

// TestResolveLinkSources 走完整链路：真的 HTTP 抓取 → 解析 → 采样输出。
func TestResolveLinkSources(t *testing.T) {
	body := "# 高爆IP段\n104.16.0.0/13\n104.24.0.0/14\n1.2.3.4\n1.2.3.5:8443#JP\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	cfg := config.Default()
	s := New(cfg, "", "", t.TempDir(), Auth{}, "", nil)

	src := extraSources{urls: []string{srv.URL + "/all.txt"}}
	merged, unparsed := s.resolveLinkSources(context.Background(), src, config.SourceCustom)
	if len(unparsed) != 0 {
		t.Fatalf("正常链接不该落到兜底，实际 %v", unparsed)
	}
	if len(merged.cidrs) != 2 || len(merged.ips) != 1 || len(merged.nodes) != 1 {
		t.Fatalf("合并结果不对：ips=%v nodes=%v cidrs=%v", merged.ips, merged.nodes, merged.cidrs)
	}

	text := candidatesText(merged, 100)
	if !strings.Contains(text, "1.2.3.4:443#US") {
		t.Errorf("点名的单 IP 应当出现在候选里，实际前几行：%s", head(text, 3))
	}
	if !strings.Contains(text, "1.2.3.5:8443#JP") {
		t.Errorf("带端口的节点必须保留原端口，实际前几行：%s", head(text, 3))
	}

	// 除两个点名节点之外，从段里采出来的都必须落在那两个段里。
	explicit := map[string]bool{"1.2.3.4": true, "1.2.3.5": true}
	sampled := 0
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		ip, _, _ := strings.Cut(line, ":")
		if explicit[ip] {
			continue
		}
		sampled++
		if !inCIDR(ip, "104.16.0.0/13") && !inCIDR(ip, "104.24.0.0/14") {
			t.Errorf("从段里采出的 %s 不在填的两个段里", ip)
		}
	}
	if sampled < 10 {
		t.Errorf("段里采出的候选太少：%d 条", sampled)
	}

	// 日志要说明认出了什么，否则用户无从判断链接到底有没有生效
	logs := strings.Join(s.logs, "\n")
	if !strings.Contains(logs, "来源链接解析完成") {
		t.Errorf("应当打一行解析结果，实际日志：%s", logs)
	}
}

// TestResolveLinkSourcesFailures 两种失败都要落到兜底、并且说清原因。
func TestResolveLinkSourcesFailures(t *testing.T) {
	t.Run("链接 404", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "not found", http.StatusNotFound)
		}))
		defer srv.Close()
		s := New(config.Default(), "", "", t.TempDir(), Auth{}, "", nil)
		merged, unparsed := s.resolveLinkSources(context.Background(),
			extraSources{urls: []string{srv.URL + "/x.txt"}}, config.SourceCustom)
		if len(unparsed) != 1 {
			t.Fatalf("404 应当落到兜底，实际 %v", unparsed)
		}
		if !merged.isEmpty() {
			t.Errorf("失败时不该凭空产生来源：%v", merged)
		}
		if !strings.Contains(strings.Join(s.logs, "\n"), "拉取失败") {
			t.Errorf("必须说明是拉取失败，实际日志：%v", s.logs)
		}
	})
	t.Run("内容是网页而不是 IP 列表", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("<html><body><h1>Hello</h1></body></html>"))
		}))
		defer srv.Close()
		s := New(config.Default(), "", "", t.TempDir(), Auth{}, "", nil)
		_, unparsed := s.resolveLinkSources(context.Background(),
			extraSources{urls: []string{srv.URL + "/x.txt"}}, config.SourceCustom)
		if len(unparsed) != 1 {
			t.Fatalf("认不出内容时应当落到兜底，实际 %v", unparsed)
		}
		if !strings.Contains(strings.Join(s.logs, "\n"), "没认出任何 IP") {
			t.Errorf("必须说明是内容没认出 IP，实际日志：%v", s.logs)
		}
	})
}

// TestMergedSourcesDedupe 同一个 IP 出现两次只留一条，端口不同也算同一个。
func TestMergedSourcesDedupe(t *testing.T) {
	dst := extraSources{ips: []string{"1.2.3.4"}}
	mergeSources(&dst, extraSources{
		ips:   []string{"1.2.3.4", "5.6.7.8"},
		nodes: []string{"1.2.3.4:8443#JP", "9.9.9.9:443#US"},
	})
	if len(dst.ips) != 2 {
		t.Errorf("单 IP 应当去重后为 2 个，实际 %v", dst.ips)
	}
	if len(dst.nodes) != 1 || dst.nodes[0] != "9.9.9.9:443#US" {
		t.Errorf("同一个 IP 换个端口也该算重复，实际 %v", dst.nodes)
	}
}

// head 取前 n 行，报错时打印用。
func head(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, " / ")
}
