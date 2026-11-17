package web

import (
	"io"
	"net"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/303528084/cf-ddns-sidecar/config"
)

// TestParseExtraSources 逐行解析「优选 IP 段」的三类写法。
//
// 这里最要紧的不是「能认出正确的」，而是「认不出的时候会不会出声」。用户填了
// 一段看似合法其实是 104.16.0.0/33 的东西，如果静默忽略，他保存后会看到后台
// 里那段还在、测速却毫无变化，然后判定「这个功能是假的」。
func TestParseExtraSources(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		cidrs []string
		ips   []string
		urls  []string
	}{
		{
			name:  "三种写法混在一起",
			lines: []string{"104.16.0.0/13", "1.2.3.4", "https://example.com/all.txt"},
			cidrs: []string{"104.16.0.0/13"},
			ips:   []string{"1.2.3.4"},
			urls:  []string{"https://example.com/all.txt"},
		},
		{
			name:  "空行与注释跳过",
			lines: []string{"", "   ", "# 这是注释", "104.16.0.0/13", "  # 也跳过  "},
			cidrs: []string{"104.16.0.0/13"},
		},
		{
			name:  "/32 归到单 IP：位宽为 0 的段采样时会被当成空段跳掉",
			lines: []string{"1.2.3.4/32"},
			ips:   []string{"1.2.3.4"},
		},
		{
			name:  "同一行重复只留一次",
			lines: []string{"1.2.3.4", "1.2.3.4", "104.16.0.0/13", "104.16.0.0/13"},
			cidrs: []string{"104.16.0.0/13"},
			ips:   []string{"1.2.3.4"},
		},
		{
			name:  "/32 与裸 IP 是同一个东西，不该出现两条",
			lines: []string{"1.2.3.4/32", "1.2.3.4"},
			ips:   []string{"1.2.3.4"},
		},
		{
			name:  "链接大小写不敏感，重复也只留一次",
			lines: []string{"HTTPS://Example.com/a.txt", "https://example.com/a.txt"},
			urls:  []string{"HTTPS://Example.com/a.txt"},
		},
		{
			name:  "行首行尾的空白要吃掉",
			lines: []string{"  104.16.0.0/13  ", "\t1.2.3.4\t"},
			cidrs: []string{"104.16.0.0/13"},
			ips:   []string{"1.2.3.4"},
		},
		{
			name:  "什么也没填就是空",
			lines: nil,
		},
	}

	for _, c := range cases {
		got, err := parseExtraSources(c.lines)
		if err != nil {
			t.Errorf("%s：不该报错，实际 %v", c.name, err)
			continue
		}
		if !eqStrings(got.cidrs, c.cidrs) {
			t.Errorf("%s：IP 段应为 %v，实际 %v", c.name, c.cidrs, got.cidrs)
		}
		if !eqStrings(got.ips, c.ips) {
			t.Errorf("%s：单 IP 应为 %v，实际 %v", c.name, c.ips, got.ips)
		}
		if !eqStrings(got.urls, c.urls) {
			t.Errorf("%s：链接应为 %v，实际 %v", c.name, c.urls, got.urls)
		}
	}
}

// TestParseExtraSourcesRejects 写错的行必须点名第几行。
//
// 只说「格式错误」是不够的：用户往往填了十几行，得知道去哪一行改。
func TestParseExtraSourcesRejects(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		want  string
	}{
		{
			name:  "掩码超出 32",
			lines: []string{"104.16.0.0/13", "104.16.0.0/33"},
			want:  "第 2 行",
		},
		{
			name:  "根本不是 IP",
			lines: []string{"hello", "1.2.3.4"},
			want:  "第 1 行",
		},
		{
			name:  "IPv6 不支持",
			lines: []string{"2001:db8::1"},
			want:  "第 1 行",
		},
		{
			name:  "段里混了域名",
			lines: []string{"1.2.3.4", "cf.example.com/24"},
			want:  "第 2 行",
		},
		{
			name:  "缺掩码的段",
			lines: []string{"1.2.3.0/"},
			want:  "第 1 行",
		},
	}

	for _, c := range cases {
		_, err := parseExtraSources(c.lines)
		if err == nil {
			t.Errorf("%s：应当报错却通过了", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s：错误信息应含 %q，实际 %q", c.name, c.want, err.Error())
		}
		if !strings.Contains(err.Error(), "「") {
			t.Errorf("%s：错误信息应把原文引出来方便定位，实际 %q", c.name, err.Error())
		}
	}
}

// TestCandidateList 三种情形的语义必须分得清，尤其第三种。
func TestCandidateList(t *testing.T) {
	t.Run("没设置过就用内置官方段", func(t *testing.T) {
		cfg := config.Default()
		out := candidateList(cfg, 100)
		assertAllInCIDRs(t, out, cloudflareIPv4)
	})
	t.Run("nil 配置也不该崩", func(t *testing.T) {
		out := candidateList(nil, 50)
		assertAllInCIDRs(t, out, cloudflareIPv4)
	})
	t.Run("填了段就只用这些段", func(t *testing.T) {
		cfg := config.Default()
		cfg.Speed.ExtraSources = []string{"104.16.0.0/13"}
		out := candidateList(cfg, 100)
		assertAllInCIDRs(t, out, []string{"104.16.0.0/13"})
	})
	t.Run("填了段就不该出现官方段里的其他网段", func(t *testing.T) {
		cfg := config.Default()
		cfg.Speed.ExtraSources = []string{"1.0.0.0/16"}
		out := candidateList(cfg, 100)
		assertAllInCIDRs(t, out, []string{"1.0.0.0/16"})
	})
	t.Run("只填了单 IP 就只测这一个", func(t *testing.T) {
		cfg := config.Default()
		cfg.Speed.ExtraSources = []string{"1.2.3.4"}
		if got := candidateList(cfg, 100); got != "1.2.3.4:443#US\n" {
			t.Errorf("只填一个 IP 时应当只有它，实际 %q", got)
		}
	})
	t.Run("只填了链接就一个本地候选都不出", func(t *testing.T) {
		// 这一条是整个功能的命门：若这里偷偷回落到官方段，用户填了链接却
		// 看到结果还是原来那些段，而程序看起来一切正常，根本无从排查。
		cfg := config.Default()
		cfg.Speed.ExtraSources = []string{"https://example.com/all.txt"}
		if got := candidateList(cfg, 100); got != "" {
			t.Errorf("只填链接时应交给引擎去拉、本地不出候选，实际 %q", got)
		}
	})
	t.Run("配置被手工改坏时退回内置段而不是返回空", func(t *testing.T) {
		cfg := config.Default()
		cfg.Speed.ExtraSources = []string{"这不是一个 IP 段"}
		out := candidateList(cfg, 50)
		assertAllInCIDRs(t, out, cloudflareIPv4)
	})
}

// TestSampleFromSourcesSingleIPKept 单 IP 是用户点名的，抽样就等于随机丢掉它。
func TestSampleFromSourcesSingleIPKept(t *testing.T) {
	src := extraSources{
		ips:   []string{"1.2.3.4", "5.6.7.8"},
		cidrs: []string{"104.16.0.0/13"},
	}
	out := sampleFromSources(src, 200)
	if len(out) < 2 {
		t.Fatalf("候选太少：%v", out)
	}
	for _, want := range []string{"1.2.3.4:443#US", "5.6.7.8:443#US"} {
		found := false
		for _, v := range out {
			if v == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("点名的单 IP 被抽掉了：%s 不在结果里", want)
		}
	}
	// 名额被单 IP 占掉两个，剩下的都该来自那段 /13
	if len(out) > 200 {
		t.Errorf("超出要的数量：%d", len(out))
	}
	for _, v := range out {
		ip, _, _ := strings.Cut(v, ":")
		if strings.HasPrefix(ip, "1.2.3.4") || strings.HasPrefix(ip, "5.6.7.8") {
			continue
		}
		if !inCIDR(ip, "104.16.0.0/13") {
			t.Errorf("冒出了用户没填的地址：%s", v)
		}
	}
}

// TestSampleFromSourcesNoDuplicate 同一个 IP 出现两次只会白测一次。
func TestSampleFromSourcesNoDuplicate(t *testing.T) {
	src := extraSources{cidrs: []string{"192.168.0.0/24", "10.0.0.0/24"}}
	seen := map[string]bool{}
	for _, v := range sampleFromSources(src, 300) {
		ip, _, _ := strings.Cut(v, ":")
		if seen[ip] {
			t.Fatalf("重复候选：%s", ip)
		}
		seen[ip] = true
	}
}

// TestSaveConfigExtraSources 三件事：不带字段＝保持原值、空数组＝清空、写错行＝400 且点名行号。
//
// 「不带字段」和「传了空数组」在 JSON 里都能解成空切片，所以后端必须用指针
// 把两者分开。用普通切片的话，用户永远清不空自己填的段——点了保存、界面清空、
// 下次测速还是老样子，这是最难查的一类 bug。
func TestSaveConfigExtraSources(t *testing.T) {
	newSrv := func(t *testing.T, sources []string) *Server {
		t.Helper()
		cfg := config.Default()
		cfg.Speed.ExtraSources = sources
		return New(cfg, filepath.Join(t.TempDir(), "config.json"), "", t.TempDir(), Auth{}, "", nil)
	}
	post := func(t *testing.T, s *Server, body string) (int, string) {
		t.Helper()
		r := mkReq("POST", "/api/config", "127.0.0.1:5000", nil)
		r.Body = io.NopCloser(strings.NewReader(body))
		w := httptest.NewRecorder()
		s.saveConfig(w, r)
		return w.Code, w.Body.String()
	}

	t.Run("请求里没带这个字段就保持原值", func(t *testing.T) {
		s := newSrv(t, []string{"104.16.0.0/13"})
		code, resp := post(t, s, `{"domains":["a.com"],"interval_minutes":60}`)
		if code != 200 {
			t.Fatalf("应当成功，实际 %d %s", code, resp)
		}
		if !eqStrings(s.cfg.Speed.ExtraSources, []string{"104.16.0.0/13"}) {
			t.Errorf("老客户端没带字段，不该顺手清空用户的段，实际 %v", s.cfg.Speed.ExtraSources)
		}
	})
	t.Run("传空数组就是主动清空", func(t *testing.T) {
		s := newSrv(t, []string{"104.16.0.0/13"})
		code, resp := post(t, s, `{"domains":["a.com"],"extra_sources":[]}`)
		if code != 200 {
			t.Fatalf("应当成功，实际 %d %s", code, resp)
		}
		if len(s.cfg.Speed.ExtraSources) != 0 {
			t.Errorf("用户清空后应当为空，实际 %v", s.cfg.Speed.ExtraSources)
		}
	})
	t.Run("全是空白等于清空", func(t *testing.T) {
		s := newSrv(t, []string{"104.16.0.0/13"})
		code, resp := post(t, s, `{"extra_sources":["","   "]}`)
		if code != 200 {
			t.Fatalf("应当成功，实际 %d %s", code, resp)
		}
		if len(s.cfg.Speed.ExtraSources) != 0 {
			t.Errorf("全是空白应当等于清空，实际 %v", s.cfg.Speed.ExtraSources)
		}
	})
	t.Run("写错一行整单退回并点名行号", func(t *testing.T) {
		s := newSrv(t, nil)
		code, resp := post(t, s, `{"extra_sources":["104.16.0.0/13","1.2.3.4","坏的一行"]}`)
		if code != 400 {
			t.Fatalf("应当 400，实际 %d %s", code, resp)
		}
		if !strings.Contains(resp, "第 3 行") {
			t.Errorf("错误信息应点名第 3 行，实际 %s", resp)
		}
		if len(s.cfg.Speed.ExtraSources) != 0 {
			t.Errorf("校验失败时不该改动已有配置，实际 %v", s.cfg.Speed.ExtraSources)
		}
	})
	t.Run("正确的段会存下来并去掉空行", func(t *testing.T) {
		s := newSrv(t, nil)
		code, resp := post(t, s,
			`{"extra_sources":["104.16.0.0/13","  1.2.3.4  ","","# 注释"]}`)
		if code != 200 {
			t.Fatalf("应当成功，实际 %d %s", code, resp)
		}
		want := []string{"104.16.0.0/13", "1.2.3.4", "# 注释"}
		if !eqStrings(s.cfg.Speed.ExtraSources, want) {
			t.Errorf("应当存 %v，实际 %v", want, s.cfg.Speed.ExtraSources)
		}
	})
}

// ---------- 小工具 ----------

func eqStrings(a, b []string) bool {
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

func inCIDR(ip, cidr string) bool {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	p := net.ParseIP(ip)
	return p != nil && n.Contains(p)
}

// assertAllInCIDRs 断言候选列表非空、条数对得上、且每条都落在给定网段里。
func assertAllInCIDRs(t *testing.T, out string, cidrs []string) {
	t.Helper()
	out = strings.TrimSpace(out)
	if out == "" {
		t.Fatal("候选列表是空的")
	}
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		ip, rest, ok := strings.Cut(line, ":")
		if !ok || !strings.Contains(rest, "#") {
			t.Fatalf("行格式不是 ip:port#国家：%q", line)
		}
		hit := false
		for _, c := range cidrs {
			if inCIDR(ip, c) {
				hit = true
				break
			}
		}
		if !hit {
			t.Fatalf("候选 %s 不在允许的网段里", ip)
		}
	}
	if len(lines) < 10 {
		t.Errorf("候选太少（%d 条），测速会没什么可挑的", len(lines))
	}
}

// TestSourcePlanText 校验「这一轮用了哪些来源」那句话。
//
// 这句话是 2026-11-17 22:14 那次反馈的直接产物：日志里只有引擎自己的行，
// 用户看不出程序到底用了他填的链接还是官方那 15 段。所以它必须只说真正
// 存在的来源，不能把「0 个」也念出来吓人。
func TestSourcePlanText(t *testing.T) {
	cases := []struct {
		name string
		src  extraSources
		want string
	}{
		{"只有段", extraSources{cidrs: []string{"104.16.0.0/13", "1.1.1.0/24"}}, "IP 段 2 个"},
		{"只有单 IP", extraSources{ips: []string{"1.2.3.4"}}, "单个 IP 1 个"},
		{"只有带端口节点", extraSources{nodes: []string{"1.2.3.4:8443#JP"}}, "带端口节点 1 个"},
		{"三者都有", extraSources{
			cidrs: []string{"104.16.0.0/13"},
			ips:   []string{"1.2.3.4"},
			nodes: []string{"5.6.7.8:2053#SG"},
		}, "IP 段 1 个、单个 IP 1 个、带端口节点 1 个"},
		{"一个都没有", extraSources{}, "本地没认出任何 IP"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sourcePlanText(c.src); got != c.want {
				t.Fatalf("得到 %q，期望 %q", got, c.want)
			}
		})
	}
}
