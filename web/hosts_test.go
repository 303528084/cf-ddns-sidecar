package web

// hosts 源这一块的用例。
//
// 这一组里最值得看的是三类「静默失败」——它们都不会报错，只会让界面上写着
// 「已同步」而 AdGuard 里的东西跟用户的预期不一样：
//   - 拦截条目（0.0.0.0 / 127.0.0.1）被当成解析写进去，域名变成打不开；
//   - 拉到一个网页（用户填了站点的根路径）被当成「源里现在空」→ 全删；
//   - 和加速域名重名时两边都写，谁最后写谁赢，每轮 IP 都在变。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/303528084/cf-ddns-sidecar/config"
)

func TestParseHostsText(t *testing.T) {
	text := `
# GitHub520 Host Start
140.82.113.4 github.com
140.82.113.4 gist.github.com
# 一行多个域名
185.199.108.133 raw.githubusercontent.com  objects.githubusercontent.com
2606:4700::1111 v6.example.com
0.0.0.0 ads.example.com
127.0.0.1 tracker.example.com
::1 v6block.example.com
:: v6block2.example.com
not-an-ip broken.example.com
140.82.113.4 uppercase.example.COM   # 行尾注释
140.82.113.5 github.com
# GitHub520 Host End
`
	got, st := parseHostsText(text)

	want := map[string]string{
		"github.com":                    "140.82.113.4",
		"gist.github.com":               "140.82.113.4",
		"raw.githubusercontent.com":     "185.199.108.133",
		"objects.githubusercontent.com": "185.199.108.133",
		"v6.example.com":                "2606:4700::1111",
		"uppercase.example.com":         "140.82.113.4", // 域名归一化成小写
	}
	for d, ip := range want {
		if got[d] != ip {
			t.Errorf("%s 应为 %s，实际 %q", d, ip, got[d])
		}
	}
	// 拦截条目一条都不许进来：写进去等于把这些域名指到一个打不开的地址。
	for _, d := range []string{"ads.example.com", "tracker.example.com",
		"v6block.example.com", "v6block2.example.com", "broken.example.com"} {
		if _, ok := got[d]; ok {
			t.Errorf("%s 不该被认成解析结果（实际 %q）", d, got[d])
		}
	}
	if st.blocked != 4 {
		t.Errorf("拦截条目应记 4 条，实际 %d", st.blocked)
	}
	if st.badIP != 1 {
		t.Errorf("首列不是 IP 的行应记 1 条，实际 %d", st.badIP)
	}
	// 重复域名取先出现的那个（和 /etc/hosts 的查找语义一致）。
	if got["github.com"] != "140.82.113.4" {
		t.Errorf("重复域名应保留第一次出现的 IP，实际 %q", got["github.com"])
	}
	if st.dup != 1 {
		t.Errorf("重复域名应记 1 条，实际 %d", st.dup)
	}
	if st.ok != len(got) {
		t.Errorf("ok 应等于结果条数 %d，实际 %d", len(got), st.ok)
	}
}

func TestParseHostsTextSkipsJunk(t *testing.T) {
	// 空文件、纯注释、只有 IP 没域名：都该是 0 条，而不是崩掉或者造出奇怪的东西。
	for _, text := range []string{"", "\n\n# nothing\n", "140.82.113.4\n", "1.2.3.4 localhost\n"} {
		got, _ := parseHostsText(text)
		if len(got) != 0 {
			t.Errorf("%q 应解析出 0 条，实际 %v", text, got)
		}
	}
}

func TestLooksLikeHTML(t *testing.T) {
	yes := []string{
		"<!DOCTYPE html><html><body>x</body></html>",
		"  \n<!doctype HTML>\n<html>",
		"\ufeff<html lang=\"zh\">",
	}
	for _, s := range yes {
		if !looksLikeHTML(s) {
			t.Errorf("%q 应被认成网页", s)
		}
	}
	no := []string{
		"# GitHub520 Host Start\n140.82.113.4 github.com\n",
		"",
		"140.82.113.4 github.com",
	}
	for _, s := range no {
		if looksLikeHTML(s) {
			t.Errorf("%q 不该被认成网页", s)
		}
	}
}

// TestFetchHostsRejectsHTMLPage 用户填了站点根路径时要报「这是网页」，
// 而不是笼统的「解析失败」——他才知道该去填 /hosts.txt。
func TestFetchHostsRejectsHTMLPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<!DOCTYPE html><html><body><h1>GitHub 加速</h1></body></html>"))
	}))
	defer srv.Close()

	_, err := fetchHosts(context.Background(), []string{srv.URL})
	if err == nil {
		t.Fatal("返回网页时应当报错，不能当成「源里没条目」——那会把 AdGuard 上的记录全删掉")
	}
	if !strings.Contains(err.Error(), "网页") {
		t.Errorf("错误信息要说明这是网页，实际: %v", err)
	}
}

// TestFetchHostsEmptyBodyIsError 200 但一条都认不出（空文件/纯注释）也算失败。
//
// 这一条防的是「上游某天返回一个 200 的空白页」：当成「源里现在没有条目」处理，
// 就会把 AdGuard 上几十条重写全删掉，而日志看起来一切正常。
func TestFetchHostsEmptyBodyIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("# 今天维护，暂无数据\n"))
	}))
	defer srv.Close()

	if _, err := fetchHosts(context.Background(), []string{srv.URL}); err == nil {
		t.Fatal("空内容应当报错，不能返回空表示「源里没条目」")
	}
}

// TestFetchHostsPartialFailure 一个链接挂了、另一个好的：用好的，并记下哪条挂了。
func TestFetchHostsPartialFailure(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("140.82.113.4 github.com\n"))
	}))
	defer good.Close()

	res, err := fetchHosts(context.Background(), []string{bad.URL, good.URL})
	if err != nil {
		t.Fatalf("有一个链接可用就不该整体失败: %v", err)
	}
	if res.entries["github.com"] != "140.82.113.4" {
		t.Errorf("好链接的结果没拿到: %v", res.entries)
	}
	if len(res.errs) != 1 || !strings.Contains(res.errs[0], bad.URL) {
		t.Errorf("要能看出是哪一个链接挂了，实际 %v", res.errs)
	}
}

func TestMergeHostsWant(t *testing.T) {
	cfg := config.Default().Clone()
	cfg.Domains = []string{"github.com"}
	cfg.RewrittenDomains = []string{"github.com", "old.example.com"}
	// 账本里记着上一轮写过的两个域名：一个这轮源里还有，一个没了。
	cfg.HostsEntries = map[string]string{
		"raw.githubusercontent.com": "185.199.108.133",
		"gone.example.com":          "9.9.9.9",
	}

	names := cfg.RewriteDomains()
	answers := map[string]bool{"162.159.39.41": true}
	want := rewritePlan(cfg, names, answers)

	hosts := map[string]string{
		"github.com":                "140.82.113.4", // 和加速域名重名
		"raw.githubusercontent.com": "185.199.108.133",
		"new.example.com":           "1.1.1.1",
	}
	st := mergeHostsWant(want, cfg, names, hosts)

	// 加速域名优先：github.com 的答案必须还是测速结果。
	if got := want["github.com"]; len(got) != 1 || !got["162.159.39.41"] {
		t.Errorf("和加速域名重名时应让给测速结果，实际 %v", got)
	}
	if st.skipped != 1 {
		t.Errorf("应记 1 条「与加速域名重名」，实际 %d", st.skipped)
	}
	if got := want["new.example.com"]; len(got) != 1 || !got["1.1.1.1"] {
		t.Errorf("源里的新域名没写进去: %v", got)
	}
	if got := want["raw.githubusercontent.com"]; len(got) != 1 || !got["185.199.108.133"] {
		t.Errorf("源里还有的域名答案不对: %v", got)
	}
	// 账本里有、这轮源里没有 → 空集合（= 清掉），否则它会永远留在 AdGuard 上。
	if got, ok := want["gone.example.com"]; !ok || len(got) != 0 {
		t.Errorf("源里消失的域名应给空集合，实际 %v（有没有这个键：%v）", got, ok)
	}
	if st.cleared != 1 {
		t.Errorf("应记 1 条清掉的，实际 %d", st.cleared)
	}
	// old.example.com 是**加速域名**的账本，归 rewritePlan 管，不该被算到 hosts 头上。
	if st.cleared != 1 {
		t.Errorf("hosts 不该去清加速域名那本账: %d", st.cleared)
	}
}

// TestMergeHostsWantNilClearsLedger 关掉开关 / 没填来源时 hosts 传 nil，
// 账本里那些必须变成空集合——否则界面上写着「已关闭」、AdGuard 上还在生效。
func TestMergeHostsWantNilClearsLedger(t *testing.T) {
	cfg := config.Default().Clone()
	cfg.HostsEntries = map[string]string{"a.example.com": "1.1.1.1", "b.example.com": "2.2.2.2"}

	want := map[string]map[string]bool{}
	st := mergeHostsWant(want, cfg, nil, nil)

	if st.added != 0 || st.cleared != 2 {
		t.Errorf("应清 2 条、写 0 条，实际 added=%d cleared=%d", st.added, st.cleared)
	}
	for _, d := range []string{"a.example.com", "b.example.com"} {
		if got, ok := want[d]; !ok || len(got) != 0 {
			t.Errorf("%s 应给空集合，实际 %v（有没有这个键：%v）", d, got, ok)
		}
	}
}

// TestResolveHostsFallsBackToLastRound 拉不到就沿用上一轮的条目，一条都不删。
//
// 这是「网络抖一下不能把 AdGuard 表抖没」那条口径的直接实现。
func TestResolveHostsFallsBackToLastRound(t *testing.T) {
	s, _ := newPasswordTestServer(t, "")
	cfg := s.cfg.Clone()
	cfg.HostsEnabled = true
	// 指向一个必定连不上的地址（端口 1）：比等超时快得多。
	cfg.HostsSource = "http://127.0.0.1:1/hosts.txt"
	cfg.HostsEntries = map[string]string{"github.com": "140.82.113.4"}

	got := s.resolveHosts(context.Background(), cfg)
	if len(got) != 1 || got["github.com"] != "140.82.113.4" {
		t.Fatalf("拉取失败时应沿用上一轮的条目，实际 %v", got)
	}
}

// TestResolveHostsOffWhenDisabled 开关关着就返回 nil（= 该清账本），
// 而且绝不去发网络请求——用户关了之后还每轮去拉一次是说不通的。
func TestResolveHostsOffWhenDisabled(t *testing.T) {
	s, _ := newPasswordTestServer(t, "")
	cfg := s.cfg.Clone()
	cfg.HostsEnabled = false
	cfg.HostsSource = "http://127.0.0.1:1/hosts.txt"
	cfg.HostsEntries = map[string]string{"github.com": "140.82.113.4"}

	if got := s.resolveHosts(context.Background(), cfg); got != nil {
		t.Fatalf("开关关掉时应返回 nil（让账本被清掉），实际 %v", got)
	}
}

// TestResolveHostsSuccess 拉成功时用新结果，并如实记下跳过了什么。
func TestResolveHostsSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(
			"140.82.113.4 github.com\n0.0.0.0 ads.example.com\n2606:4700::1111 v6.example.com\n"))
	}))
	defer srv.Close()

	s, _ := newPasswordTestServer(t, "")
	cfg := s.cfg.Clone()
	cfg.HostsEnabled = true
	cfg.HostsSource = srv.URL
	cfg.HostsEntries = map[string]string{"old.example.com": "9.9.9.9"}

	got := s.resolveHosts(context.Background(), cfg)
	if len(got) != 2 || got["github.com"] != "140.82.113.4" || got["v6.example.com"] != "2606:4700::1111" {
		t.Fatalf("应拿到 2 条（v4 + v6），实际 %v", got)
	}
	if _, ok := got["ads.example.com"]; ok {
		t.Error("拦截条目不该写进结果")
	}
	if _, ok := got["old.example.com"]; ok {
		t.Error("应该用这一轮的新结果，不该把上一轮的混进来")
	}
}

// TestHostsWantForOffMeansClear 锁住「关掉开关 = 账本交给收回逻辑」这条线。
//
// 接错的表现很隐蔽：开关关掉、日志一个字不记、记录原封不动留在 AdGuard 上
// （2026-11-18 真机就是这么反馈的），看起来像开关没生效。
func TestHostsWantForOffMeansClear(t *testing.T) {
	cfg := config.Default().Clone()
	cfg.HostsSource = "https://hosts.gitcdn.top/hosts.txt"
	cfg.HostsEntries = map[string]string{"a.example.com": "1.2.3.4"}

	cfg.HostsEnabled = true
	if got := hostsWantFor(cfg); len(got) != 1 {
		t.Fatalf("开着且填了来源时要交账本，实际 %v", got)
	}

	cfg.HostsEnabled = false
	if got := hostsWantFor(cfg); got != nil {
		t.Fatalf("关掉开关时必须给 nil（＝收回），实际 %v", got)
	}

	// 开关还开着但来源被清空：同样一条都不该留。
	cfg.HostsEnabled = true
	cfg.HostsSource = "  \n# 只剩注释\n"
	if got := hostsWantFor(cfg); got != nil {
		t.Fatalf("来源为空时必须给 nil，实际 %v", got)
	}
}

// TestEnableHostsNowWritesImmediately 锁住「打开开关当刻就写进 AdGuard」。
//
// 打开开关之后要立刻同步一次，后面再随测速轮走：不然用户看到的是「开关开了、
// AdGuard 里还是空的」，要等下一轮测速（默认一小时）才有反应，合理的判断就是
// 「开关没生效」。这条用例盯的就是这一下：一个假 hosts 源加一个假 AdGuard，
// 打开开关后重写表里必须已经有清单里那些域名。
func TestEnableHostsNowWritesImmediately(t *testing.T) {
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("1.1.1.1 a.example.com\n2.2.2.2 b.example.com\n"))
	}))
	defer src.Close()

	var mu sync.Mutex
	current := map[string]string{}
	ag := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/control/rewrite/list":
			out := make([]map[string]any, 0, len(current))
			for d, a := range current {
				out = append(out, map[string]any{"domain": d, "answer": a, "enabled": true})
			}
			_ = json.NewEncoder(w).Encode(out)
		case "/control/rewrite/add":
			var e struct {
				Domain string `json:"domain"`
				Answer string `json:"answer"`
			}
			_ = json.NewDecoder(r.Body).Decode(&e)
			current[e.Domain] = e.Answer
			_, _ = w.Write([]byte("{}"))
		case "/control/rewrite/delete":
			var e struct {
				Domain string `json:"domain"`
			}
			_ = json.NewDecoder(r.Body).Decode(&e)
			delete(current, e.Domain)
			_, _ = w.Write([]byte("{}"))
		default:
			_, _ = w.Write([]byte("{}"))
		}
	}))
	defer ag.Close()

	s := newToolsTestServer(t, func(c *config.Config) {
		c.AdGuard.URL = ag.URL
		c.HostsEnabled = true
		c.HostsSource = src.URL
		// 有测速结果，才能顺带验到「加速域名照常写」。
		c.LastIP = "104.16.0.9"
		c.Domains = []string{"mine.example.com"}
	})

	note := s.enableHostsNow(s.cfg.Clone())
	if !strings.Contains(note, "已开启 hosts 源") {
		t.Fatalf("返回值应说明已开启，实际 %q", note)
	}

	mu.Lock()
	got := map[string]string{}
	for k, v := range current {
		got[k] = v
	}
	mu.Unlock()

	if got["a.example.com"] != "1.1.1.1" || got["b.example.com"] != "2.2.2.2" {
		t.Errorf("打开开关后 AdGuard 里应立刻有清单那两条，实际 %v", got)
	}
	if got["mine.example.com"] != "104.16.0.9" {
		t.Errorf("加速域名那条也要照常写，实际 %v", got)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cfg.HostsEntries) != 2 {
		t.Errorf("账本应记下这 2 条，实际 %v", s.cfg.HostsEntries)
	}
	if s.cfg.HostsSyncedAt == "" {
		t.Error("HostsSyncedAt 应该写上，卡片要显示「上次同步」")
	}
}
