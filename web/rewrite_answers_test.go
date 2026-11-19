package web

// 「关掉一族就要把那一族从 AdGuard 收回」的测试。
//
// 这件事以前是坏的：期望答案直接拿 LastIP / LastIPv6IPs 拼，不看开关，所以关掉
// v6 之后只要碰一下域名列表，v6 那条又冒回 AdGuard；更别提「保存设置」这条路上
// 根本没人去碰 AdGuard，关了就等于要等下一轮测速（默认 60 分钟）才生效。
//
// 下面分两层盯着：rewriteAnswersFor 的返回值（纯函数，四态各验一次），
// 以及保存配置之后 AdGuard 里到底还剩什么（真的起一个假 AdGuard 对账）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/303528084/cf-ddns-sidecar/config"
	"github.com/303528084/cf-ddns-sidecar/dns"
)

// TestRewriteAnswersForFollowsSwitches 四态：两族都开、只 v4、只 v6、都关。
func TestRewriteAnswersForFollowsSwitches(t *testing.T) {
	cases := []struct {
		name string
		mode string // v4 的开关
		v6   string // v6 的开关
		want []string
	}{
		{"两族都开", config.SourceBuiltin, config.SourceBuiltin,
			[]string{"104.16.0.1", "2606:4700::1"}},
		{"只 v4", config.SourceBuiltin, config.SourceOff,
			[]string{"104.16.0.1"}},
		{"只 v6", config.SourceOff, config.SourceBuiltin,
			[]string{"2606:4700::1"}},
		{"两族都关", config.SourceOff, config.SourceOff, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := config.Default()
			cfg.Speed.SourceMode = c.mode
			cfg.IPv6SourceMode = c.v6
			cfg.LastIP = "104.16.0.1"
			cfg.LastIPv6IPs = []string{"2606:4700::1"}

			answers := rewriteAnswersFor(*cfg)
			got := make([]string, 0, len(answers))
			for a := range answers {
				got = append(got, a)
			}
			sort.Strings(got)
			if len(got) != len(c.want) {
				t.Fatalf("期望 %v，实际 %v", c.want, got)
			}
			for i := range c.want {
				if got[i] != c.want[i] {
					t.Fatalf("期望 %v，实际 %v", c.want, got)
				}
			}
		})
	}
}

// TestRewriteAnswersForNeedsRealAddress 开关开着也不算数：没有地址就是没有答案。
// 空串要当没有，不然会把空答案当成一条「该有的记录」写进 AdGuard。
func TestRewriteAnswersForNeedsRealAddress(t *testing.T) {
	cfg := config.Default()
	cfg.Speed.SourceMode = config.SourceBuiltin
	cfg.IPv6SourceMode = config.SourceBuiltin
	cfg.LastIP = ""
	cfg.LastIPv6IPs = []string{""}

	if got := rewriteAnswersFor(*cfg); len(got) != 0 {
		t.Fatalf("没有地址的时候答案应该是空的，实际 %v", got)
	}
}

// fakeAdGuard 只记 (域名, 答案) 这一对，够用来判断「哪一族还在」。
type fakeAdGuard struct {
	mu   sync.Mutex
	pair map[string]map[string]bool // 域名 -> 一堆答案
}

func newFakeAdGuard(t *testing.T, seed map[string][]string) (*fakeAdGuard, *httptest.Server) {
	t.Helper()
	f := &fakeAdGuard{pair: make(map[string]map[string]bool, len(seed))}
	for d, answers := range seed {
		set := make(map[string]bool, len(answers))
		for _, a := range answers {
			set[a] = true
		}
		f.pair[d] = set
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.Path {
		case "/control/rewrite/list":
			out := make([]map[string]any, 0, len(f.pair))
			for d, answers := range f.pair {
				for a := range answers {
					out = append(out, map[string]any{"domain": d, "answer": a, "enabled": true})
				}
			}
			_ = json.NewEncoder(w).Encode(out)
		case "/control/rewrite/add":
			var e struct {
				Domain string `json:"domain"`
				Answer string `json:"answer"`
			}
			_ = json.NewDecoder(r.Body).Decode(&e)
			if f.pair[e.Domain] == nil {
				f.pair[e.Domain] = make(map[string]bool, 1)
			}
			f.pair[e.Domain][e.Answer] = true
			_, _ = w.Write([]byte("{}"))
		case "/control/rewrite/delete":
			var e struct {
				Domain string `json:"domain"`
				Answer string `json:"answer"`
			}
			_ = json.NewDecoder(r.Body).Decode(&e)
			delete(f.pair[e.Domain], e.Answer)
			if len(f.pair[e.Domain]) == 0 {
				delete(f.pair, e.Domain)
			}
			_, _ = w.Write([]byte("{}"))
		default:
			_, _ = w.Write([]byte("{}"))
		}
	}))
	return f, srv
}

// answersOf 返回某个域名下现在的全部答案，排好序方便比对。
func (f *fakeAdGuard) answersOf(domain string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.pair[domain]))
	for a := range f.pair[domain] {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// 关掉 v6 再保存，AdGuard 里那条 v6 必须当刻消失、v4 原地不动。
//
// 「当刻」是重点：以前保存设置这条路根本不碰 AdGuard，要等下一轮测速才收回，
// 中间用户看到的就是「关了还在」。
func TestSaveConfigRetractsDisabledFamily(t *testing.T) {
	ag, srv := newFakeAdGuard(t, map[string][]string{
		"ok.test": {"104.16.0.1", "2606:4700::1"},
	})
	defer srv.Close()

	s := newToolsTestServer(t, func(c *config.Config) {
		c.AdGuard.URL = srv.URL
		c.Domains = []string{"ok.test"}
		c.LastIP = "104.16.0.1"
		c.LastIPv6IPs = []string{"2606:4700::1"}
		c.IPv6SourceMode = config.SourceBuiltin
	})

	// adguard_url 必须带上：保存接口对它不是「没传就不动」，而是无条件按请求体
	// 覆盖，不带就等于把地址清空，后面那段收回根本不会执行（界面每次都带上）。
	rec := sendJSON(t, s, http.MethodPost, "/api/config",
		`{"adguard_url":"`+srv.URL+`","ipv6_source_mode":"off"}`)
	if rec.Code != 200 {
		t.Fatalf("保存失败：%d %s", rec.Code, rec.Body.String())
	}

	got := ag.answersOf("ok.test")
	want := []string{"104.16.0.1"}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("关掉 v6 之后 AdGuard 里应只剩 v4，实际 %v", got)
	}
	// 日志里得说清「收走了」，不然用户点完保存只看到「已写入 0 条」，
	// 会以为什么都没发生。
	s.mu.Lock()
	logs := strings.Join(s.logs, "\n")
	s.mu.Unlock()
	if !strings.Contains(logs, "收回") {
		t.Fatalf("关掉 v6 之后日志里该有一句「收回」，实际：\n%s", logs)
	}
}

// TestRewriteSyncNote 三种结果各说一句话，重点是「只收回、没新增」不能报成「写入 0 条」。
func TestRewriteSyncNote(t *testing.T) {
	cases := []struct {
		stats dns.SyncStats
		want  string
	}{
		{dns.SyncStats{Written: 3}, "已写入 AdGuard：3 条"},
		{dns.SyncStats{Removed: 2}, "已从 AdGuard 收回 2 条"},
		{dns.SyncStats{Written: 1, Removed: 2}, "已写入 AdGuard：1 条，收回 2 条"},
		{dns.SyncStats{}, "已写入 AdGuard：0 条"},
	}
	for _, c := range cases {
		if got := rewriteSyncNote(c.stats); got != c.want {
			t.Errorf("%+v 应说成 %q，实际 %q", c.stats, c.want, got)
		}
	}
}

// 两族都关是「这个域名不该再有本工具写的记录」，全部收回。
func TestSaveConfigRetractsBothFamilies(t *testing.T) {
	ag, srv := newFakeAdGuard(t, map[string][]string{
		"ok.test": {"104.16.0.1", "2606:4700::1"},
	})
	defer srv.Close()

	s := newToolsTestServer(t, func(c *config.Config) {
		c.AdGuard.URL = srv.URL
		c.Domains = []string{"ok.test"}
		c.LastIP = "104.16.0.1"
		c.LastIPv6IPs = []string{"2606:4700::1"}
		c.IPv6SourceMode = config.SourceBuiltin
	})

	rec := sendJSON(t, s, http.MethodPost, "/api/config",
		`{"adguard_url":"`+srv.URL+`","source_mode":"off","ipv6_source_mode":"off"}`)
	if rec.Code != 200 {
		t.Fatalf("保存失败：%d %s", rec.Code, rec.Body.String())
	}

	if got := ag.answersOf("ok.test"); len(got) != 0 {
		t.Fatalf("两族都关之后不该留下任何重写，实际 %v", got)
	}
}

// 反过来的一条：开关开着但这一轮还没测出地址，一条都不许动。
//
// 这条和上面两条是同一条边界的两侧。混在一起就会很糟：一次普通的保存
// （别的设置改了点东西）把用户上一轮好好的结果抹掉。
func TestSaveConfigKeepsRewritesWhenNoResultYet(t *testing.T) {
	ag, srv := newFakeAdGuard(t, map[string][]string{
		"ok.test": {"104.16.0.1"},
	})
	defer srv.Close()

	// 两族都开着，但一轮都还没跑完：LastIP 空、LastIPv6IPs 空。
	// 这时候答案集合是空的，可按「全部收回」处理就会把用户上次的结果抹掉。
	s := newToolsTestServer(t, func(c *config.Config) {
		c.AdGuard.URL = srv.URL
		c.Domains = []string{"ok.test"}
		c.Speed.SourceMode = config.SourceBuiltin
		c.IPv6SourceMode = config.SourceBuiltin
	})

	rec := sendJSON(t, s, http.MethodPost, "/api/config",
		`{"adguard_url":"`+srv.URL+`","interval_minutes":30}`)
	if rec.Code != 200 {
		t.Fatalf("保存失败：%d %s", rec.Code, rec.Body.String())
	}

	got := ag.answersOf("ok.test")
	if len(got) != 1 || got[0] != "104.16.0.1" {
		t.Fatalf("没有新结果时不该动已有重写，现在变成 %v", got)
	}
}
