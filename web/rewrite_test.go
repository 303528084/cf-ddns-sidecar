package web

// 「AdGuard 只动自己认领的域名」这套机制的两层测试：
//  ① rewritePlan 是纯函数，负责决定「这一轮管哪些域名、哪些旧域名该清」；
//  ② 删域名那条接口要真的把旧记录从 AdGuard 上清掉，并把账本更新掉。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/303528084/cf-ddns-sidecar/config"
)

// agRecord 是假 AdGuard 里的一条重写。
type agRecord struct {
	Domain  string `json:"domain"`
	Answer  string `json:"answer"`
	Enabled bool   `json:"enabled"`
}

// agFake 是一个最小的 AdGuard 重写表，并记下「加了什么、删了什么」。
type agFake struct {
	mu      sync.Mutex
	table   []agRecord
	adds    []string
	deletes []string
}

func (f *agFake) deleted() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.deletes...)
}

func (f *agFake) remaining() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.table))
	for _, e := range f.table {
		out = append(out, e.Domain+"|"+e.Answer)
	}
	return out
}

func newAGFake(entries ...agRecord) (*agFake, *httptest.Server) {
	f := &agFake{table: entries}
	mux := http.NewServeMux()
	mux.HandleFunc("/control/rewrite/list", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(f.table)
	})
	mux.HandleFunc("/control/rewrite/add", func(w http.ResponseWriter, r *http.Request) {
		var e agRecord
		_ = json.NewDecoder(r.Body).Decode(&e)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.table = append(f.table, e)
		f.adds = append(f.adds, e.Domain+"|"+e.Answer)
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/control/rewrite/delete", func(w http.ResponseWriter, r *http.Request) {
		var e agRecord
		_ = json.NewDecoder(r.Body).Decode(&e)
		f.mu.Lock()
		defer f.mu.Unlock()
		kept := make([]agRecord, 0, len(f.table))
		for _, cur := range f.table {
			if cur.Domain == e.Domain && cur.Answer == e.Answer {
				continue
			}
			kept = append(kept, cur)
		}
		f.table = kept
		f.deletes = append(f.deletes, e.Domain+"|"+e.Answer)
		_, _ = w.Write([]byte(`{}`))
	})
	return f, httptest.NewServer(mux)
}

// TestRewritePlanClearsDroppedDomains 是这个功能点的规则本身：
// 账本里有、当前列表里没有的域名 → 空答案集（整条清掉）。
func TestRewritePlanClearsDroppedDomains(t *testing.T) {
	answers := map[string]bool{"1.1.1.1": true}

	t.Run("删掉的域名进清理名单", func(t *testing.T) {
		cfg := config.Config{
			Domains:          []string{"keep.com"},
			RewrittenDomains: []string{"keep.com", "dropped.com"},
		}
		want := rewritePlan(cfg, []string{"keep.com"}, answers)
		if len(want) != 2 {
			t.Fatalf("应有 keep.com 与 dropped.com 两项，实际 %#v", want)
		}
		if len(want["dropped.com"]) != 0 {
			t.Fatalf("dropped.com 应是空答案集（表示清掉），实际 %#v", want["dropped.com"])
		}
		if !want["keep.com"]["1.1.1.1"] {
			t.Fatalf("keep.com 应写当前最优 IP，实际 %#v", want["keep.com"])
		}
	})

	t.Run("又加回列表的域名按正常答案写", func(t *testing.T) {
		cfg := config.Config{RewrittenDomains: []string{"back.com"}}
		want := rewritePlan(cfg, []string{"back.com"}, answers)
		if want["back.com"]["1.1.1.1"] != true {
			t.Fatalf("加回列表后应按当前答案写，不能当成要清的，实际 %#v", want["back.com"])
		}
	})

	t.Run("通配符条目不算丢失", func(t *testing.T) {
		cfg := config.Config{RewrittenDomains: []string{"*.a.com"}}
		want := rewritePlan(cfg, []string{"a.com", "*.a.com"}, answers)
		if len(want) != 2 {
			t.Fatalf("通配符已经在名单里，不该被当成要清理的，实际 %#v", want)
		}
	})

	// 没有答案时**绝对不能**带清理项：否则会变成「把所有域名下的记录都删掉」，
	// 把上一轮好好的结果抹了。调用方本来就会先拦住「没 IP 不写」，这里兜一层。
	t.Run("没有答案时不做任何清理", func(t *testing.T) {
		cfg := config.Config{RewrittenDomains: []string{"dropped.com"}}
		want := rewritePlan(cfg, []string{"keep.com"}, map[string]bool{})
		if len(want) != 1 {
			t.Fatalf("没有最优 IP 时不该出现清理项，实际 %#v", want)
		}
		if _, ok := want["dropped.com"]; ok {
			t.Fatal("没有最优 IP 时 dropped.com 不该被清掉")
		}
	})
}

// TestDeleteDomainClearsAdguardAndUpdatesLedger 删一个域名之后：
//   - 它在 AdGuard 上的记录被清掉（不是整张表重来）；
//   - 别人手工加的那条原样留着；
//   - 账本里只剩还在列表里的域名，否则下次同步又会去删一遍不存在的东西。
func TestDeleteDomainClearsAdguardAndUpdatesLedger(t *testing.T) {
	f, srv := newAGFake(
		agRecord{Domain: "a.com", Answer: "104.16.0.1", Enabled: true},
		agRecord{Domain: "a.com", Answer: "2606:4700::1", Enabled: true},
		agRecord{Domain: "my-printer.lan", Answer: "192.168.1.9", Enabled: true},
	)
	defer srv.Close()

	s := newToolsTestServer(t, func(c *config.Config) {
		c.AdGuard.URL = srv.URL
		c.Domains = []string{"a.com", "b.com"}
		c.RewrittenDomains = []string{"a.com", "b.com"}
		c.LastIP = "104.16.0.1"
		c.LastIPv6IPs = []string{"2606:4700::1"}
	})

	req := httptest.NewRequest(http.MethodDelete, "/api/domains?domain=a.com", nil)
	req.RemoteAddr = "192.168.1.10:5000"
	req.Header.Set("Authorization", "Bearer "+s.signToken())
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("删域名应成功，实际 %d，body=%s", rec.Code, rec.Body.String())
	}

	gone := f.deleted()
	// a.com 的 v4 与 v6 两条都该删
	if len(gone) != 2 {
		t.Fatalf("a.com 的两条都该被删，实际 %v", gone)
	}
	for _, e := range gone {
		if e != "a.com|104.16.0.1" && e != "a.com|2606:4700::1" {
			t.Fatalf("不该删 %s（那不是 a.com 的记录）", e)
		}
	}

	// b.com 还没写过，这次会补上；my-printer.lan 必须原样留着
	left := f.remaining()
	foundForeign := false
	for _, e := range left {
		if e == "my-printer.lan|192.168.1.9" {
			foundForeign = true
		}
		if len(e) > 6 && e[:6] == "a.com|" {
			t.Fatalf("a.com 的记录应清干净，却还剩 %s", e)
		}
	}
	if !foundForeign {
		t.Fatalf("别人手工加的那条被删了，实际剩 %v", left)
	}

	// 账本要跟着缩到只剩还在列表里的域名
	s.mu.Lock()
	ledger := append([]string{}, s.cfg.RewrittenDomains...)
	s.mu.Unlock()
	if len(ledger) != 1 || ledger[0] != "b.com" {
		t.Fatalf("账本应只剩 b.com，实际 %v", ledger)
	}
}
