package dns

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/303528084/cf-ddns-sidecar/config"
)

// fakeAdGuard 是一个最小的 AdGuard Home 重写表，只实现本项目用到的三个接口：
// list / add / delete。同时记下「谁被删了、谁被加了」，好让用例断言到底动了哪几条
// ——只看最终状态是不够的：先全删再重建也能得到同样的最终状态，而那正是要防的行为。
type fakeAdGuard struct {
	mu      sync.Mutex
	table   []agRewrite
	adds    []string // "domain|answer"
	deletes []string // "domain|answer"
}

func (f *fakeAdGuard) snapshot() (table, adds, deletes []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.table {
		table = append(table, e.Domain+"|"+e.Answer)
	}
	adds = append(adds, f.adds...)
	deletes = append(deletes, f.deletes...)
	return
}

func newFakeAdGuard(entries ...agRewrite) (*fakeAdGuard, *httptest.Server) {
	f := &fakeAdGuard{table: entries}
	mux := http.NewServeMux()
	mux.HandleFunc("/control/rewrite/list", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(f.table)
	})
	mux.HandleFunc("/control/rewrite/add", func(w http.ResponseWriter, r *http.Request) {
		var e agRewrite
		_ = json.NewDecoder(r.Body).Decode(&e)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.table = append(f.table, e)
		f.adds = append(f.adds, e.Domain+"|"+e.Answer)
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/control/rewrite/delete", func(w http.ResponseWriter, r *http.Request) {
		var e agRewrite
		_ = json.NewDecoder(r.Body).Decode(&e)
		f.mu.Lock()
		defer f.mu.Unlock()
		kept := make([]agRewrite, 0, len(f.table))
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

func clientFor(srv *httptest.Server) Provider {
	return NewAdGuard(config.AdguardInstance{URL: srv.URL})
}

// TestReplaceRewritesNeverWipesForeignRecords 是本轮修复的核心用例。
//
// 老行为是「清空整张表再按 want 重建」，表里不是本工具写的记录会全部消失。
// 用户自己在 AdGuard 后台加的那几条重写就是这么没的，而且没有任何提示。
func TestReplaceRewritesNeverWipesForeignRecords(t *testing.T) {
	f, srv := newFakeAdGuard(
		agRewrite{Domain: "my-printer.lan", Answer: "192.168.1.9", Enabled: true},
		agRewrite{Domain: "nas.lan", Answer: "192.168.1.10", Enabled: true},
		agRewrite{Domain: "router.lan", Answer: "192.168.1.1", Enabled: true},
	)
	defer srv.Close()

	stats, err := clientFor(srv).ReplaceRewrites(map[string]map[string]bool{
		"openai.com": {"104.16.0.1": true},
	})
	if err != nil {
		t.Fatalf("不该失败: %v", err)
	}

	table, adds, deletes := f.snapshot()
	if len(deletes) != 0 {
		t.Fatalf("一条别人的记录都不该删，实际删了 %v", deletes)
	}
	if len(adds) != 1 || adds[0] != "openai.com|104.16.0.1" {
		t.Fatalf("应只新增 openai.com 那条，实际 %v", adds)
	}
	if len(table) != 4 {
		t.Fatalf("别人的 3 条加上新的 1 条应共 4 条，实际 %d 条：%v", len(table), table)
	}
	if stats.Kept != 3 || stats.Written != 1 || stats.Removed != 0 {
		t.Fatalf("统计不对: 保留 %d / 新增 %d / 删除 %d", stats.Kept, stats.Written, stats.Removed)
	}
}

// TestReplaceRewritesOnlyTouchesClaimedDomains 同一个域名下答案换了，只改这一条，
// 旁边那个域名一条都不动。
func TestReplaceRewritesOnlyTouchesClaimedDomains(t *testing.T) {
	f, srv := newFakeAdGuard(
		agRewrite{Domain: "openai.com", Answer: "1.2.3.4", Enabled: true},
		agRewrite{Domain: "keep.example.com", Answer: "5.6.7.8", Enabled: true},
	)
	defer srv.Close()

	stats, err := clientFor(srv).ReplaceRewrites(map[string]map[string]bool{
		"openai.com":       {"104.16.0.1": true, "2606:4700::1": true},
		"keep.example.com": {"5.6.7.8": true},
	})
	if err != nil {
		t.Fatalf("不该失败: %v", err)
	}

	table, adds, deletes := f.snapshot()
	// 只有旧的那条该被删；keep.example.com 答案已经对了，连「删了再加」都不该发生
	if len(deletes) != 1 || deletes[0] != "openai.com|1.2.3.4" {
		t.Fatalf("应只删 openai.com 的旧答案，实际删了 %v", deletes)
	}
	// v4 + v6 两条都要补上
	if len(adds) != 2 || adds[0] != "openai.com|104.16.0.1" || adds[1] != "openai.com|2606:4700::1" {
		t.Fatalf("应新增 v4 与 v6 各一条，实际 %v", adds)
	}
	// keep.example.com 是**认领了但已经写对**的域名，不算「别人的记录」：
	// Kept 统计的是「不归本工具管、一条都没碰」的那些，这里一条都没有。
	if stats.Kept != 0 {
		t.Fatalf("没有别人的记录时 Kept 应为 0，实际 %d", stats.Kept)
	}
	if stats.Written != 2 || stats.Removed != 1 {
		t.Fatalf("统计不对: 新增 %d / 删除 %d", stats.Written, stats.Removed)
	}
	if len(table) != 3 {
		t.Fatalf("最终应有 3 条（keep 1 条 + openai 2 条），实际 %v", table)
	}
}

// TestReplaceRewritesClearsDroppedDomain 空答案集 = 「这个域名不该有任何记录」，
// 用来清掉用户已经从域名列表里删掉的域名在 AdGuard 上的残留。
func TestReplaceRewritesClearsDroppedDomain(t *testing.T) {
	f, srv := newFakeAdGuard(
		agRewrite{Domain: "old.example.com", Answer: "104.16.0.9", Enabled: true},
		agRewrite{Domain: "old.example.com", Answer: "2606:4700::9", Enabled: true},
		agRewrite{Domain: "keep.example.com", Answer: "1.1.1.1", Enabled: true},
	)
	defer srv.Close()

	// rewritePlan 会把「账本里有、当前列表里没有」的域名以空集放进来，
	// 这里直接模拟那个形状。
	stats, err := clientFor(srv).ReplaceRewrites(map[string]map[string]bool{
		"keep.example.com": {"1.1.1.1": true},
		"old.example.com":  {},
	})
	if err != nil {
		t.Fatalf("不该失败: %v", err)
	}

	table, adds, deletes := f.snapshot()
	if len(deletes) != 2 {
		t.Fatalf("old.example.com 的两条都该删，实际 %v", deletes)
	}
	if len(adds) != 0 {
		t.Fatalf("不该新增任何东西，实际 %v", adds)
	}
	if len(table) != 1 || table[0] != "keep.example.com|1.1.1.1" {
		t.Fatalf("应只剩 keep.example.com，实际 %v", table)
	}
	if stats.Removed != 2 || stats.Written != 0 {
		t.Fatalf("统计不对: 删除 %d / 新增 %d", stats.Removed, stats.Written)
	}
}

// TestReplaceRewritesRevivesDisabledRecord 停用过的记录要被重写成启用状态。
//
// 否则会出现「记录在、但不生效」：重写表里明明有一条，域名就是不解析成那个 IP，
// 而界面上没有任何地方能看出这条被停用过——这类坏状态最难自己发现。
func TestReplaceRewritesRevivesDisabledRecord(t *testing.T) {
	f, srv := newFakeAdGuard(
		agRewrite{Domain: "openai.com", Answer: "104.16.0.1", Enabled: false},
	)
	defer srv.Close()

	if _, err := clientFor(srv).ReplaceRewrites(map[string]map[string]bool{
		"openai.com": {"104.16.0.1": true},
	}); err != nil {
		t.Fatalf("不该失败: %v", err)
	}

	_, adds, deletes := f.snapshot()
	if len(deletes) != 1 || len(adds) != 1 {
		t.Fatalf("停用的那条应删了重写成启用，实际删 %v 加 %v", deletes, adds)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.table) != 1 || !f.table[0].Enabled {
		t.Fatalf("重写后应是 1 条启用记录，实际 %#v", f.table)
	}
}

// TestReplaceRewritesEmptyWantTouchesNothing 全空（没有任何域名）时什么都不该做。
func TestReplaceRewritesEmptyWantTouchesNothing(t *testing.T) {
	f, srv := newFakeAdGuard(
		agRewrite{Domain: "my-printer.lan", Answer: "192.168.1.9", Enabled: true},
	)
	defer srv.Close()

	stats, err := clientFor(srv).ReplaceRewrites(map[string]map[string]bool{})
	if err != nil {
		t.Fatalf("不该失败: %v", err)
	}
	table, adds, deletes := f.snapshot()
	if len(adds) != 0 || len(deletes) != 0 {
		t.Fatalf("什么都不该做，实际加 %v 删 %v", adds, deletes)
	}
	if len(table) != 1 || stats.Kept != 1 {
		t.Fatalf("唯一那条别人记录应留着，实际 %v（Kept=%d）", table, stats.Kept)
	}
}
