package web

// 「域名增删改」这三个增量接口的测试。
//
// 为什么这层要单独测：这三个接口直接改配置文件并立刻写 AdGuard，做错了不是
// 显示错了而已——加错一次、删错一次，用户的域名就真的从重写表里没了。所以
// 下面每一条都盯着「配置里到底变成什么」和「该不该动」这两件事：
//
//   - 确认不走 Cloudflare 的：**一个字都不能改**（这就是「不让添加」）；
//   - 查不到 IP 的：照样加进来（网络抖一下就丢掉用户填的域名更糟）；
//   - 重复点添加：不能出现两条一样的；
//   - 删掉之后：元信息（含子域、添加时间）也要跟着消失。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/303528084/cf-ddns-sidecar/config"
)

// sendJSON 以已登录身份发一个带 JSON body 的请求。
// 叫 sendJSON 而不是 postJSON：这里要用 PUT 和 DELETE，而 postJSON 这个名字
// 已经被 password_test.go 占着了（那个只发 POST）。
func sendJSON(t *testing.T, s *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "192.168.1.10:5000"
	req.Header.Set("Authorization", "Bearer "+s.signToken())
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// domainResp 是三个接口共用的响应形状。
type domainResp struct {
	OK      bool        `json:"ok"`
	Error   string      `json:"error"`
	Note    string      `json:"note"`
	Removed int         `json:"removed"`
	Domains []domainRow `json:"domains"`
}

func decodeDomainResp(t *testing.T, rec *httptest.ResponseRecorder) domainResp {
	t.Helper()
	var r domainResp
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("响应不是 JSON: %v，原文 %s", err, rec.Body.String())
	}
	return r
}

// domainsOf 读回服务端当前的域名列表。
func domainsOf(s *Server) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.cfg.Domains...)
}

// stubCFLookup 让所有域名都解析到一个 Cloudflare 的 IP。
func stubCFLookup(t *testing.T) {
	t.Helper()
	stubLookup(t, map[string][]string{
		"ok.test":     {"104.16.132.229"},
		"second.test": {"172.64.229.179"},
	}, nil)
	stubProbe(t, nil)
}

// TestDomainCheckOnlyDoesNotSave 检测接口只回结论，不能顺手把域名存进去。
func TestDomainCheckOnlyDoesNotSave(t *testing.T) {
	stubCFLookup(t)
	s := newToolsTestServer(t, nil)

	rec := sendJSON(t, s, http.MethodPost, "/api/domains/check", `{"domain":"ok.test"}`)
	if rec.Code != 200 {
		t.Fatalf("检测应返回 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var r struct {
		OK     bool        `json:"ok"`
		Result DomainCheck `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if !r.Result.OK {
		t.Fatalf("应判定为走 Cloudflare：%+v", r.Result)
	}
	if got := domainsOf(s); len(got) != 0 {
		t.Fatalf("只检测不该改配置，实际存了 %v", got)
	}
}

// TestDomainAddRejectsNonCloudflare 确认不走的域名：返回 400 且配置一个字都不改。
func TestDomainAddRejectsNonCloudflare(t *testing.T) {
	stubLookup(t, map[string][]string{"not-cf.test": {"93.184.216.34"}}, nil)
	stubProbe(t, nil) // 第二层也没探到 Cloudflare
	s := newToolsTestServer(t, nil)

	rec := sendJSON(t, s, http.MethodPost, "/api/domains", `{"domain":"not-cf.test"}`)
	if rec.Code != 400 {
		t.Fatalf("不走 Cloudflare 应被拒（400），实际 %d：%s", rec.Code, rec.Body.String())
	}
	if got := domainsOf(s); len(got) != 0 {
		t.Fatalf("被拒的域名不该进配置，实际 %v", got)
	}
	r := decodeDomainResp(t, rec)
	if !strings.Contains(r.Error, "Cloudflare") {
		t.Errorf("报错应说清原因，实际 %q", r.Error)
	}
	// 界面上那句红字用的是 result.reason，它得带上解析到的 IP。
	if !strings.Contains(rec.Body.String(), "93.184.216.34") {
		t.Errorf("结论里应写明解析到了哪个 IP，实际 %s", rec.Body.String())
	}
}

// TestDomainAddAcceptsUnknown 查不到 IP 的照样加：把「DNS 抖了一下」当成
// 「这个域名不走 Cloudflare」，等于让人白填一遍，还可能是自己 DNS 的问题。
func TestDomainAddAcceptsUnknown(t *testing.T) {
	stubLookup(t, nil, nil) // 表是空的 → 所有域名都按 no such host
	stubProbe(t, nil)
	s := newToolsTestServer(t, nil)

	rec := sendJSON(t, s, http.MethodPost, "/api/domains", `{"domain":"unknown.test"}`)
	if rec.Code != 200 {
		t.Fatalf("查不到 IP 也应能添加，实际 %d：%s", rec.Code, rec.Body.String())
	}
	if got := domainsOf(s); len(got) != 1 || got[0] != "unknown.test" {
		t.Fatalf("域名没存进去，实际 %v", got)
	}
	if !strings.Contains(strings.Join(s.logs, "\n"), "没验成") {
		t.Errorf("日志里应留一句「没验成」，实际：\n%s", strings.Join(s.logs, "\n"))
	}
}

// TestDomainAddWithWildcard 勾了「包含子域」要写进 DomainMeta，
// 并且 RewriteDomains 里要真的多出一条 *.域名（AdGuard 就是照它写的）。
func TestDomainAddWithWildcard(t *testing.T) {
	stubCFLookup(t)
	s := newToolsTestServer(t, nil)

	rec := sendJSON(t, s, http.MethodPost, "/api/domains", `{"domain":"ok.test","wildcard":true}`)
	if rec.Code != 200 {
		t.Fatalf("添加失败：%d %s", rec.Code, rec.Body.String())
	}
	s.mu.Lock()
	names := s.cfg.RewriteDomains()
	meta := s.cfg.DomainMeta["ok.test"]
	s.mu.Unlock()

	if !meta.Wildcard {
		t.Fatalf("wildcard 没存进元信息：%+v", meta)
	}
	if meta.AddedAt == "" {
		t.Error("添加时间没记下来")
	}
	want := []string{"ok.test", "*.ok.test"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("RewriteDomains = %v，期望 %v", names, want)
	}
}

// TestDomainAddTwiceDoesNotDuplicate 重复点添加不能出现两条，
// 也不能把第一次的添加时间刷成现在（那会让人以为域名是刚加的）。
func TestDomainAddTwiceDoesNotDuplicate(t *testing.T) {
	stubCFLookup(t)
	s := newToolsTestServer(t, nil)

	sendJSON(t, s, http.MethodPost, "/api/domains", `{"domain":"ok.test"}`)
	s.mu.Lock()
	firstAt := s.cfg.DomainMeta["ok.test"].AddedAt
	s.mu.Unlock()

	rec := sendJSON(t, s, http.MethodPost, "/api/domains", `{"domain":"ok.test","wildcard":true}`)
	if rec.Code != 200 {
		t.Fatalf("第二次添加失败：%d %s", rec.Code, rec.Body.String())
	}
	if got := domainsOf(s); len(got) != 1 {
		t.Fatalf("不该出现重复项，实际 %v", got)
	}
	s.mu.Lock()
	meta := s.cfg.DomainMeta["ok.test"]
	s.mu.Unlock()
	if meta.AddedAt != firstAt {
		t.Errorf("添加时间被刷新了：%q → %q", firstAt, meta.AddedAt)
	}
	if !meta.Wildcard {
		t.Error("第二次勾了包含子域，应该生效")
	}
}

// TestDomainAddNormalizesInput 大小写、协议、末尾斜杠都要先规范化再比。
// 不规范化的话 openai.com 和 OpenAI.com 会被当成两个域名写两条重写。
func TestDomainAddNormalizesInput(t *testing.T) {
	stubCFLookup(t)
	s := newToolsTestServer(t, nil)

	rec := sendJSON(t, s, http.MethodPost, "/api/domains", `{"domain":"  HTTPS://OK.test/path "}`)
	if rec.Code != 200 {
		t.Fatalf("添加失败：%d %s", rec.Code, rec.Body.String())
	}
	if got := domainsOf(s); len(got) != 1 || got[0] != "ok.test" {
		t.Fatalf("应规范化为 ok.test，实际 %v", got)
	}
}

// TestDomainAddEmptyRejected 空域名给 400，并且提示要能看懂。
func TestDomainAddEmptyRejected(t *testing.T) {
	stubCFLookup(t)
	s := newToolsTestServer(t, nil)

	rec := sendJSON(t, s, http.MethodPost, "/api/domains", `{"domain":"   "}`)
	if rec.Code != 400 {
		t.Fatalf("空域名应被拒，实际 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "填") {
		t.Errorf("提示应告诉用户要填域名，实际 %s", rec.Body.String())
	}
}

// TestDomainDeleteRemovesMeta 删域名要把元信息一起删掉。
// 留着的话，同名域名下次加回来会直接继承「包含子域」和旧时间。
func TestDomainDeleteRemovesMeta(t *testing.T) {
	stubCFLookup(t)
	s := newToolsTestServer(t, nil)

	sendJSON(t, s, http.MethodPost, "/api/domains", `{"domain":"ok.test","wildcard":true}`)
	sendJSON(t, s, http.MethodPost, "/api/domains", `{"domain":"second.test"}`)

	rec := call(s, http.MethodDelete, "/api/domains?domain=ok.test")
	if rec.Code != 200 {
		t.Fatalf("删除失败：%d %s", rec.Code, rec.Body.String())
	}
	if got := domainsOf(s); len(got) != 1 || got[0] != "second.test" {
		t.Fatalf("应只剩 second.test，实际 %v", got)
	}
	s.mu.Lock()
	_, still := s.cfg.DomainMeta["ok.test"]
	s.mu.Unlock()
	if still {
		t.Error("删掉的域名不该留下元信息")
	}
	if r := decodeDomainResp(t, rec); len(r.Domains) != 1 || r.Domains[0].Domain != "second.test" {
		t.Errorf("响应里的列表应只剩一条，实际 %+v", r.Domains)
	}
}

// TestDomainDeleteUnknown404 删一个不存在的域名：404，不能当成成功。
// 当成成功的话界面会刷掉列表，用户以为删掉了别的。
func TestDomainDeleteUnknown404(t *testing.T) {
	s := newToolsTestServer(t, nil)
	rec := call(s, http.MethodDelete, "/api/domains?domain=nope.test")
	if rec.Code != 404 {
		t.Fatalf("删不存在的域名应 404，实际 %d：%s", rec.Code, rec.Body.String())
	}
}

// TestDomainClearAll 一次清空整个列表：域名和元信息都不许剩。
//
// 这条盯的是「全清之后再加回一个同名域名」：元信息若留着，新加的那个会直接
// 继承上次的「包含子域」和添加时间，用户看到的是一进来就勾着子域的怪状态。
func TestDomainClearAll(t *testing.T) {
	stubCFLookup(t)
	s := newToolsTestServer(t, nil)
	sendJSON(t, s, http.MethodPost, "/api/domains", `{"domain":"ok.test","wildcard":true}`)
	sendJSON(t, s, http.MethodPost, "/api/domains", `{"domain":"second.test"}`)

	rec := call(s, http.MethodDelete, "/api/domains?all=1")
	if rec.Code != 200 {
		t.Fatalf("清空失败：%d %s", rec.Code, rec.Body.String())
	}
	if got := domainsOf(s); len(got) != 0 {
		t.Fatalf("清空之后列表应为空，实际 %v", got)
	}
	s.mu.Lock()
	meta := len(s.cfg.DomainMeta)
	s.mu.Unlock()
	if meta != 0 {
		t.Errorf("清空之后元信息也要清掉，还剩 %d 条", meta)
	}
	r := decodeDomainResp(t, rec)
	if r.Removed != 2 || len(r.Domains) != 0 {
		t.Errorf("响应应报删了 2 条、列表为空，实际 removed=%d domains=%v", r.Removed, r.Domains)
	}
}

// TestDomainClearAllOnEmpty 列表本来就空的时候点「全部删除」：200 加一句话，
// 不能报错——界面上那个按钮在空列表时是藏着的，但接口不该因此变得脆弱。
func TestDomainClearAllOnEmpty(t *testing.T) {
	s := newToolsTestServer(t, nil)
	rec := call(s, http.MethodDelete, "/api/domains?all=1")
	if rec.Code != 200 {
		t.Fatalf("空列表清空应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	if r := decodeDomainResp(t, rec); r.Removed != 0 {
		t.Errorf("应报删了 0 条，实际 %d", r.Removed)
	}
}

// TestDomainWildcardToggle 切换子域开关：勾上多一条 *.域名，取消就没了。
func TestDomainWildcardToggle(t *testing.T) {
	stubCFLookup(t)
	s := newToolsTestServer(t, nil)
	sendJSON(t, s, http.MethodPost, "/api/domains", `{"domain":"ok.test"}`)

	rec := sendJSON(t, s, http.MethodPut, "/api/domains/wildcard", `{"domain":"ok.test","wildcard":true}`)
	if rec.Code != 200 {
		t.Fatalf("打开子域失败：%d %s", rec.Code, rec.Body.String())
	}
	s.mu.Lock()
	on := s.cfg.RewriteDomains()
	s.mu.Unlock()
	if strings.Join(on, ",") != "ok.test,*.ok.test" {
		t.Fatalf("勾上之后应多一条通配符，实际 %v", on)
	}

	rec = sendJSON(t, s, http.MethodPut, "/api/domains/wildcard", `{"domain":"ok.test","wildcard":false}`)
	if rec.Code != 200 {
		t.Fatalf("关闭子域失败：%d %s", rec.Code, rec.Body.String())
	}
	s.mu.Lock()
	off := s.cfg.RewriteDomains()
	s.mu.Unlock()
	if strings.Join(off, ",") != "ok.test" {
		t.Fatalf("取消之后应只剩本体，实际 %v", off)
	}
}

// TestDomainWildcardUnknown404 给一个不在列表里的域名切换子域：404。
func TestDomainWildcardUnknown404(t *testing.T) {
	s := newToolsTestServer(t, nil)
	rec := sendJSON(t, s, http.MethodPut, "/api/domains/wildcard", `{"domain":"nope.test","wildcard":true}`)
	if rec.Code != 404 {
		t.Fatalf("应 404，实际 %d：%s", rec.Code, rec.Body.String())
	}
}

// TestConfigReportsDomainRows 界面靠 /api/config 里的 domain_rows 画列表，
// 里面必须带着「含不含子域」——少了它，刷新之后所有开关都会显示成「仅本域」。
func TestConfigReportsDomainRows(t *testing.T) {
	stubCFLookup(t)
	s := newToolsTestServer(t, nil)
	sendJSON(t, s, http.MethodPost, "/api/domains", `{"domain":"ok.test","wildcard":true}`)

	rec := call(s, http.MethodGet, "/api/config")
	if rec.Code != 200 {
		t.Fatalf("读配置失败：%d", rec.Code)
	}
	var got struct {
		Domains    []string    `json:"domains"`
		DomainRows []domainRow `json:"domain_rows"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Domains) != 1 || got.Domains[0] != "ok.test" {
		t.Fatalf("domains 字段不对：%v", got.Domains)
	}
	if len(got.DomainRows) != 1 {
		t.Fatalf("domain_rows 应有 1 条，实际 %+v", got.DomainRows)
	}
	if !got.DomainRows[0].Wildcard {
		t.Errorf("domain_rows 里的 wildcard 丢了：%+v", got.DomainRows[0])
	}
	if got.DomainRows[0].AddedAt == "" {
		t.Errorf("domain_rows 里应有添加时间：%+v", got.DomainRows[0])
	}
}

// TestSaveConfigWithoutDomainsKeepsThem 这是最关键的一条回归测试。
//
// 域名改由增量接口管之后，界面点「保存全部设置」不再提交 domains 字段。
// 如果后端还把它当成「传了空列表」，用户点一次保存，域名就全被清空了。
func TestSaveConfigWithoutDomainsKeepsThem(t *testing.T) {
	stubCFLookup(t)
	s := newToolsTestServer(t, nil)
	sendJSON(t, s, http.MethodPost, "/api/domains", `{"domain":"ok.test","wildcard":true}`)

	rec := sendJSON(t, s, http.MethodPost, "/api/config", `{"adguard_url":"http://192.168.1.2:3000"}`)
	if rec.Code != 200 {
		t.Fatalf("保存失败：%d %s", rec.Code, rec.Body.String())
	}
	if got := domainsOf(s); len(got) != 1 || got[0] != "ok.test" {
		t.Fatalf("没传 domains 时不该动已有域名，实际 %v", got)
	}
	s.mu.Lock()
	wild := s.cfg.DomainMeta["ok.test"].Wildcard
	s.mu.Unlock()
	if !wild {
		t.Error("没传 domains 时也不该丢掉「包含子域」")
	}
}

// TestSaveConfigWithDomainsStillScreens 传了 domains 的老路子还得照旧检查
// （导入文件、旧客户端走的是这条路）。
func TestSaveConfigWithDomainsStillScreens(t *testing.T) {
	stubLookup(t, map[string][]string{"not-cf.test": {"93.184.216.34"}}, nil)
	stubProbe(t, nil)
	s := newToolsTestServer(t, nil)

	rec := sendJSON(t, s, http.MethodPost, "/api/config",
		`{"domains":["not-cf.test"],"adguard_url":"http://192.168.1.2:3000"}`)
	if rec.Code != 200 {
		t.Fatalf("保存应成功（被拒的域名只是不保存，不是整单失败）：%d %s", rec.Code, rec.Body.String())
	}
	if got := domainsOf(s); len(got) != 0 {
		t.Fatalf("确认不走 Cloudflare 的域名不该被存进去，实际 %v", got)
	}
	if !strings.Contains(rec.Body.String(), "domains_rejected") {
		t.Errorf("响应里应带出被拒的域名，实际 %s", rec.Body.String())
	}
}

// TestDomainAddWritesWildcardToAdGuard 这是「包含子域」真正落地的地方。
//
// 前面几条只验到「配置里记下了 wildcard=true」，但用户要的效果是 AdGuard 的
// 重写表里多出一条 `*.域名`。这里起一个假 AdGuard，把收到的重写记下来对账。
func TestDomainAddWritesWildcardToAdGuard(t *testing.T) {
	stubCFLookup(t)

	var mu sync.Mutex
	var written []string
	ag := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/control/rewrite/list":
			// 空表：ReplaceRewrites 会先清空再写，这里没有要清的东西。
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("[]"))
		case "/control/rewrite/add":
			var e struct {
				Domain string `json:"domain"`
				Answer string `json:"answer"`
			}
			json.NewDecoder(r.Body).Decode(&e)
			mu.Lock()
			written = append(written, e.Domain+" -> "+e.Answer)
			mu.Unlock()
			w.Write([]byte("{}"))
		default:
			w.Write([]byte("{}"))
		}
	}))
	defer ag.Close()

	s := newToolsTestServer(t, func(c *config.Config) {
		c.AdGuard.URL = ag.URL
		// 没有最优 IP 就不会写 AdGuard，这里给一个，模拟「已经测过速」。
		c.LastIP = "104.16.132.229"
	})

	rec := sendJSON(t, s, http.MethodPost, "/api/domains", `{"domain":"ok.test","wildcard":true}`)
	if rec.Code != 200 {
		t.Fatalf("添加失败：%d %s", rec.Code, rec.Body.String())
	}

	mu.Lock()
	got := append([]string(nil), written...)
	mu.Unlock()
	sort.Strings(got)
	want := []string{"*.ok.test -> 104.16.132.229", "ok.test -> 104.16.132.229"}
	if strings.Join(got, " | ") != strings.Join(want, " | ") {
		t.Fatalf("AdGuard 收到的重写不对：\n实际 %v\n期望 %v", got, want)
	}
	if r := decodeDomainResp(t, rec); !strings.Contains(r.Note, "通配符") {
		t.Errorf("note 应说明其中有一条是子域通配符，实际 %q", r.Note)
	}
}

// TestDomainWildcardOffRemovesFromAdGuard 取消「含子域」之后，`*.域名` 那条
// 必须从 AdGuard 里消失——不然用户以为关了，实际还在拦整个子域。
func TestDomainWildcardOffRemovesFromAdGuard(t *testing.T) {
	stubCFLookup(t)

	var mu sync.Mutex
	current := map[string]string{} // domain -> answer
	ag := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/control/rewrite/list":
			out := make([]map[string]any, 0, len(current))
			for d, a := range current {
				out = append(out, map[string]any{"domain": d, "answer": a, "enabled": true})
			}
			json.NewEncoder(w).Encode(out)
		case "/control/rewrite/add":
			var e struct {
				Domain string `json:"domain"`
				Answer string `json:"answer"`
			}
			json.NewDecoder(r.Body).Decode(&e)
			current[e.Domain] = e.Answer
			w.Write([]byte("{}"))
		case "/control/rewrite/delete":
			var e struct {
				Domain string `json:"domain"`
			}
			json.NewDecoder(r.Body).Decode(&e)
			delete(current, e.Domain)
			w.Write([]byte("{}"))
		}
	}))
	defer ag.Close()

	s := newToolsTestServer(t, func(c *config.Config) {
		c.AdGuard.URL = ag.URL
		c.LastIP = "104.16.132.229"
	})

	sendJSON(t, s, http.MethodPost, "/api/domains", `{"domain":"ok.test","wildcard":true}`)
	mu.Lock()
	withWild := len(current)
	mu.Unlock()
	if withWild != 2 {
		t.Fatalf("打开子域后 AdGuard 里应有 2 条，实际 %d 条", withWild)
	}

	rec := sendJSON(t, s, http.MethodPut, "/api/domains/wildcard", `{"domain":"ok.test","wildcard":false}`)
	if rec.Code != 200 {
		t.Fatalf("关闭子域失败：%d %s", rec.Code, rec.Body.String())
	}
	mu.Lock()
	_, still := current["*.ok.test"]
	left := len(current)
	mu.Unlock()
	if still {
		t.Error("取消之后 AdGuard 里还留着 *.ok.test")
	}
	if left != 1 {
		t.Errorf("取消之后 AdGuard 里应只剩 1 条，实际 %d 条", left)
	}
}

// TestDomainAddNoteWhenAdGuardMissing 没填 AdGuard 地址时也要保存成功，
// 但 note 要说清「还没真正生效」——否则用户会以为域名已经在拦广告了。
func TestDomainAddNoteWhenAdGuardMissing(t *testing.T) {
	stubCFLookup(t)
	s := newToolsTestServer(t, func(c *config.Config) {
		c.AdGuard.URL = ""
	})
	rec := sendJSON(t, s, http.MethodPost, "/api/domains", `{"domain":"ok.test"}`)
	if rec.Code != 200 {
		t.Fatalf("没填 AdGuard 地址不该导致添加失败：%d %s", rec.Code, rec.Body.String())
	}
	r := decodeDomainResp(t, rec)
	if !strings.Contains(r.Note, "AdGuard") {
		t.Errorf("note 应说明 AdGuard 那一步没做，实际 %q", r.Note)
	}
}

// TestDomainAddKeepsIPv6Answer 点一下「加域名」不能把家里的 v6 重写顺手抹掉。
//
// ReplaceRewrites 是「先清空整张重写表、再按 want 重建」，而这条路径用的是
// 上一次测速结果（LastIP / LastIPv6IPs）。如果只往 want 里放 v4，用户只是
// 加了个域名，所有 AAAA 重写就静悄悄没了——界面上还会显示「已写入 N 条」。
func TestDomainAddKeepsIPv6Answer(t *testing.T) {
	stubCFLookup(t)

	var mu sync.Mutex
	var written []string
	ag := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/control/rewrite/list":
			w.Write([]byte("[]"))
		case "/control/rewrite/add":
			var e struct {
				Domain string `json:"domain"`
				Answer string `json:"answer"`
			}
			json.NewDecoder(r.Body).Decode(&e)
			mu.Lock()
			written = append(written, e.Domain+" -> "+e.Answer)
			mu.Unlock()
			w.Write([]byte("{}"))
		default:
			w.Write([]byte("{}"))
		}
	}))
	defer ag.Close()

	s := newToolsTestServer(t, func(c *config.Config) {
		c.AdGuard.URL = ag.URL
		c.LastIP = "104.16.132.229"
		c.LastIPv6IPs = []string{"2606:4700::1", "2606:4700::2"}
		// 空值按「关闭」读，关掉的那一族不进 AdGuard。这条测试要的是 v6 那一条
		// 别丢，所以得先把 v6 打开，否则测的是另一件事。
		c.IPv6SourceMode = config.SourceBuiltin
	})

	rec := sendJSON(t, s, http.MethodPost, "/api/domains", `{"domain":"v6.test","wildcard":false}`)
	if rec.Code != 200 {
		t.Fatalf("添加失败：%d %s", rec.Code, rec.Body.String())
	}

	mu.Lock()
	got := append([]string(nil), written...)
	mu.Unlock()
	sort.Strings(got)
	want := []string{"v6.test -> 104.16.132.229", "v6.test -> 2606:4700::1"}
	if strings.Join(got, " | ") != strings.Join(want, " | ") {
		t.Fatalf("AdGuard 收到的重写不对（v6 最优那条必须也在）：\n实际 %v\n期望 %v", got, want)
	}
}
