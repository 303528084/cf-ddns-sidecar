package web

// 「要加速的域名」的增删改。
//
// 为什么单独一套接口，而不是让界面复用 /api/config：
//
//	/api/config 是**全量覆盖**式的保存——请求里没带的字段要么被清空、
//	要么按默认值写回去。用它做「加一个域名」这种增量操作，等于每次加一个
//	域名都要把整份配置重新提交一遍，任何一处没带全就会被悄悄改掉。
//
// 所以域名页改成三个小接口（加 / 删 / 切换包含子域），每个都是「改一项、
// 存一次、立刻写进 AdGuard」。用户点「添加」就生效，不用再去点保存。
//
// 检测仍然在服务端做（见 cfcheck.go）：前端那个「检测」按钮只是为了满足
// 「先验证再添加」的交互，真正的判断不能放在浏览器里——否则改个 JS 就能
// 把不走的域名塞进来。

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/303528084/cf-ddns-sidecar/config"
	"github.com/303528084/cf-ddns-sidecar/dns"
)

// domainRow 是界面「域名列表」里的一行。
type domainRow struct {
	Domain string `json:"domain"`
	// Wildcard 表示这个域名连子域一起管（AdGuard 里多一条 `*.域名`）。
	Wildcard bool `json:"wildcard"`
	// AddedAt 是添加时间，只给界面显示。
	AddedAt string `json:"added_at,omitempty"`
	// Answer 是「现在指向哪个 IP」。取上次测速的最优 IP；还没测过就是空。
	// 界面上显示「未测速」比显示一个空单元格好懂。
	Answer string `json:"answer,omitempty"`
}

// domainRows 把配置摊成界面要的行。顺序与 cfg.Domains 一致。
func domainRows(cfg config.Config) []domainRow {
	out := make([]domainRow, 0, len(cfg.Domains))
	for _, d := range cfg.Domains {
		m := cfg.DomainMeta[d]
		out = append(out, domainRow{
			Domain:   d,
			Wildcard: m.Wildcard,
			AddedAt:  m.AddedAt,
			Answer:   cfg.LastIP,
		})
	}
	return out
}

// decodeDomainBody 解析 {"domain": "...", "wildcard": bool}，顺便规范化域名。
func decodeDomainBody(r *http.Request) (domain string, wildcard bool, err error) {
	var body struct {
		Domain   string `json:"domain"`
		Wildcard bool   `json:"wildcard"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return "", false, err
	}
	return config.NormalizeDomain(body.Domain), body.Wildcard, nil
}

// syncRewrites 把当前域名配置写进 AdGuard，返回一句给用户看的话。
//
// 不把错误往上抛成接口失败：域名已经存进配置了，写 AdGuard 失败（地址没填、
// 连不上、还没测速）不该让「添加」这个动作整个失败——用户会以为白点了。
// 该说的是「加进去了，但还没真正生效，原因是 X」。
//
// 这几句话都很短，因为它们会原样进 toast（一行放得下才不会被折成两行挡住
// 下面的说明），也会进日志。
//
// 注意 ReplaceRewrites 会**清空整张重写表再重建**（和测速时完全一样），
// 所以界面上那句「AdGuard 里不在这份清单中的记录会被清掉」仍然成立。
func (s *Server) syncRewrites(cfg config.Config) string {
	if strings.TrimSpace(cfg.AdGuard.URL) == "" {
		return "已保存；还没填 AdGuard 地址，填好后才会写进去"
	}
	if cfg.LastIP == "" {
		return "已保存；还没有测速结果，下次测速后写进 AdGuard"
	}
	provider, err := dns.New(cfg.AdGuard.Instance())
	if err != nil {
		return "已保存；连不上 AdGuard（" + friendlyErr(err) + "）"
	}
	names := cfg.RewriteDomains()
	want := make(map[string]map[string]bool, len(names))
	for _, d := range names {
		want[d] = map[string]bool{cfg.LastIP: true}
	}
	stats, err := provider.ReplaceRewrites(want)
	if err != nil {
		return "已保存；写 AdGuard 失败（" + friendlyErr(err) + "）"
	}
	if extra := len(names) - len(cfg.Domains); extra > 0 {
		return "已写入 AdGuard：" + itoa(stats.Written) + " 条（含 " + itoa(extra) + " 条子域通配符）"
	}
	return "已写入 AdGuard：" + itoa(stats.Written) + " 条"
}

func itoa(n int) string {
	// 只用来拼一两处日志，不值得为它引 strconv 的语义噪音。
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// handleDomains 是 /api/domains 的分发口：POST 加、DELETE 删。
//
// 两个动作走同一个路径而不是 /api/domains/add 与 /api/domains/delete：
// 它们操作的是同一个资源集合，用 HTTP 方法区分才是对的，也少两个路径。
func (s *Server) handleDomains(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.handleDomainAdd(w, r)
	case http.MethodDelete:
		s.handleDomainDelete(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDomainCheck 只检测，不改配置。对应界面上那个「检测」按钮。
func (s *Server) handleDomainCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	domain, _, err := decodeDomainBody(r)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "请求格式不对"})
		return
	}
	if domain == "" {
		writeJSON(w, 400, map[string]string{"error": "请先填一个域名"})
		return
	}
	check := checkDomainEdge(r.Context(), domain)
	writeJSON(w, 200, map[string]any{"ok": true, "result": check})
}

// handleDomainAdd 检测 + 存进配置 + 立刻写 AdGuard。
//
// 检测不通过时返回 400 并且**什么都不改**——这正是用户要的「不是的不让添加」。
// 检测不了（DNS 查不到）时照样添加，但把原因带回去让界面标黄，理由见
// cfcheck.go 顶部：网络抖一下就把用户填的域名扔掉，比放过去糟得多。
func (s *Server) handleDomainAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	domain, wildcard, err := decodeDomainBody(r)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "请求格式不对"})
		return
	}
	if domain == "" {
		writeJSON(w, 400, map[string]string{"error": "请先填一个域名"})
		return
	}

	check := checkDomainEdge(r.Context(), domain)
	if !check.OK && !check.Unknown {
		s.appendLog("域名未添加：" + domain + " —— " + check.Reason)
		writeJSON(w, 400, map[string]any{
			"ok":     false,
			"error":  "这个域名没走 Cloudflare",
			"result": check,
		})
		return
	}

	s.mu.Lock()
	cfg := s.cfg.Clone()
	exists := false
	for _, d := range cfg.Domains {
		if d == domain {
			exists = true
			break
		}
	}
	if !exists {
		cfg.Domains = append(cfg.Domains, domain)
	}
	if cfg.DomainMeta == nil {
		cfg.DomainMeta = map[string]config.DomainMeta{}
	}
	meta := cfg.DomainMeta[domain]
	meta.Wildcard = wildcard
	// 已经存在的域名不覆盖添加时间：那个时间说的是「什么时候加进来的」，
	// 不是「最后一次点添加」。用户重复点一次不该让它看起来像新加的。
	if meta.AddedAt == "" {
		meta.AddedAt = time.Now().Format("2006-01-02 15:04:05")
	}
	cfg.DomainMeta[domain] = meta
	s.cfg = &cfg
	s.mu.Unlock()

	if err := cfg.Save(); err != nil {
		writeJSON(w, 500, map[string]string{"error": "保存失败: " + friendlyErr(err)})
		return
	}

	note := s.syncRewrites(cfg)
	suffix := ""
	if wildcard {
		suffix = "（含子域）"
	}
	s.appendLog("已添加域名 " + domain + suffix + "：" + note)
	if check.Unknown {
		s.appendLog("域名已添加但没验成：" + domain + " —— " + check.Reason)
	}

	writeJSON(w, 200, map[string]any{
		"ok":      true,
		"result":  check,
		"note":    note,
		"domains": domainRows(cfg),
	})
}

// handleDomainDelete 从列表里删掉一个域名，并立刻写 AdGuard（把它清掉）。
func (s *Server) handleDomainDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	domain := config.NormalizeDomain(r.URL.Query().Get("domain"))
	if domain == "" {
		writeJSON(w, 400, map[string]string{"error": "没说是哪个域名"})
		return
	}

	s.mu.Lock()
	cfg := s.cfg.Clone()
	kept := make([]string, 0, len(cfg.Domains))
	found := false
	for _, d := range cfg.Domains {
		if d == domain {
			found = true
			continue
		}
		kept = append(kept, d)
	}
	if !found {
		s.mu.Unlock()
		writeJSON(w, 404, map[string]string{"error": "列表里没有这个域名"})
		return
	}
	cfg.Domains = kept
	delete(cfg.DomainMeta, domain)
	s.cfg = &cfg
	s.mu.Unlock()

	if err := cfg.Save(); err != nil {
		writeJSON(w, 500, map[string]string{"error": "保存失败: " + friendlyErr(err)})
		return
	}
	note := s.syncRewrites(cfg)
	s.appendLog("已删除域名 " + domain + "：" + note)

	writeJSON(w, 200, map[string]any{
		"ok":      true,
		"note":    note,
		"domains": domainRows(cfg),
	})
}

// handleDomainWildcard 切换某个域名的「包含子域」。
//
// 只改这一项、立刻生效：勾上就多写一条 `*.域名`，取消就把它删掉。
func (s *Server) handleDomainWildcard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	domain, wildcard, err := decodeDomainBody(r)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "请求格式不对"})
		return
	}

	s.mu.Lock()
	cfg := s.cfg.Clone()
	exists := false
	for _, d := range cfg.Domains {
		if d == domain {
			exists = true
			break
		}
	}
	if !exists {
		s.mu.Unlock()
		writeJSON(w, 404, map[string]string{"error": "列表里没有这个域名"})
		return
	}
	if cfg.DomainMeta == nil {
		cfg.DomainMeta = map[string]config.DomainMeta{}
	}
	meta := cfg.DomainMeta[domain]
	meta.Wildcard = wildcard
	cfg.DomainMeta[domain] = meta
	s.cfg = &cfg
	s.mu.Unlock()

	if err := cfg.Save(); err != nil {
		writeJSON(w, 500, map[string]string{"error": "保存失败: " + friendlyErr(err)})
		return
	}
	note := s.syncRewrites(cfg)
	if wildcard {
		s.appendLog("域名 " + domain + " 改为包含子域（同时写 *." + domain + "）：" + note)
	} else {
		s.appendLog("域名 " + domain + " 改为不包含子域：" + note)
	}

	writeJSON(w, 200, map[string]any{
		"ok":      true,
		"note":    note,
		"domains": domainRows(cfg),
	})
}
