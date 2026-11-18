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
	"log"
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
// 关于 AdGuard 上「谁的地盘」：写重写从 2026-11-18 起只动本工具认领的域名
// （见 dns.Provider.ReplaceRewrites）。这里的 want 由 rewritePlan 组装，除了
// 当前域名列表，还包含账本里「以前管过、现在不管了」的域名——用户刚删掉的那
// 个域名就在里面，所以界面上那句「AdGuard 里对应的重写也会一起清掉」仍然成立。
func (s *Server) syncRewrites(cfg config.Config) string {
	if strings.TrimSpace(cfg.AdGuard.URL) == "" {
		return "已保存；还没填 AdGuard 地址，填好后才会写进去"
	}
	// 没有测速结果、也没有 hosts 条目时才真的没东西可写。
	// 只看 LastIP 的话，一个「只配了 hosts 源、还没跑过测速」的用户点一下
	// 添加域名，就会得到「还没有测速结果」——而 hosts 那几十条其实是可以写的。
	if cfg.LastIP == "" && len(cfg.HostsEntries) == 0 {
		return "已保存；还没有测速结果，下次测速后写进 AdGuard"
	}
	provider, err := dns.New(cfg.AdGuard.Instance())
	if err != nil {
		return "已保存；连不上 AdGuard（" + friendlyErr(err) + "）"
	}
	names := cfg.RewriteDomains()
	// 这里用的是「上一次测速结果」而不是「这一轮刚测的」——因为这是个
	// 改域名清单的动作，本来就没有新一轮结果。v4 用 LastIP、v6 用
	// LastIPv6IPs，两边对称。
	//
	// **必须带上 v6**：want 里没有的答案会被当成多余删掉，只给 v4 的话，
	// 用户只是点了一下「加域名」，家里所有 v6 的重写就被悄悄删掉了，而界面
	// 上只会说「已写入 AdGuard：N 条」。
	want := make(map[string]map[string]bool, len(names))
	if cfg.LastIP != "" {
		want = rewritePlan(cfg, names, rewriteAnswers(cfg.LastIP, cfg.LastIPv6IPs))
	}
	// hosts 那一块也要带上。少了这一步，用户每加一个加速域名就会把 hosts 源
	// 写的那几十条**整份删掉**（want 里没有的域名，在认领语义下等于"不该有
	// 记录"），而界面上只会显示一句"已写入 AdGuard：1 条"。
	//
	// 开关关掉、或者来源被清空时传 nil 进去：这一步就变成**收回**
	// ——mergeHostsWant 会把账本里那些「不再归它管」的域名给空集合，等于从
	// AdGuard 上删掉它们。用户关掉开关时立即走这一段（见 web/switch.go），
	// 不用等到下一轮测速，否则「点完开关什么也没发生」看起来就是没生效。
	hostsWant := hostsWantFor(cfg)
	// hostsWant 为 nil ＝ 这一块现在不该有任何记录（开关关掉 / 来源为空），
	// 于是 mergeHostsWant 会把账本里的域名给空集合，也就是从 AdGuard 收回。
	hostsOff := hostsWant == nil
	hostsStat := mergeHostsWant(want, cfg, names, hostsWant)
	stats, err := provider.ReplaceRewrites(want)
	if err != nil {
		return "已保存；写 AdGuard 失败（" + friendlyErr(err) + "）"
	}
	// 收回成功之后账本要跟着清空，否则下一轮还会以为这些域名仍归它管，
	// 反复去删一批已经不在的记录。
	if hostsOff && len(cfg.HostsEntries) > 0 {
		s.mu.Lock()
		s.cfg.HostsEntries = nil
		s.cfg.HostsSyncedAt = ""
		toSave := s.cfg.Clone()
		s.mu.Unlock()
		if err := toSave.Save(); err != nil {
			log.Printf("保存配置失败: %v", err)
		}
	}
	// 记下这一轮认领的域名。删域名这条路上它特别关键：账本是「下次同步该清
	// 哪些旧记录」的唯一依据。
	s.rememberRewritten(names)
	// 这句话会原样进 toast，所以要短。没有 hosts 源时保持原来的说法一个字都
	// 不加——多一句「含 0 条 hosts 源」只会让人以为哪里没配好。
	msg := "已写入 AdGuard：" + itoa(stats.Written) + " 条"
	var parts []string
	if extra := len(names) - len(cfg.Domains); extra > 0 {
		parts = append(parts, itoa(extra)+" 条子域通配符")
	}
	if hostsStat.added > 0 {
		parts = append(parts, itoa(hostsStat.added)+" 条 hosts 源")
	}
	// 关掉开关这一路，重点不是「写进去了几条」，而是「收回来了几条」。
	if hostsOff && hostsStat.cleared > 0 {
		return "已关闭 hosts 源，从 AdGuard 收回 " + itoa(hostsStat.cleared) + " 条"
	}
	if len(parts) > 0 {
		msg += "（含 " + strings.Join(parts, "、") + "）"
	}
	return msg
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
