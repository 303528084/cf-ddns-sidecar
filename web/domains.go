package web

// 「要加速的域名」的增删改。
//
// 不走 /api/config：那是全量覆盖，加一个域名要整份重交，漏一项就被悄悄改掉。
// 这里每个动作一个接口，改一项、存一次、立刻写进 AdGuard。
// 域名是否真走 Cloudflare 只能在服务端判（cfcheck.go），前端那个「检测」只为交互。

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
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
// 不返回 error：域名已经存进配置了，写 AdGuard 失败（地址没填、连不上、还没测速）
// 不该让「添加」整个失败，该说的是「加进去了，但还没真正生效，原因是 X」。
// 返回的句子都很短，因为它会原样进 toast 和日志。
func (s *Server) syncRewrites(cfg config.Config) string {
	msg, _ := s.syncRewritesHosts(cfg, hostsWantFor(cfg), hostsOffFor(cfg))
	return msg
}

// rewriteSyncNote 把一次同步的结果拼成一句短话。
//
// 收回要单独说：关掉一族之后新增恒为 0，只报「写入 0 条」等于什么都没交代，
// 而用户这时候正等着看那一族被收走。
func rewriteSyncNote(stats dns.SyncStats) string {
	switch {
	case stats.Written > 0 && stats.Removed > 0:
		return fmt.Sprintf("已写入 AdGuard：%d 条，收回 %d 条", stats.Written, stats.Removed)
	case stats.Written == 0 && stats.Removed > 0:
		return fmt.Sprintf("已从 AdGuard 收回 %d 条", stats.Removed)
	}
	return fmt.Sprintf("已写入 AdGuard：%d 条", stats.Written)
}

// syncRewritesHosts 多一个「这一块现在该写哪些条目」，第二个返回值是「重写表
// 真写成功了吗」：写失败就不能动账本，否则下次会以为记录已经在 AdGuard 上了。
//
// hostsWant / hostsOff 把三种情形分开：正常同步（want=账本, off=false）、
// 关掉或清空来源（want=nil, off=true，效果是收回）、刚到开关（want=刚拉的清单）。
func (s *Server) syncRewritesHosts(cfg config.Config, hostsWant map[string]string, hostsOff bool) (string, bool) {
	if strings.TrimSpace(cfg.AdGuard.URL) == "" {
		return "已保存；还没填 AdGuard 地址，填好后才会写进去", false
	}
	// 答案按开关状态算，不是按 LastIP 拼：某一族关掉之后，它的地址不能再出现在
	// 期望集合里，否则每次重同步都会把刚关掉的那一族又写回 AdGuard。
	answers := rewriteAnswersFor(cfg)
	// 两族都关了是「这个域名不该再有本工具写的记录」，和「有族开着但还没测出地址」
	// 是两件事：后者必须一条都不动，否则会把上一轮好好的结果抹掉。
	allOff := cfg.EffectiveSourceMode() == config.SourceOff && cfg.EffectiveIPv6SourceMode() == config.SourceOff
	// 没有测速结果、也没有 hosts 条目时才真的没东西可写。
	// 只看 LastIP 的话，一个「只配了 hosts 源、还没跑过测速」的用户点一下
	// 添加域名，就会得到「还没有测速结果」，而 hosts 那几十条其实是可以写的。
	if len(answers) == 0 && !allOff && len(hostsWant) == 0 && len(cfg.HostsEntries) == 0 {
		return "已保存；还没有测速结果，下次测速后写进 AdGuard", false
	}
	provider, err := dns.New(cfg.AdGuard.Instance())
	if err != nil {
		return "已保存；连不上 AdGuard（" + friendlyErr(err) + "）", false
	}
	names := cfg.RewriteDomains()
	// want 里没有的答案会被当成多余删掉，所以 v6 和 hosts 两边都必须带上：
	// 少一边就等于「点一下加域名，另一边被悄悄清空」。
	want := make(map[string]map[string]bool, len(names))
	if len(answers) > 0 || allOff {
		// answers 为空且 allOff 时，rewritePlan 给每个域名一个空集合，等于全收回。
		want = rewritePlan(cfg, names, answers)
	}
	// off 时传的是 nil：mergeHostsWant 会把账本里那些域名置成空集合，等于收回。
	hostsStat := mergeHostsWant(want, cfg, names, hostsWant)
	stats, err := provider.ReplaceRewrites(want)
	if err != nil {
		return "已保存；写 AdGuard 失败（" + friendlyErr(err) + "）", false
	}
	// 收回成功了账本就要清空，否则下一轮还会去删一批已经不存在的记录。
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
	// 记下这一轮认领的域名。删域名这条路全靠它知道下次该清哪些旧记录。
	s.rememberRewritten(names)
	// 这句话原样进 toast，要短。没有 hosts 源时一个字都不加，否则会让人以为没配好。
	// 收回也要说出来：关掉一族之后新增是 0，只说「写入 0 条」等于什么都没交代。
	msg := rewriteSyncNote(stats)
	var parts []string
	if extra := len(names) - len(cfg.Domains); extra > 0 {
		parts = append(parts, strconv.Itoa(extra)+" 条子域通配符")
	}
	if hostsStat.added > 0 {
		parts = append(parts, strconv.Itoa(hostsStat.added)+" 条 hosts 源")
	}
	// 关掉开关这一路，重点不是写进去几条，是收回来几条。
	if hostsOff && hostsStat.cleared > 0 {
		return "已关闭 hosts 源，从 AdGuard 收回 " + strconv.Itoa(hostsStat.cleared) + " 条", true
	}
	if len(parts) > 0 {
		msg += "（含 " + strings.Join(parts, "、") + "）"
	}
	return msg, true
}

// handleDomains 是 /api/domains 的分发口：POST 加、DELETE 删。
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
// 检测不通过时返回 400 并且**什么都不改**，这正是用户要的「不是的不让添加」。
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
	// 清空整个列表。域名多了以后一个一个点太慢，而且每删一个都要同步一次
	// AdGuard——二十个域名就是二十次网络往返，中途失败还会留下删了一半的状态。
	if r.URL.Query().Get("all") == "1" {
		s.clearAllDomains(w)
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

// clearAllDomains 是「全部删除」：一次清空列表，只同步一次 AdGuard。
//
// 作用和逐个删除一样：被清掉的域名下一轮同步时整条清掉（rewritePlan 给已失管
// 的域名一个空答案集），不是「不管了、留在 AdGuard 里」。
//
// 单独一个函数而不是在 handleDomainDelete 里改一行：那里是「按域名删」，这里有
// 「一个都不剩」，两者对 DomainMeta 的处理不一样（整表置空 vs 删一个键）。
func (s *Server) clearAllDomains(w http.ResponseWriter) {
	s.mu.Lock()
	cfg := s.cfg.Clone()
	n := len(cfg.Domains)
	if n == 0 {
		s.mu.Unlock()
		writeJSON(w, 200, map[string]any{
			"ok": true, "removed": 0,
			"note": "列表本来就是空的", "domains": domainRows(cfg),
		})
		return
	}
	// 空切片而不是 nil：一个个删到最后一个时存的也是 []，两种形状的同一个状态
	// 迟早会有人拿 == nil 去判断「从没配过」。
	cfg.Domains = []string{}
	cfg.PruneDomainMeta()
	s.cfg = &cfg
	s.mu.Unlock()

	if err := cfg.Save(); err != nil {
		writeJSON(w, 500, map[string]string{"error": "保存失败: " + friendlyErr(err)})
		return
	}
	note := s.syncRewrites(cfg)
	s.appendLog("已清空域名列表（" + strconv.Itoa(n) + " 个）：" + note)

	writeJSON(w, 200, map[string]any{
		"ok": true, "removed": n,
		"note": note, "domains": domainRows(cfg),
	})
}

// handleDomainWildcard 切换某个域名的「包含子域」。
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
