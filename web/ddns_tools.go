package web

// 后台里「配好了吗」这类小工具：测试域名解析的密钥、手动推送一次解析、
// 以及把 AdGuard 里现有的重写表读出来看看。
//
// 为什么值得单独做：用户填密钥的时候完全不知道自己填对没有——以前只能等
// 下一个测速周期（默认 60 分钟）看日志里有没有报错，或者干脆等到域名解析
// 失效才发现。2026-11-17 那天他就是卡在「密钥到底对不对」上。
// 现在按一下就能当场得到答案，而且「测试密钥」只读，不会动线上解析。

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/303528084/cf-ddns-sidecar/config"
	"github.com/303528084/cf-ddns-sidecar/ddns"
	"github.com/303528084/cf-ddns-sidecar/dns"
)

// currentDDNS 取出当前 DDNS 配置并造好服务商客户端。
// 不可用时 provider 为 nil，msg 是一句能直接显示给用户看的话。
func (s *Server) currentDDNS() (ddns.Provider, config.Config, string) {
	s.mu.Lock()
	cfg := s.cfg.Clone()
	s.mu.Unlock()

	if !cfg.DDNS.Enabled {
		return nil, cfg, "域名解析还没启用：先在上面的「启用」打勾并保存一次"
	}
	if cfg.DDNS.Provider == "" || cfg.DDNS.Domain == "" {
		return nil, cfg, "还没选服务商或没填优选域名"
	}
	if missing := config.MissingCredentials(cfg.DDNS.Provider); len(missing) > 0 {
		return nil, cfg, "缺少密钥：" + strings.Join(missing, "、")
	}
	p, err := ddns.New(cfg.DDNS.Provider, cfg.DDNS.Domain, config.DDNCredentials())
	if err != nil {
		return nil, cfg, err.Error()
	}
	return p, cfg, ""
}

// recordOptions 把配置里的 TTL / 云朵翻译成 ddns 包要求的写法。
// 放一处是为了让「定时推送」和「立即更新一次」写出去的记录一定一致——
// 两条路各写一份的话，早晚会有一条忘记带 TTL。
//
// rtype 必须由调用方逐个族给（A / AAAA），不能从配置里取：配置里存的是
// 同步模式，可能是「两族都写」，而一条记录一次只能属于一族。
func recordOptions(d config.DDNSConfig, rtype string) ddns.RecordOptions {
	return ddns.RecordOptions{Type: rtype, TTL: d.TTL, Proxied: d.Proxied}
}

// emptySourceReason 说明「这一族为什么一个地址都没有」。
// 分开说是因为两族的补救办法完全不同：A 没有是测速整体没跑成，
// AAAA 没有是这一轮 v6 没测出节点（先去看 v6 探测）。
func emptySourceReason(rtype string) string {
	if rtype == ddns.TypeAAAA {
		return "这一轮没有 v6 结果"
	}
	return "这一轮没有 v4 结果"
}

// familyLabel 把记录类型说成人话，用在直接给用户看的句子里。
func familyLabel(rtype string) string {
	if rtype == ddns.TypeAAAA {
		return "IPv6"
	}
	return "IPv4"
}

// pickIPs 按排名取前 n 条，不足 n 条时有多少给多少。
//
// 顺序有意义：res.IPs 是从优到劣排好的，截断只能从头截。
func pickIPs(ips []string, n int) []string {
	if n <= 0 {
		n = 1
	}
	if len(ips) > n {
		ips = ips[:n]
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if strings.TrimSpace(ip) != "" {
			out = append(out, ip)
		}
	}
	return out
}

// handleDDNSCheck 只读校验密钥：确认能用、能查到这条域名，并报出当前指向。
func (s *Server) handleDDNSCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p, cfg, msg := s.currentDDNS()
	if p == nil {
		writeJSON(w, 400, map[string]string{"error": msg})
		return
	}

	// 按同步模式逐族校验。单族时就是一次，A+AAAA 时是两次。
	// 一次校验两族的原因：用户选「两个都写」之后，只报 A 那张表会让他
	// 以为 AAAA 也一起验过了——密钥或权限问题往往只影响其中一族
	// （比如 Cloudflare 的令牌权限只给了某个 Zone 的部分类型）。
	mode := cfg.DDNS.EffectiveRecordMode()
	families := ddns.FamiliesOf(mode)
	views := make([]ddnsFamilyView, 0, len(families))
	for _, family := range families {
		state, err := p.Verify(cfg.DDNS.Domain, family)
		if err != nil {
			s.appendLog(fmt.Sprintf("测试域名解析密钥失败（%s）: %s", family, err.Error()))
			writeJSON(w, 502, map[string]string{"error": ddnsHint(err)})
			return
		}

		s.mu.Lock()
		bestIP, rank := lastRankForType(s.cfg, family)
		allIPs := pickIPs(rank, cfg.DDNS.EffectiveIPCount())
		s.mu.Unlock()
		if len(allIPs) == 0 && bestIP != "" {
			// 老配置里只有 last_ip（升级前存的），没有列表。
			allIPs = []string{bestIP}
		}

		if state.Found {
			s.appendLog(fmt.Sprintf("域名解析密钥可用：%s 现在指向 %s（共 %d 条 %s 记录）",
				cfg.DDNS.Domain, strings.Join(state.CurrentIPs, "、"), len(state.CurrentIPs), family))
		} else {
			s.appendLog(fmt.Sprintf("域名解析密钥可用：%s 还没有 %s 记录，下次成功后会创建",
				cfg.DDNS.Domain, family))
		}
		views = append(views, ddnsFamilyView{
			Type:       family,
			Found:      state.Found,
			CurrentIP:  state.CurrentIP,
			CurrentIPs: state.CurrentIPs,
			BestIP:     bestIP,
			WillWrite:  allIPs,
		})
	}

	writeJSON(w, 200, map[string]any{
		"ok":          true,
		"provider":    cfg.DDNS.Provider,
		"domain":      cfg.DDNS.Domain,
		"record_type": mode,
		"families":    views,
	})
}

// ddnsFamilyView 是「某一族现在什么样、点立即更新会写成什么样」。
//
// 为什么要分族报：A 和 AAAA 在服务商那边是两张互不相干的表。只报一个总数
// 或者只报 A，用户看不出这次动的是哪张——「两个都写」模式下尤其容易误会。
type ddnsFamilyView struct {
	Type       string   `json:"type"`
	Found      bool     `json:"found"`
	CurrentIP  string   `json:"current_ip"`
	CurrentIPs []string `json:"current_ips"`
	BestIP     string   `json:"best_ip"`
	WillWrite  []string `json:"will_write"`
}

// ddnsFamilyResult 是「这一族这次写成功没有」。
type ddnsFamilyResult struct {
	Type    string   `json:"type"`
	IPs     []string `json:"ips"`
	Skipped string   `json:"skipped,omitempty"`
}

// lastRankForType 返回「记录类型对应的上一次排名」和最优那一条。
//
// A 用 v4 那组（LastIP / LastIPs），AAAA 用 v6 那组（LastIPv6 / LastIPv6IPs）。
// 两族分开存的原因：一次测速会同时产出 v4 和 v6 两套排名，混在一起就分不清
// 哪条地址该写进哪一种记录——把 v4 地址塞进 AAAA 是纯粹的坏记录。
// 返回值都是拷贝，调用方可以放心改。
func lastRankForType(c *config.Config, rtype string) (best string, rank []string) {
	if c == nil {
		return "", nil
	}
	if rtype == ddns.TypeAAAA {
		return c.LastIPv6, append([]string(nil), c.LastIPv6IPs...)
	}
	return c.LastIP, append([]string(nil), c.LastIPs...)
}

// handleDDNSUpdate 立刻把当前最优 IP 推一次，不用等下一个测速周期。
func (s *Server) handleDDNSUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p, cfg, msg := s.currentDDNS()
	if p == nil {
		writeJSON(w, 400, map[string]string{"error": msg})
		return
	}

	// 先把每一族该写什么算出来，再决定动作。算 IP 只读配置，放在锁里一次拿完。
	mode := cfg.DDNS.EffectiveRecordMode()
	families := ddns.FamiliesOf(mode)

	s.mu.Lock()
	busy := s.running
	planned := make([]ddnsFamilyResult, 0, len(families))
	for _, family := range families {
		lastIP, stored := lastRankForType(s.cfg, family)
		// 存了完整排名，所以用户把「同步几个」从 1 改成 5 之后不用重新测速——
		// 直接从这一份里截前 5 条就行。
		ips := pickIPs(stored, cfg.DDNS.EffectiveIPCount())
		if len(ips) == 0 && lastIP != "" {
			ips = []string{lastIP} // 升级前存的配置只有单条
		}
		planned = append(planned, ddnsFamilyResult{Type: family, IPs: ips})
	}
	s.mu.Unlock()

	// 测速进行中不推：那一轮自己会推，两边同时写同一条记录只会打架。
	if busy {
		writeJSON(w, 409, map[string]string{"error": "测速正在进行中，它结束后会自己推送；请稍后再试"})
		return
	}

	wrote := 0
	for i := range planned {
		pl := &planned[i]
		if len(pl.IPs) == 0 {
			// 这一族没结果就跳过，**不要**因此放弃另一族：v6 没测出节点
			// 不该连累 A 记录也不更新。
			pl.Skipped = "还没有测出可用的 " + familyLabel(pl.Type) + " 节点"
			continue
		}
		if err := p.EnsureRecords(cfg.DDNS.Domain, pl.IPs, recordOptions(cfg.DDNS, pl.Type)); err != nil {
			s.appendLog(fmt.Sprintf("手动推送域名解析失败（%s）: %s", pl.Type, err.Error()))
			writeJSON(w, 502, map[string]string{"error": ddnsHint(err)})
			return
		}
		wrote++
		s.appendLog(fmt.Sprintf("域名解析已手动更新：%s → %s（共 %d 条 %s 记录）",
			cfg.DDNS.Domain, strings.Join(pl.IPs, "、"), len(pl.IPs), pl.Type))
	}

	if wrote == 0 {
		// 一族都没写成，按模式给一句最有用的指引，别只说「失败」——
		// 三种模式的补救办法不一样。
		msg := "还没有测出最优 IP。先点「立即测速」；只想验证密钥对不对，用「测试密钥」就够了"
		switch mode {
		case ddns.ModeBoth:
			msg = "还没有测出可用的 IP（IPv4 和 IPv6 都没有）。先点「立即测速」"
		case ddns.TypeAAAA:
			msg = "还没有测出可用的 IPv6 节点。先在探测卡片里跑一次 v6 探测，或者等下一轮自动测速"
		}
		writeJSON(w, 400, map[string]string{"error": msg})
		return
	}

	writeJSON(w, 200, map[string]any{
		"ok":          true,
		"domain":      cfg.DDNS.Domain,
		"record_type": mode,
		"results":     planned,
	})
}

// handleAdguardRewrites 把 AdGuard 里现在的重写表读出来，并标出「下次测速会被清掉」
// 的那些——ReplaceRewrites 会清空整张表再重建，用户有权先看一眼。
func (s *Server) handleAdguardRewrites(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	cfg := s.cfg.Clone()
	s.mu.Unlock()

	if strings.TrimSpace(cfg.AdGuard.URL) == "" {
		writeJSON(w, 400, map[string]string{"error": "还没填 AdGuard 地址"})
		return
	}
	provider, err := dns.New(cfg.AdGuard.Instance())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": friendlyErr(err)})
		return
	}

	entries, err := provider.ListRewrites()
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": friendlyErr(err)})
		return
	}

	// 期望集合：每个要加速的域名 → 当前最优 IP。LastIP 为空时为空表，
	// 界面上就会把所有现存的都标成「下次测速会被清掉」，这恰好是实话。
	//
	// 用 RewriteDomains() 而不是 Domains：勾了包含子域的那些会多一条
	// `*.域名`，漏掉的话界面会把我们自己写的通配符标成「会被清掉」。
	names := cfg.RewriteDomains()
	expected := make(map[string]string, len(names))
	if cfg.LastIP != "" {
		for _, d := range names {
			expected[d] = cfg.LastIP
		}
	}
	writeJSON(w, 200, map[string]any{
		"ok":       true,
		"entries":  entries,
		"expected": expected,
		"last_ip":  cfg.LastIP,
	})
}

// ddnsHint 在服务商返回的原始错误后面补一句「大概是什么问题」。
//
// 原始信息里有 HTTP 状态码和云厂商的错误码，对排查有价值，所以不替换掉，
// 只在后面加一句人话。
func ddnsHint(err error) string {
	msg := err.Error()
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(msg, "401"), strings.Contains(msg, "403"),
		strings.Contains(low, "unauthorized"), strings.Contains(low, "invalidaccesskey"),
		strings.Contains(low, "authfailure"), strings.Contains(low, "invalid api key"),
		strings.Contains(low, "signature"):
		return msg + "（看着像密钥不对或没有改解析的权限）"
	case strings.Contains(low, "timeout"), strings.Contains(low, "no such host"),
		strings.Contains(low, "connection refused"), strings.Contains(low, "eof"):
		return msg + "（连不上服务商，检查 NAS 的外网出口）"
	}
	return msg
}
