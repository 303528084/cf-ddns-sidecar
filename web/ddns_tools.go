package web

// 后台里「配好了吗」这类小工具：测试域名解析的密钥、手动推送一次解析、把 AdGuard 里现有
// 的重写表读出来看看。
//
// 值得单独做：用户填密钥时完全不知道自己填对没有，以前只能等下一个测速周期（默认 60
// 分钟）看日志有没有报错，或者等到解析失效才发现。现在按一下当场得到答案，而且「测试
// 密钥」只读，不动线上解析。

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/303528084/cf-ddns-sidecar/config"
	"github.com/303528084/cf-ddns-sidecar/ddns"
	"github.com/303528084/cf-ddns-sidecar/dns"
)

// pruneOtherFamily 在单族模式下把另一族记录清掉。
//
// 只在 written 不为空时被调用，也就是这一轮那一族确实写成功了。写失败却先把另一族
// 删掉，一旦服务商那头还有别的问题，域名会两头都空，访问直接断。
//
// 清失败只记日志不算整轮失败：这一族已经写进去了，另一族没清干净下一轮还会再来一次，
// 没必要因为这个让整轮测速显示成失败。返回 true 表示这一轮把另一族对齐了。
func (s *Server) pruneOtherFamily(p ddns.Provider, domain, written string) bool {
	if written == "" {
		return false
	}
	other := ddns.TypeAAAA
	if written == ddns.TypeAAAA {
		other = ddns.TypeA
	}
	n, err := p.ClearRecords(domain, other)
	if err != nil {
		s.appendLog(fmt.Sprintf("域名解析：按「只写 %s」清理 %s 记录失败: %s（下一轮会再试）",
			written, other, err.Error()))
		return false
	}
	if n > 0 {
		s.appendLog(fmt.Sprintf("域名解析：按「只写 %s」清掉了 %d 条旧的 %s 记录", written, n, other))
	}
	return true
}

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
// 放一处是为了让「定时推送」和「立即更新一次」写出去的记录一定一致，
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

// pickOutcome 是「这次挑出哪几条」以及「为什么比要的少」。
//
// 少了多少要分开算：低于门槛是用户自己设的标准把节点刷掉了，没有速度数据是
// 测速那一步没量出来。两者的补救办法完全不同，日志里混成一句「2 条被排除」
// 会让人去改门槛，而实际上该去看的是带宽测速有没有跑成。
type pickOutcome struct {
	IPs    []string
	Low    int // 测出速度，但低于门槛
	NoData int // 没有速度数据，当成不达标
}

// dropped 是「因为门槛而少写的条数」。
func (o pickOutcome) dropped() int { return o.Low + o.NoData }

// pickForWrite 挑出这次真正要写进解析的地址：先按排名截前 n 条，再按门槛筛。
//
// 门槛只在截出来的这 n 条里生效，**不从后面补位**。补位看起来更体贴，但它的
// 前提是排名列表比 n 长，而「保留候选 IP 数」默认就是 5、同步条数也默认 1~5，
// 想要 5 条时后面通常一条候选都不剩，补也补不出来。为一个大多数情况下不存在
// 的空位准备一套逻辑，只会让「我设了 5 条，为什么写了 6 条」变成新的疑问。
func pickForWrite(ips []string, nodes []config.NodeStat, minSpeed float64, n int) pickOutcome {
	head := pickIPs(ips, n)
	if minSpeed <= 0 {
		return pickOutcome{IPs: head}
	}

	// 速度按 IP 查，不按下标取。nodes 和 ips 本该一一对应，但老配置、导入的
	// 旧备份、手改过 config.json 都会让其中一份少几条，按下标取速度就会张冠李戴，
	// 把慢的说成快的——这是这里最坏的一种错，宁可当成「没数据」剔掉。
	speeds := make(map[string]float64, len(nodes))
	for _, nd := range nodes {
		if nd.Speed > 0 {
			speeds[nd.IP] = nd.Speed
		}
	}

	out := pickOutcome{IPs: make([]string, 0, len(head))}
	for _, ip := range head {
		speed, ok := speeds[ip]
		switch {
		case !ok:
			out.NoData++
		case speed < minSpeed:
			out.Low++
		default:
			out.IPs = append(out.IPs, ip)
		}
	}
	return out
}

// skipReason 把「少写了几条」说成人话，接在日志后面。
func (o pickOutcome) skipReason(minSpeed float64) string {
	var parts []string
	if o.Low > 0 {
		parts = append(parts, fmt.Sprintf("%d 条低于 %s Mbps", o.Low, trimSpeed(minSpeed)))
	}
	if o.NoData > 0 {
		parts = append(parts, fmt.Sprintf("%d 条没测出速度", o.NoData))
	}
	return strings.Join(parts, "、")
}

// trimSpeed 去掉小数末尾多余的 0：5 显示成「5」而不是「5.00」。
func trimSpeed(v float64) string {
	s := strconv.FormatFloat(v, 'f', 1, 64)
	return strings.TrimSuffix(s, ".0")
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
	// 以为 AAAA 也一起验过了，密钥或权限问题往往只影响其中一族
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
		bestIP, rank, nodeStats := lastRankForType(s.cfg, family)
		pick := pickForWrite(rank, nodeStats, cfg.DDNS.MinSpeedMbps, cfg.DDNS.EffectiveIPCount())
		s.mu.Unlock()
		allIPs := pick.IPs
		// 老配置里只有 last_ip（升级前存的），没有列表，退回那一条。
		// 但门槛把候选全刷掉的时候不能这么退：那等于绕过用户刚设的标准，
		// 把他最不想要的那条地址写上去，而且界面上还会显示「将写入」。
		if len(allIPs) == 0 && bestIP != "" && pick.dropped() == 0 {
			allIPs = []string{bestIP}
		}
		note := ""
		if pick.dropped() > 0 {
			note = pick.skipReason(cfg.DDNS.MinSpeedMbps)
		}

		if state.Found {
			s.appendLog(fmt.Sprintf("域名解析密钥可用：%s 现在指向 %s（共 %d 条 %s 记录）",
				cfg.DDNS.Domain, strings.Join(state.CurrentIPs, "、"), len(state.CurrentIPs), family))
		} else {
			s.appendLog(fmt.Sprintf("域名解析密钥可用：%s 还没有 %s 记录，下次成功后会创建",
				cfg.DDNS.Domain, family))
		}
		views = append(views, ddnsFamilyView{
			Type:         family,
			Found:        state.Found,
			CurrentIP:    state.CurrentIP,
			CurrentIPs:   state.CurrentIPs,
			BestIP:       bestIP,
			WillWrite:    allIPs,
			MinSpeedNote: note,
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
// 或者只报 A，用户看不出这次动的是哪张，「两个都写」模式下尤其容易误会。
type ddnsFamilyView struct {
	Type       string   `json:"type"`
	Found      bool     `json:"found"`
	CurrentIP  string   `json:"current_ip"`
	CurrentIPs []string `json:"current_ips"`
	BestIP     string   `json:"best_ip"`
	WillWrite  []string `json:"will_write"`
	// MinSpeedNote 说明「因为没到门槛少写了几条」。写成功的时候也可能有值，
	// 前端要照它显示，否则用户看到「将写入 4 条」而自己设的是 5 条，
	// 会以为程序又少写了一条。
	MinSpeedNote string `json:"min_speed_note,omitempty"`
}

// ddnsFamilyResult 是「这一族这次写成功没有」。
type ddnsFamilyResult struct {
	Type    string   `json:"type"`
	IPs     []string `json:"ips"`
	Skipped string   `json:"skipped,omitempty"`
	// MinSpeedNote 说明「因为没到门槛少写了几条」。这一族写成了也可能有值：
	// 用户设 5 条、实际写 4 条，得当场说清少的那条去哪儿了。
	MinSpeedNote string `json:"min_speed_note,omitempty"`
}

// lastRankForType 返回「记录类型对应的上一次排名」、最优那一条，以及跟着排名的
// 节点明细（速度在里面，门槛要靠它判断）。
//
// A 用 v4 那组（LastIP / LastIPs / LastNodes），AAAA 用 v6 那组。两族分开存的
// 原因：一次测速会同时产出 v4 和 v6 两套排名，混在一起就分不清哪条地址该写进
// 哪一种记录，把 v4 地址塞进 AAAA 是纯粹的坏记录。
// 返回值都是拷贝，调用方可以放心改。
func lastRankForType(c *config.Config, rtype string) (best string, rank []string, nodes []config.NodeStat) {
	if c == nil {
		return "", nil, nil
	}
	if rtype == ddns.TypeAAAA {
		return c.LastIPv6, append([]string(nil), c.LastIPv6IPs...), append([]config.NodeStat(nil), c.LastIPv6Nodes...)
	}
	return c.LastIP, append([]string(nil), c.LastIPs...), append([]config.NodeStat(nil), c.LastNodes...)
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
		lastIP, stored, nodeStats := lastRankForType(s.cfg, family)
		// 存了完整排名，所以用户把「同步几个」从 1 改成 5 之后不用重新测速，
		// 直接从这一份里截前 5 条就行。
		pick := pickForWrite(stored, nodeStats, cfg.DDNS.MinSpeedMbps, cfg.DDNS.EffectiveIPCount())
		ips := pick.IPs
		// 只有「排名列表本身就没有」才退回单条 lastIP（升级前存的配置只有一条）。
		// 门槛把候选全刷掉时不退：那等于绕过用户设的标准把最慢的一条写上去。
		if len(ips) == 0 && lastIP != "" && pick.dropped() == 0 {
			ips = []string{lastIP}
		}
		res := ddnsFamilyResult{Type: family, IPs: ips}
		if pick.dropped() > 0 {
			res.MinSpeedNote = pick.skipReason(cfg.DDNS.MinSpeedMbps)
		}
		planned = append(planned, res)
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
			// 措辞要分辨：测速跑成了但全没到门槛，和压根没测出节点，
			// 用户的下一步动作完全不同（一个去改门槛，一个去重跑测速）。
			if pl.MinSpeedNote != "" {
				pl.Skipped = "有结果，但都没到最低速度：" + pl.MinSpeedNote
			} else {
				pl.Skipped = "还没有测出可用的 " + familyLabel(pl.Type) + " 节点"
			}
			continue
		}
		if err := p.EnsureRecords(cfg.DDNS.Domain, pl.IPs, recordOptions(cfg.DDNS, pl.Type)); err != nil {
			s.appendLog(fmt.Sprintf("手动推送域名解析失败（%s）: %s", pl.Type, err.Error()))
			writeJSON(w, 502, map[string]string{"error": ddnsHint(err)})
			return
		}
		wrote++
		msg := fmt.Sprintf("域名解析已手动更新：%s → %s（共 %d 条 %s 记录）",
			cfg.DDNS.Domain, strings.Join(pl.IPs, "、"), len(pl.IPs), pl.Type)
		if pl.MinSpeedNote != "" {
			msg += "；" + pl.MinSpeedNote + " 未写"
		}
		s.appendLog(msg)
	}

	if wrote == 0 {
		// 一族都没写成。若全是「速度没到门槛」，就别让用户去重跑测速——
		// 那是白等一轮，该改的是门槛本身。
		lowOnly := true
		for _, pl := range planned {
			if len(pl.IPs) > 0 || pl.MinSpeedNote == "" {
				lowOnly = false
				break
			}
		}
		if lowOnly {
			writeJSON(w, 400, map[string]string{"error": fmt.Sprintf(
				"测出来的节点都没到最低下载速度（%s），一条也没写。要放宽就把「最低下载速度」调小或清空",
				trimSpeed(cfg.DDNS.MinSpeedMbps)+" Mbps")})
			return
		}
		// 按模式给一句最有用的指引，别只说「失败」，三种模式的补救办法不一样。
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

	// 单族模式下手动推一次也顺手清另一族：用户点了「立即推送」就是想马上看到结果，
	// 只写 A 却还留着旧的 AAAA，看起来就像没生效。写失败时上面已经返回了，走不到这里。
	if len(families) == 1 {
		s.pruneOtherFamily(p, cfg.DDNS.Domain, families[0])
	}

	writeJSON(w, 200, map[string]any{
		"ok":          true,
		"domain":      cfg.DDNS.Domain,
		"record_type": mode,
		"results":     planned,
	})
}

// handleAdguardRewrites 把 AdGuard 里现在的重写表读出来，并标出「下次同步会保留哪几条、
// 清掉哪几条」，用户有权先看一眼再让它动手。ReplaceRewrites 只动本工具认领的域名，所以
// 返回的东西分三份，前端据此标三种状态：
//
//	managed  域名 → 这一轮该有的答案列表（v4、v6 可能各一条）→ 匹配就「保留」
//	stale    以前管过、现在不在域名列表里的域名 → 「会被清掉」
//	其余     不归本工具管（用户自己加的、AdGuard 自带的）→ 「不动它」
//
// managed 存答案列表而不是单个字符串：以前只放 cfg.LastIP，于是 v6 那条明明会被保留、
// 界面上却被标成「会被清掉」。用户看到红色标记会以为 v6 又要被抹掉，而实际什么都没发生，
// 这种「界面比实际更吓人」的谎话和反过来一样有害。
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

	// 期望集合：每个要加速的域名 → 当前最优 IP（v4 + v6）。用 RewriteDomains() 而不是
	// Domains：勾了包含子域的那些会多一条 `*.域名`，漏掉的话界面会把我们自己写的通配符
	// 标成「会被清掉」。答案走 rewriteAnswersFor，和 syncRewritesHosts 同一个函数：
	// 两处各算一套的话，界面说「保留」而实际同步会删掉，按这个预览核对反而更糊涂。
	// 那一族关掉时这里就不列它，所以「下一轮会删掉」在预览里也是实话。
	names := cfg.RewriteDomains()
	managed := make(map[string][]string, len(names))
	if answers := rewriteAnswersFor(cfg); len(answers) > 0 {
		sorted := make([]string, 0, len(answers))
		for a := range answers {
			sorted = append(sorted, a)
		}
		sort.Strings(sorted)
		for _, d := range names {
			managed[d] = sorted
		}
	}
	// hosts 源写的那几十条同样是本工具写的：不列进来，界面会把它们全标成
	// 「不归这个程序管」，用户看到一屏"不是我的"，第一反应是「它没在工作」。
	// 答案就取账本里记的那个 IP（正是上一轮写进去的）。
	for d, ip := range cfg.HostsEntries {
		if ip == "" {
			continue
		}
		if _, ok := managed[d]; ok {
			continue // 和加速域名重名：实际写的是测速结果，上面已经列了
		}
		managed[d] = []string{ip}
	}

	// 以前管过、现在不在列表里的域名：这些是「下次同步会整条清掉」的。
	nameSet := make(map[string]bool, len(names))
	for _, d := range names {
		nameSet[d] = true
	}
	stale := make([]string, 0, len(cfg.RewrittenDomains))
	for _, d := range cfg.RewrittenDomains {
		if d == "" || nameSet[d] {
			continue
		}
		// hosts 源还认领着它（比如从「要加速的域名」里删了，但它本来就在
		// hosts 清单里），下一轮会把这条重新写成清单里的地址，不是清掉。
		if _, ok := managed[d]; ok {
			continue
		}
		stale = append(stale, d)
	}
	sort.Strings(stale)

	writeJSON(w, 200, map[string]any{
		"ok":      true,
		"entries": entries,
		"managed": managed,
		"stale":   stale,
		"last_ip": cfg.LastIP,
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
