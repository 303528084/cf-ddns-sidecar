package web

// GitHub hosts 源 → AdGuard 重写。
//
// 这是和「测速挑最优 IP」平行的第二条路：那边是「所有加速域名共用同一个最优
// IP」，这边是「别人维护的一份域名→IP 清单，原样写进 AdGuard 重写表」。两条路
// 写的是同一张重写表，所以必须有明确的边界，否则两边会互相覆盖：
//
//  1. **独立开关、独立来源、独立账本**。关掉 hosts 只影响它自己写的那几十条，
//     一个加速域名都不动；反过来加速域名那套删删改改也不会碰到它。
//  2. **冲突时加速域名优先**（用户 2026-11-18 定的口径）。同一个域名既在「要加
//     速的域名」里、又在 hosts 源里时，用测速结果那个 IP——因为那是本机测出来
//     的，比清单里写死的地址更可能真的快。被跳过的不静默，日志里记一笔。
//  3. **拉取失败沿用上一轮**。网络抖一下就把几十条重写删掉、下一轮再加回来，
//     AdGuard 表每轮都在抖，等于把「稳定」交给对方站点的可用性。上一轮的结果
//     存在 config.HostsEntries 里，它就是干这个的。
//  4. **拦截条目跳过**。`0.0.0.0 域名`、`127.0.0.1 域名` 这类是「别让它解析」
//     的意思，不是解析结果；照写进重写等于把这些域名指到一个不存在的地址上，
//     表现是打不开而不是被拦，比不写更糟。IPv6 地址照写（AdGuard 的 AAAA
//     重写是支持的），只有本机/未指定地址才跳。

import (
	"context"
	"errors"
	"log"
	"net"
	"strings"
	"time"

	"github.com/303528084/cf-ddns-sidecar/config"
)

// maxHostsEntries 是一次同步接受的域名条数上限。
//
// 不是洁癖：这份清单会被原样写进 AdGuard 的重写表，一个几十万行的源（或者
// 一个把整站 HTML 当 hosts 返回的链接——它是"认得出来"的，只是条数离谱）会把
// AdGuard 拖到打不开。截断时日志会写明截了。
const maxHostsEntries = 2000

// hostsParseStats 记录一次解析认下了什么、跳过了什么。
//
// 每一项都要能进日志：用户填了个链接、界面上说「已同步」，但某个域名没生效，
// 他需要能自己看出是「被当作拦截条目跳了」还是「这行 IP 认不出」，而不是来问。
type hostsParseStats struct {
	ok      int // 认下来的域名条数（去重后）
	blocked int // 拦截条目（0.0.0.0 / 127.0.0.1 / :: / ::1）
	badIP   int // 首列不是 IP 的行
	badName int // 域名不像域名
	dup     int // 同域名出现多次，用了第一次的
	over    int // 超出条数上限被截掉的
}

// hostsFetch 是一次「拉取 + 解析」的结果。
type hostsFetch struct {
	entries map[string]string
	stats   hostsParseStats
	// errs 是每个失败链接一句人话。上层逐条打进日志，不做成一个大字符串——
	// 用户填了三个链接时，得能看出是哪一个不行。
	errs []string
}

// plausibleHostname 判断一个字符串像不像能写进 AdGuard 重写的域名。
//
// 比"合法 DNS 名"宽松：这里处理的是外部文本，宁可放过一个奇怪的域名（AdGuard
// 自己会拒绝），也别把一整批来源作废。只挡三类明显不是域名的东西：空的、
// 没有点的（`localhost`、`myhost`）、带空白或斜杠的。
func plausibleHostname(d string) bool {
	if len(d) < 4 || len(d) > 253 || !strings.Contains(d, ".") {
		return false
	}
	if strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") {
		return false
	}
	if net.ParseIP(d) != nil {
		return false // `1.2.3.4 1.2.3.4` 这种把 IP 填进域名列的
	}
	for _, r := range d {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}

// parseHostsText 把一份 hosts 文本解析成「域名 → IP」。
//
// 认的格式就是标准 hosts：一行 `IP 域名 [域名…]`，`#` 之后是注释。
// 一行多个域名时都指向同一个 IP（`140.82.113.4 github.com gist.github.com`）。
//
// 重复域名取**第一次**出现的那个：和 /etc/hosts 的查找语义一致（先匹配到的
// 生效），出问题时用户拿同一份文件在电脑上试出来的结果能对上。
func parseHostsText(text string) (map[string]string, hostsParseStats) {
	var st hostsParseStats
	out := make(map[string]string)

	for _, raw := range strings.Split(text, "\n") {
		// 注释去掉：`#` 前面是空白或行首才算注释（同 sources.go 的判据，
		// 那里的 `#US` 是标签，这里的 `#` 全是注释，但仍然沿用同一套规则，
		// 免得哪天两边不一致）。
		line := commentRe.ReplaceAllString(raw, "")
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		ip := net.ParseIP(fields[0])
		if ip == nil {
			st.badIP++
			continue
		}
		// 拦截条目：`0.0.0.0` / `::` 是「未指定地址」，`127.0.0.1` / `::1` 是
		// 「本机」。这两个在 hosts 里都是「别解析它」的意思，写进重写会让这些
		// 域名指向一个打不开的地址——比不写更糟，所以整行跳过并记数。
		if ip.IsUnspecified() || ip.IsLoopback() {
			st.blocked += len(fields) - 1
			continue
		}

		answer := ip.String()
		for _, h := range fields[1:] {
			d := config.NormalizeDomain(h)
			if !plausibleHostname(d) {
				st.badName++
				continue
			}
			if _, seen := out[d]; seen {
				st.dup++
				continue
			}
			if len(out) >= maxHostsEntries {
				st.over++
				continue
			}
			out[d] = answer
		}
	}
	st.ok = len(out)
	return out, st
}

// looksLikeHTML 判断拿到的正文是不是一个网页。
//
// 这个判断值得单独写一个函数，因为它是这个功能最容易踩的坑：
// `https://hosts.gitcdn.top/`（用户会想当然填的那个根路径）返回的是一张
// 落地页，不是 hosts 列表。笼统报「解析失败」等于把用户丢在原地——他看不出
// 「链接填错了路径」和「站点挂了」有什么区别。识别出来之后就能直接告诉他
// 「这个链接返回的是网页，试试 /hosts.txt」。
func looksLikeHTML(text string) bool {
	head := text
	if len(head) > 512 {
		head = head[:512]
	}
	head = strings.ToLower(head)
	// 从左边第一个非空白字符看起：有些站点会在 DOCTYPE 前面塞空行和 BOM。
	head = strings.TrimSpace(strings.TrimPrefix(head, "\ufeff"))
	return strings.HasPrefix(head, "<!doctype") || strings.HasPrefix(head, "<html")
}

// fetchHosts 把几个链接依次拉下来并合并。
//
// 合并规则：先填的链接优先（同一个域名后面出现的版本丢掉并记 dup）。这样用户
// 想用自己的一份清单盖住上游某几条时，把自己的填在前面就行，不用额外的覆盖语法。
//
// 返回 error 的条件只有两种，都是「这一轮不该拿结果去覆盖 AdGuard」：
//   - 所有链接都失败；
//   - 有链接成功了，但一条都认不出来（空文件、或者全是注释）。
//
// 第二种必须算失败：上游某天返回一个 200 的空白页，如果当成「源里现在没有条目」
// 处理，就会把 AdGuard 上几十条重写全删掉，而日志看起来一切正常。
func fetchHosts(ctx context.Context, urls []string) (*hostsFetch, error) {
	res := &hostsFetch{entries: make(map[string]string)}
	var firstErr string

	for _, u := range urls {
		text, err := fetchSourceText(ctx, u)
		if err != nil {
			res.errs = append(res.errs, u+" —— "+friendlyErr(err))
			if firstErr == "" {
				firstErr = friendlyErr(err)
			}
			continue
		}
		if looksLikeHTML(text) {
			res.errs = append(res.errs, u+" —— 这个链接返回的是网页，不是 hosts 列表。"+
				"看起来是站点的介绍页，数据通常在 /hosts.txt 这种路径上")
			if firstErr == "" {
				firstErr = "这个链接返回的是网页，不是 hosts 列表（试试 /hosts.txt 这类路径）"
			}
			continue
		}

		entries, st := parseHostsText(text)
		if len(entries) == 0 {
			res.errs = append(res.errs, u+" —— 拉到了内容，但一条 hosts 都认不出来"+
				"（正常的每行长这样：140.82.113.4 github.com）")
			if firstErr == "" {
				firstErr = "拉到了内容，但一条 hosts 都认不出来"
			}
			continue
		}
		res.stats.blocked += st.blocked
		res.stats.badIP += st.badIP
		res.stats.badName += st.badName
		res.stats.over += st.over
		for d, ip := range entries {
			if _, seen := res.entries[d]; seen {
				res.stats.dup++
				continue
			}
			if len(res.entries) >= maxHostsEntries {
				res.stats.over++
				continue
			}
			res.entries[d] = ip
		}
	}

	res.stats.ok = len(res.entries)
	if len(res.entries) == 0 {
		if firstErr == "" {
			firstErr = "没有可用的 hosts 来源"
		}
		return res, errors.New(firstErr)
	}
	return res, nil
}

// hostsMergeStat 记录 hosts 条目并进 want 时发生了什么。
type hostsMergeStat struct {
	added   int // 真正写进 want 的域名数
	skipped int // 与加速域名重名、让给加速结果的
	cleared int // 账本里有、这一轮源里没有 → 要清掉的
}

// mergeHostsWant 把 hosts 条目并进 AdGuard 写入意图。
//
// hosts 为 nil 表示「这一块这一轮不写」（开关关掉、没填来源、从没拉到过）。
// 注意它同时意味着「账本里那些该清了」——用户把开关关掉之后，AdGuard 上那些
// 域名不能留着指向旧 IP 的残骸，否则界面上写着"已关闭"、实际还在改解析。
//
// 账本（cfg.HostsEntries）在这一步只有一个用途：记住「上一轮我认领了哪些域名」。
// 源里删掉一个域名之后，只有它还知道要去 AdGuard 上把那条清掉——这和
// rewrittenDomains 之于「要加速的域名」是一回事。
func mergeHostsWant(want map[string]map[string]bool, cfg config.Config, names []string, hosts map[string]string) hostsMergeStat {
	var st hostsMergeStat

	claimed := make(map[string]bool, len(names))
	for _, d := range names {
		claimed[d] = true
	}

	for d, ip := range hosts {
		if d == "" || ip == "" {
			continue
		}
		if claimed[d] {
			// 加速域名优先：这个域名归测速结果管，hosts 里这条让开。
			st.skipped++
			continue
		}
		want[d] = map[string]bool{ip: true}
		st.added++
	}

	for d := range cfg.HostsEntries {
		if d == "" || claimed[d] {
			continue
		}
		if _, still := hosts[d]; still {
			continue
		}
		if _, ok := want[d]; ok {
			continue
		}
		// 空集合 = 「这个域名不该有任何记录」，ReplaceRewrites 会把它清掉。
		want[d] = map[string]bool{}
		st.cleared++
	}
	return st
}

// hostsWantFor 决定「这一块现在该在 AdGuard 上有哪些记录」。
//
// 返回值同时有两种含义，和 ReplaceRewrites 的认领语义对齐：
//   - 给了账本 → 这些域名归 hosts 源管，答案就是清单里那些；
//   - nil     → **这一块一条都不该有**。开关关掉、或者来源被清空时就是这种，
//     把账本交给 mergeHostsWant 时会变成「空答案集」，也就是从 AdGuard 收回。
//
// 单独提出来是为了能测：`syncRewrites` 要连真 AdGuard，测不动；
// 而「关掉开关后到底传不传账本」正是这条功能最容易接错的地方。
func hostsWantFor(cfg config.Config) map[string]string {
	if hostsOffFor(cfg) {
		return nil
	}
	return cfg.HostsEntries
}

// hostsOffFor 说「这一块现在是不是该一条都不留」：开关没开、或者来源被清空。
//
// 和 hostsWantFor 分开是因为两处用得上但语义不同：syncRewrites 要判断
// 「这次是不是在收回」（收回完要把账本清掉），而不只是「want 是不是 nil」
// ——刚打开开关、但这一次没拉到条目时 want 也是 nil，那不是收回。
func hostsOffFor(cfg config.Config) bool {
	return !cfg.HostsEnabled || len(cfg.HostsSourceURLs()) == 0
}

// enableHostsNow 在开关打开的那一刹那把清单拉下来、立刻写进 AdGuard。
//
// 为什么非要做这一步：定时同步挂在测速那一轮（默认 60 分钟一次）。用户打开
// 开关后如果什么都不发生，他得等到下一轮测速才看得到效果，中间只能盯着一个
// 「开着的开关」——这和刚修掉的「关掉不生效」是同一个毛病，只是方向反过来。
//
// 拉不到、写不进都不算致命：账本保持原样，下一轮测速自然会重试。
func (s *Server) enableHostsNow(cfg config.Config) string {
	if strings.TrimSpace(cfg.AdGuard.URL) == "" {
		return "已开启 hosts 源；还没填 AdGuard 地址，填好后自动会写"
	}
	if len(cfg.HostsSourceURLs()) == 0 {
		return "已开启 hosts 源；先把清单链接填上再保存"
	}
	// 15 秒够拉一份几十 KB 的清单了；再长用户会以为界面卡住。
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	entries := s.resolveHosts(ctx, cfg) // 这里会打「N 条可用」或「拉取失败」
	if len(entries) == 0 {
		return "已开启 hosts 源；这一次没拉到可用条目，下次测速再试"
	}
	note, ok := s.syncRewritesHosts(cfg, entries, false)
	if !ok {
		return note
	}
	s.mu.Lock()
	s.cfg.HostsEntries = entries
	s.cfg.HostsSyncedAt = time.Now().Format("2006-01-02 15:04:05")
	toSave := s.cfg.Clone()
	s.mu.Unlock()
	if err := toSave.Save(); err != nil {
		log.Printf("保存配置失败: %v", err)
	}
	return "已开启 hosts 源：" + note
}

// resolveHosts 决定这一轮 hosts 写入用哪些条目。
//
// 三种情况分开走，日志也分开说，因为它们对用户意味着完全不同的事：
//   - 开关没开 / 没填来源 → nil，同时把上一轮的账本清干净；
//   - 拉取失败 → **沿用上一轮**的条目（cfg.HostsEntries），不删任何已有记录；
//   - 成功 → 用新结果，并把「认下了多少、跳了多少」写进日志。
func (s *Server) resolveHosts(ctx context.Context, cfg config.Config) map[string]string {
	urls := cfg.HostsSourceURLs()
	if !cfg.HostsEnabled || len(urls) == 0 {
		if len(cfg.HostsEntries) > 0 {
			// 这里**不报条数**：这条日志出现时还不知道最终会清掉几条
			// （和加速域名重名的那几个归测速结果管，不算清掉）。真正的数字
			// 由 mergeHostsWant 那一行给，两处报两个数只会让人对不上账。
			s.appendLog("hosts 源已关闭，AdGuard 上由它写的记录会一起收回来")
		}
		return nil
	}

	res, err := fetchHosts(ctx, urls)
	if err != nil {
		if len(cfg.HostsEntries) > 0 {
			s.appendLog("hosts 拉取失败，沿用上一轮记着的 " + itoa(len(cfg.HostsEntries)) +
				" 条（不会删掉已有的）: " + friendlyErr(err))
			return cfg.HostsEntries
		}
		s.appendLog("hosts 拉取失败，这一轮不写 hosts: " + friendlyErr(err))
		return nil
	}

	// 每个失败的链接单独一句：填了三个链接时，得能看出是哪一个不行。
	for _, e := range res.errs {
		s.appendLog("hosts 链接没拉到：" + e)
	}

	st := res.stats
	line := "hosts 源：" + itoa(len(res.entries)) + " 条可用"
	if st.blocked > 0 {
		line += "，跳过 " + itoa(st.blocked) + " 条拦截条目（0.0.0.0 / 127.0.0.1 / :: / ::1 是「别解析」的意思，不是解析结果）"
	}
	if st.badIP > 0 {
		line += "，跳过 " + itoa(st.badIP) + " 行（第一列不是 IP）"
	}
	if st.badName > 0 {
		line += "，跳过 " + itoa(st.badName) + " 个不像域名的名字"
	}
	if st.dup > 0 {
		line += "，去掉 " + itoa(st.dup) + " 个重复域名（用了先出现的那个）"
	}
	if st.over > 0 {
		line += "，超出 " + itoa(maxHostsEntries) + " 条上限截掉了 " + itoa(st.over) + " 个"
	}
	s.appendLog(line)
	return res.entries
}
