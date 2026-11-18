package web

// GitHub hosts 源 → AdGuard 重写。
//
// 和「测速挑最优 IP」平行的第二条路：那条是所有加速域名共用一个最优 IP，这条是
// 一份别人维护的「域名→IP」清单原样写进去。写的是同一张重写表，边界要硬：
//
//  1. 独立开关、独立来源、独立账本，关掉只影响它自己写的那几十条。
//  2. 同一个域名两边都有时用测速结果（用户 2026-11-18 定的），跳过的不静默。
//  3. 拉取失败沿用上一轮，上一轮的结果就存在 config.HostsEntries 里。
//  4. 0.0.0.0 / 127.0.0.1 这类是「别解析」的意思，整行跳过；IPv6 照写。

import (
	"context"
	"errors"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/303528084/cf-ddns-sidecar/config"
)

// maxHostsEntries 是一次同步接受的域名条数上限。
//
// 这份清单会原样写进 AdGuard 的重写表，几十万行的源会把 AdGuard 拖到打不开。
// 截断时日志会写明截了。
const maxHostsEntries = 2000

// hostsParseStats 记录一次解析认下了什么、跳过了什么，每一项都能进日志：
// 用户看到「已同步」但某个域名没生效时，得能自己看出是哪一类被跳过。
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
	// errs 是每个失败链接一句人话，上层逐条打进日志：填了三个链接时，
	// 得能看出是哪一个不行。
	errs []string
}

// plausibleHostname 判断一个字符串像不像能写进 AdGuard 重写的域名。
// 比「合法 DNS 名」宽松：处理的是外部文本，宁可放过一个奇怪的（AdGuard 自己会
// 拒绝），也别把一整批来源作废。只挡空的、没有点的、带空白或斜杠的。
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
// 一行 `IP 域名 [域名…]`，`#` 之后是注释。重复域名取第一次出现的那个，
// 和 /etc/hosts 的查找语义一致，用户拿同一份文件在电脑上试能对上。
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
		// 域名指向一个打不开的地址，比不写更糟，所以整行跳过并记数。
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
// 这是这个功能最容易踩的坑：根路径 `https://hosts.gitcdn.top/` 返回的是落地页，
// 不是清单。笼统报「解析失败」用户看不出是路径填错还是站点挂了，识别出来才能
// 直接说「这个链接返回的是网页，试试 /hosts.txt」。
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

// fetchHosts 把几个链接依次拉下来并合并，先填的链接优先：想用自己的一份清单
// 盖住上游某几条，把自己的填在前面就行。
//
// 返回 error 的只有两种，都是「这一轮不该拿结果去覆盖 AdGuard」：所有链接都失败、
// 或者拉到了但一条都认不出来。第二种必须算失败，否则上游某天返回一个 200 的空白页
// 就会把几十条重写全删掉，而日志看起来一切正常。
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
// hosts 为 nil 表示「这一块这一轮不写」，同时也意味着账本里那些该清了：开关关掉
// 之后 AdGuard 上不能留着指向旧 IP 的残骸，否则界面写着「已关闭」、实际还在改解析。
//
// 账本（cfg.HostsEntries）在这里只有一个用途：记住上一轮认领了哪些域名。源里删掉
// 一个域名之后，只有它还知道要去 AdGuard 上把那条清掉。
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

// hostsWantFor 决定「这一块现在该在 AdGuard 上有哪些记录」，和 ReplaceRewrites
// 的认领语义对齐：给账本＝这些域名归它管；nil＝这一块一条都不该有（开关关掉或
// 来源清空），传给 mergeHostsWant 后会变成空答案集，也就是收回。
//
// 单独提出来是为了能测：syncRewrites 要连真 AdGuard 测不动，而「关掉开关后到底
// 传不传账本」正是这条功能最容易接错的地方。
func hostsWantFor(cfg config.Config) map[string]string {
	if hostsOffFor(cfg) {
		return nil
	}
	return cfg.HostsEntries
}

// hostsOffFor 说「这一块现在是不是该一条都不留」：开关没开、或者来源被清空。
// 和 hostsWantFor 分开是因为「刚打开开关但这一次没拉到」也是 want=nil，那不是收回。
func hostsOffFor(cfg config.Config) bool {
	return !cfg.HostsEnabled || len(cfg.HostsSourceURLs()) == 0
}

// enableHostsNow 在开关打开的那一刹那把清单拉下来、立刻写进 AdGuard。
// 定时同步挂在测速那一轮（默认 60 分钟），不在这里补一下，用户打开开关后只能
// 盯着一开关的开关等下一轮，和刚修掉的「关掉不生效」是同一个毛病。
// 拉不到、写不进都不致命：账本保持原样，下一轮测速会重试。
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
// 三种情况分开走，因为它们对用户意味着完全不同的事：开关没开 / 没填来源 → nil
// 并清账本；拉取失败 → 沿用上一轮的条目，一条已有记录都不删；成功 → 用新结果，
// 并把「认下了多少、跳了多少」写进日志。
func (s *Server) resolveHosts(ctx context.Context, cfg config.Config) map[string]string {
	urls := cfg.HostsSourceURLs()
	if !cfg.HostsEnabled || len(urls) == 0 {
		if len(cfg.HostsEntries) > 0 {
			// 这里不报条数：此刻还不知道最终会清掉几条（和加速域名重名的那些
			// 归测速结果管），真正的数字由 mergeHostsWant 那一行给。
			s.appendLog("hosts 源已关闭，AdGuard 上由它写的记录会一起收回来")
		}
		return nil
	}

	res, err := fetchHosts(ctx, urls)
	if err != nil {
		if len(cfg.HostsEntries) > 0 {
			s.appendLog("hosts 拉取失败，沿用上一轮记着的 " + strconv.Itoa(len(cfg.HostsEntries)) +
				" 条（不会删掉已有的）: " + friendlyErr(err))
			return cfg.HostsEntries
		}
		s.appendLog("hosts 拉取失败，这一轮不写 hosts: " + friendlyErr(err))
		return nil
	}

	for _, e := range res.errs {
		s.appendLog("hosts 链接没拉到：" + e)
	}

	st := res.stats
	line := "hosts 源：" + strconv.Itoa(len(res.entries)) + " 条可用"
	if st.blocked > 0 {
		line += "，跳过 " + strconv.Itoa(st.blocked) + " 条拦截条目（0.0.0.0 / 127.0.0.1 / :: / ::1 是「别解析」的意思，不是解析结果）"
	}
	if st.badIP > 0 {
		line += "，跳过 " + strconv.Itoa(st.badIP) + " 行（第一列不是 IP）"
	}
	if st.badName > 0 {
		line += "，跳过 " + strconv.Itoa(st.badName) + " 个不像域名的名字"
	}
	if st.dup > 0 {
		line += "，去掉 " + strconv.Itoa(st.dup) + " 个重复域名（用了先出现的那个）"
	}
	if st.over > 0 {
		line += "，超出 " + strconv.Itoa(maxHostsEntries) + " 条上限截掉了 " + strconv.Itoa(st.over) + " 个"
	}
	s.appendLog(line)
	return res.entries
}
