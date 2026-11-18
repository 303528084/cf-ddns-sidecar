package web

// 配置的导出与导入。
//
// 为什么要有它：数据目录一旦被清空，用户就得手抄八项设置——AdGuard 地址/
// 用户名/密码、要加速的域名列表、测速参数、服务商、优选域名、以及可能两家
// 以上的密钥。2026-11-17 那天他正是这么重填了一遍，其中 Cloudflare 令牌
// 还得回 Cloudflare 后台重新生成（旧的那份随数据目录一起没了）。
// 能导出一个文件、换机或重装时上传回来，才是真正兜住这件事。
//
// 两条硬约束：
//  1. 文件里带密钥和 AdGuard 密码，必须只走已登录的接口，并且不让浏览器
//     或中间代理缓存它（Cache-Control: no-store）；
//  2. 导入时只允许写白名单里的 key 进 ddns.env。备份文件是用户可以手改的，
//     不能让它变成往密钥文件里塞任意变量的入口。

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/303528084/cf-ddns-sidecar/config"
	"github.com/303528084/cf-ddns-sidecar/ddns"
	"github.com/303528084/cf-ddns-sidecar/engine"
)

const (
	// bundleApp 是导出文件里标识「这是谁的文件」的字段值。
	bundleApp = "cf-ddns-sidecar"
	// bundleFormat 是格式版本。以后改结构就 +1，导入侧据此拒绝未来版本。
	bundleFormat = 1
	// maxBundleBytes 是导入文件的大小上限。正常备份只有几 KB。
	maxBundleBytes = 1 << 20
	// maxRewrittenDomains 是导入账本时接受的条数上限。见 bundleConfig
	// 里 RewrittenDomains 的说明：它决定「下次同步能删哪些域名」，从一份
	// 来路不明的文件里读进几千条，等于授权程序去动几千个域名。
	maxRewrittenDomains = 200
)

// bundleConfig 是跟着文件走的那部分配置。
//
// 刻意用显式字段而不是直接序列化 config.Config：
//   - 运行状态（last_ip / last_time）不该跟着走，那是这台机器的实际结果，
//     换台机器后照搬过来只会误导人；
//   - 以后给 Config 加字段时，不会因为「顺手 Marshal」把不该出门的东西
//     一起导出去。
//
// 显式清单的代价是「加一个设置就得记得来这儿补一行」。忘了不报错、也不
// 打日志——那个值就静静地从文件里消失，而界面上写着「把全部设置存成一个
// 文件」（v1.7.4 之前正是这样漏了 6 项：记录类型、IPv6 段链接、同步条数、
// 橙云开关、TTL、每个域名的「包含子域」）。两条防线：
//  1. transfer_test.go 里有一组「导出→导入后逐项相同」的用例，Config 里
//     多一个用户能改的字段，那儿就得多一行断言；
//  2. 下面凡是「0 / false / 空列表本身就是合法值」的字段，一律用指针。
//     用零值代表「文件里没有这一项」会把「用户主动清空」和「老文件没这个
//     字段」混成同一件事，于是要么清不掉、要么一导入就被静默覆盖。
type bundleConfig struct {
	AdGuardURL      string   `json:"adguard_url"`
	AdGuardUsername string   `json:"adguard_username"`
	AdGuardPassword string   `json:"adguard_password,omitempty"`
	Domains         []string `json:"domains"`
	// DomainMeta 是每个域名的「包含子域」勾选和添加时间。
	// 不导出的话，恢复之后所有域名都变回「不包含子域」——AdGuard 里那条
	// `*.域名` 的重写不再生成，子域突然不走优选 IP 了，而界面看起来
	// 「恢复成功」。这是最难自己想到的一类故障。
	DomainMeta      map[string]config.DomainMeta `json:"domain_meta,omitempty"`
	TopN            int                          `json:"top_n"`
	Candidates      int                          `json:"bandwidth_candidates"`
	IntervalMinutes int                          `json:"interval_minutes"`
	// ExtraSources 以前漏了：用户辛苦填的「优选 IP 段」不在备份里，
	// 换台机器恢复之后会悄悄退回官方段，而界面看起来「恢复成功」。
	ExtraSources []string `json:"extra_sources,omitempty"`
	// EngineOverrides 是高级设置里改过的引擎参数。同样是「不存就丢」的东西，
	// 而且丢了以后表现是「测速行为变了但界面全是默认值」，最难查。
	EngineOverrides map[string]any `json:"engine_overrides,omitempty"`
	// IPv6ProbeURL 是 v6 段链接（一行一个）。指针的理由：用户把这一栏
	// 清空是合法操作，得和「老文件里没这个字段」分开。
	IPv6ProbeURL *string `json:"ipv6_probe_url,omitempty"`
	// hosts 源那一块（GitHub hosts 清单写进 AdGuard 重写）。
	// 两个都用指针，理由同上：「关掉」和「没这一项」必须分开，否则从一份老
	// 文件恢复会把用户打开的开关静默关掉。
	HostsEnabled *bool   `json:"hosts_enabled,omitempty"`
	HostsSource  *string `json:"hosts_source,omitempty"`
	// HostsEntries 是 hosts 那一块的账本（域名 → 上一轮写进去的 IP）。
	//
	// 和 RewrittenDomains 一样属于「严格说是运行状态、但不带就会留下残骸」：
	// 换台机器恢复之后，如果 hosts 源里已经没有某个域名，账本是唯一知道要去
	// AdGuard 上把它清掉的东西。条数上限同样是为了不让人拿一份来路不明的
	// 文件授权程序去动几千个域名。
	HostsEntries map[string]string `json:"hosts_entries,omitempty"`
	DDNSEnabled  bool              `json:"ddns_enabled"`
	DDNSProvider string            `json:"ddns_provider"`
	DDNSDomain   string            `json:"ddns_domain"`
	// 下面四项全是「0 / false 也是用户真切能选的值」（TTL 0 = 用各家默认、
	// 橙云关掉 = 谁都看得见的选项）。所以必须用指针，不能用零值代表缺失。
	DDNSTTL        *int    `json:"ddns_ttl,omitempty"`
	DDNSProxied    *bool   `json:"ddns_proxied,omitempty"`
	DDNSIPCount    *int    `json:"ddns_ip_count,omitempty"`
	DDNSRecordType *string `json:"ddns_record_type,omitempty"`
	// RewrittenDomains 是「本工具在 AdGuard 上认领过哪些域名」的账本。
	//
	// 它严格说是运行状态，按上面那条原则（不把 last_ip 这类东西带出去）本可以
	// 不导。但它决定了「下次同步时哪些旧记录可以删」：换机恢复后域名列表被整份
	// 替换，如果账本不带，那些已经不在这份清单里的域名就会在 AdGuard 上留下
	// 永久残留，指向换机前的旧 IP——而界面上一切正常。带上它，恢复之后第一次
	// 同步就能把该清的清掉。
	//
	// 限制条数不是洁癖：这个列表只会被本工具自己写，正常长度就是域名数 + 通配符
	// 数。从一份来路不明的文件里读进几千条，等于授权程序去动几千个域名。
	RewrittenDomains []string `json:"rewritten_domains,omitempty"`
}

// bundle 是可导出、也可导入的文件格式。
type bundle struct {
	App        string            `json:"app"`
	Format     int               `json:"format"`
	Version    string            `json:"version"`
	ExportedAt string            `json:"exported_at"`
	Note       string            `json:"note,omitempty"`
	Config     bundleConfig      `json:"config"`
	Secrets    map[string]string `json:"secrets,omitempty"`
}

// bundleNote 写在导出文件里，提醒拿到这份文件的人该怎么保管。
const bundleNote = "这个文件包含 AdGuard 密码和各 DNS 服务商的密钥，请当作密码保管。" +
	"换机或重装后在后台「备份与恢复」里上传即可一键恢复；后台登录密码不在其中。"

// allowedSecretKeys 是允许通过导入写进 ddns.env 的变量名白名单。
var allowedSecretKeys = func() map[string]bool {
	m := make(map[string]bool)
	for _, k := range config.AllCredentialKeys() {
		m[k] = true
	}
	return m
}()

// buildBundle 组装导出内容。creds 传 config.DDNCredentials() 的结果。
func buildBundle(cfg config.Config, creds map[string]string, ver string, now time.Time) bundle {
	secrets := make(map[string]string, len(creds))
	for _, k := range config.AllCredentialKeys() {
		if v := strings.TrimSpace(creds[k]); v != "" {
			secrets[k] = v
		}
	}

	domains := cfg.Domains
	if domains == nil {
		domains = []string{}
	}

	// 域名的附加信息也要拷一份：它和 Domains 共用一张哈希表的话，导出
	// 期间用户在界面上改了勾选，文件里就会是一半新一半旧的状态。
	var meta map[string]config.DomainMeta
	if len(cfg.DomainMeta) > 0 {
		meta = make(map[string]config.DomainMeta, len(cfg.DomainMeta))
		for k, v := range cfg.DomainMeta {
			meta[k] = v
		}
	}

	// 指针字段先落到局部变量上再取地址——直接 &cfg.DDNS.TTL 会把这个结构体
	// 的字段地址带进文件结构里，之后谁改一下 cfg，导出内容就跟着变。
	ttl := cfg.DDNS.TTL
	proxied := cfg.DDNS.Proxied
	ipCount := cfg.DDNS.IPCount
	recordType := cfg.DDNS.RecordType
	v6 := cfg.IPv6ProbeURL
	hostsOn := cfg.HostsEnabled
	hostsSrc := cfg.HostsSource

	// hosts 账本同样要拷一份：导出期间一轮测速跑完会整段替换它，直接引用
	// 那张表就可能导出成一半旧一半新。
	var hostsBook map[string]string
	if len(cfg.HostsEntries) > 0 {
		hostsBook = make(map[string]string, len(cfg.HostsEntries))
		for k, v := range cfg.HostsEntries {
			hostsBook[k] = v
		}
	}

	return bundle{
		App:        bundleApp,
		Format:     bundleFormat,
		Version:    ver,
		ExportedAt: now.Format(time.RFC3339),
		Note:       bundleNote,
		Config: bundleConfig{
			AdGuardURL:       cfg.AdGuard.URL,
			AdGuardUsername:  cfg.AdGuard.Username,
			AdGuardPassword:  cfg.AdGuard.Password,
			Domains:          append([]string{}, domains...),
			DomainMeta:       meta,
			TopN:             cfg.Speed.TopN,
			Candidates:       cfg.Speed.BandwidthCandidates,
			IntervalMinutes:  cfg.Speed.IntervalMinutes,
			ExtraSources:     append([]string{}, cfg.Speed.ExtraSources...),
			EngineOverrides:  cfg.Speed.EngineOverrides,
			IPv6ProbeURL:     &v6,
			HostsEnabled:     &hostsOn,
			HostsSource:      &hostsSrc,
			HostsEntries:     hostsBook,
			DDNSEnabled:      cfg.DDNS.Enabled,
			DDNSProvider:     cfg.DDNS.Provider,
			DDNSDomain:       cfg.DDNS.Domain,
			DDNSTTL:          &ttl,
			DDNSProxied:      &proxied,
			DDNSIPCount:      &ipCount,
			DDNSRecordType:   &recordType,
			RewrittenDomains: append([]string{}, cfg.RewrittenDomains...),
		},
		Secrets: secrets,
	}
}

// parseBundle 解析并校验导入文件，返回「纠正过什么」的提示列表。
//
// 校验原则：能修的直接修（域名去协议前缀、服务商小写、数值越界归位）、
// 修不了的报错（不是本应用的文件、格式版本太新）。宁可能用也别让人白填八项。
func parseBundle(raw []byte) (bundle, []string, error) {
	var b bundle
	if len(raw) == 0 {
		return b, nil, fmt.Errorf("文件是空的")
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return b, nil, fmt.Errorf("这不是有效的 JSON 文件（%v）", err)
	}
	if b.App != bundleApp {
		return b, nil, fmt.Errorf("这不是本应用导出的配置文件（文件里写着 app=%q）", b.App)
	}
	if b.Format <= 0 || b.Format > bundleFormat {
		return b, nil, fmt.Errorf("文件格式版本是 %d，当前程序只认到 %d，请先升级应用", b.Format, bundleFormat)
	}

	var warns []string

	// 域名：去重、去协议前缀、小写；非法项丢掉。
	before := len(b.Config.Domains)
	b.Config.Domains = normalizeDomains(b.Config.Domains)
	if dropped := before - len(b.Config.Domains); dropped > 0 {
		warns = append(warns, fmt.Sprintf("忽略了 %d 个看不懂的域名", dropped))
	}

	// 账本：同样归一化（去协议前缀、小写、去重），并按条数上限截断。
	// 通配符 `*.a.com` 会被 normalizeDomains 原样留下，这是必须的——勾了
	// 「包含子域」的域名，账本里记的就是这条通配符。
	if n := len(b.Config.RewrittenDomains); n > 0 {
		b.Config.RewrittenDomains = normalizeDomains(b.Config.RewrittenDomains)
		if len(b.Config.RewrittenDomains) > maxRewrittenDomains {
			b.Config.RewrittenDomains = b.Config.RewrittenDomains[:maxRewrittenDomains]
		}
		if dropped := n - len(b.Config.RewrittenDomains); dropped > 0 {
			warns = append(warns, fmt.Sprintf("「上次写进 AdGuard 的域名」有 %d 条看不懂或超出上限，已忽略", dropped))
		}
	}

	if b.Config.DDNSProvider != "" {
		p := strings.ToLower(strings.TrimSpace(b.Config.DDNSProvider))
		if _, ok := config.RequiredEnvByProvider[p]; ok {
			b.Config.DDNSProvider = p
		} else {
			warns = append(warns, fmt.Sprintf("服务商 %q 不认识，已按 Cloudflare 处理", b.Config.DDNSProvider))
			b.Config.DDNSProvider = "cloudflare"
		}
	}
	if b.Config.DDNSDomain != "" {
		b.Config.DDNSDomain = config.NormalizeDomain(b.Config.DDNSDomain)
	}

	// 数值越界归位，别让一个手改的文件把定时器搞成 0 或负数。
	if b.Config.TopN <= 0 {
		b.Config.TopN = 5
	}
	if b.Config.Candidates <= 0 {
		b.Config.Candidates = 100
	}
	if b.Config.IntervalMinutes < 0 {
		b.Config.IntervalMinutes = 0
	}

	// 域名的附加信息：键先归一化成域名，再只留还在域名列表里的那些。
	// 手改过的文件可能留下「域名已经删了、勾选还在」的残留，直接照收会让
	// 用户删掉一个域名再加回来时「继承」上一次的包含子域设置。
	if b.Config.DomainMeta != nil {
		keep := make(map[string]bool, len(b.Config.Domains))
		for _, d := range b.Config.Domains {
			keep[d] = true
		}
		out := make(map[string]config.DomainMeta, len(b.Config.DomainMeta))
		stale := 0
		for k, v := range b.Config.DomainMeta {
			nk := config.NormalizeDomain(k)
			if nk == "" || !keep[nk] {
				stale++
				continue
			}
			out[nk] = v
		}
		if stale > 0 {
			warns = append(warns, fmt.Sprintf("忽略了 %d 条对不上域名的附加设置", stale))
		}
		if len(out) == 0 {
			out = nil // 空表和「没有这张表」要当成同一件事，见 config.PruneDomainMeta
		}
		b.Config.DomainMeta = out
	}

	// DDNS 四项 + v6 段链接：能归一化的归一化，明显填错的就**整项丢掉并
	// 提示**。丢掉等于「保持当前值」，比按一个猜出来的数写进去安全——用户
	// 手改文件时打错一位，不该变成解析记录里一个奇怪的数字。
	if b.Config.DDNSTTL != nil {
		if v := *b.Config.DDNSTTL; v != 0 && (v < 60 || v > 86400) {
			warns = append(warns, fmt.Sprintf(
				"TTL 填的是 %d 秒，只接受 0（各家默认）或 60~86400，这一项已忽略（保持当前设置）", v))
			b.Config.DDNSTTL = nil
		}
	}
	if b.Config.DDNSIPCount != nil {
		if v := *b.Config.DDNSIPCount; v < 0 || v > 20 {
			warns = append(warns, fmt.Sprintf(
				"「同步几条 IP」填的是 %d，只接受 1~20，这一项已忽略（保持当前设置）", v))
			b.Config.DDNSIPCount = nil
		}
	}
	if b.Config.DDNSRecordType != nil {
		// 和保存配置时一样只认 A / AAAA / A+AAAA，但这里不整单退回：
		// 一个字段写坏就把整份备份拒掉，用户手里那台机器就还是空白的。
		if m, err := ddns.NormalizeRecordMode(*b.Config.DDNSRecordType); err != nil {
			warns = append(warns, fmt.Sprintf(
				"记录类型 %q 不认识（只有 A / AAAA / %s），这一项已忽略（保持当前设置）",
				*b.Config.DDNSRecordType, ddns.ModeBoth))
			b.Config.DDNSRecordType = nil
		} else {
			b.Config.DDNSRecordType = &m
		}
	}
	if b.Config.IPv6ProbeURL != nil {
		lines, err := parseV6SourceInput(*b.Config.IPv6ProbeURL)
		if err != nil {
			warns = append(warns, err.Error()+"，这一项已忽略（保持当前设置）")
			b.Config.IPv6ProbeURL = nil
		} else {
			joined := strings.Join(lines, "\n")
			b.Config.IPv6ProbeURL = &joined
		}
	}
	if b.Config.HostsSource != nil {
		lines, err := parseSourceURLLines(*b.Config.HostsSource, "hosts 源链接")
		if err != nil {
			warns = append(warns, err.Error()+"，这一项已忽略（保持当前设置）")
			b.Config.HostsSource = nil
		} else {
			joined := strings.Join(lines, "\n")
			b.Config.HostsSource = &joined
		}
	}
	// hosts 账本：域名归一化，IP 必须真能解析。
	//
	// 这里的校验比对 RewrittenDomains 更硬一点是必要的：账本里的 IP 会被原样
	// 写进 AdGuard 的重写答案，一个手改出来的乱码地址不会报错，只会变成一条
	// 把域名指到黑洞的记录，表现是「某几个网站突然打不开」。
	if len(b.Config.HostsEntries) > 0 {
		out := make(map[string]string, len(b.Config.HostsEntries))
		dropped := 0
		for k, v := range b.Config.HostsEntries {
			d := config.NormalizeDomain(k)
			v = strings.TrimSpace(v)
			if !plausibleHostname(d) || net.ParseIP(v) == nil || len(out) >= maxHostsEntries {
				dropped++
				continue
			}
			out[d] = v
		}
		if dropped > 0 {
			warns = append(warns, fmt.Sprintf(
				"hosts 账本里有 %d 条看不懂或超出上限，已忽略", dropped))
		}
		if len(out) == 0 {
			out = nil
		}
		b.Config.HostsEntries = out
	}

	// 密钥白名单：不在表里的 key 直接丢掉并提示，别静默吞了。
	if len(b.Secrets) > 0 {
		kept := make(map[string]string, len(b.Secrets))
		var dropped []string
		for k, v := range b.Secrets {
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			if !allowedSecretKeys[k] {
				dropped = append(dropped, k)
				continue
			}
			kept[k] = v
		}
		if len(dropped) > 0 {
			warns = append(warns, "忽略了不认识的密钥项 "+strings.Join(dropped, "、"))
		}
		b.Secrets = kept
	}

	return b, warns, nil
}

// handleExport 把当前设置（含密钥）打包成一个文件返回。
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	cfg := s.cfg.Clone()
	s.mu.Unlock()

	now := time.Now()
	b := buildBundle(cfg, config.DDNCredentials(), version, now)
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "生成备份文件失败: " + friendlyErr(err)})
		return
	}

	name := "cf-ddns-sidecar-" + now.Format("20060102-150405") + ".json"
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	// 里面是明文密钥，绝不能被中间代理或浏览器缓存住。
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

// handleImport 用上传的文件覆盖当前设置。
func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBundleBytes+1))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "读取上传内容失败: " + friendlyErr(err)})
		return
	}
	if len(raw) > maxBundleBytes {
		writeJSON(w, 400, map[string]string{"error": "文件太大了（正常备份只有几 KB）"})
		return
	}

	b, warns, err := parseBundle(raw)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}

	s.mu.Lock()
	cfg := s.cfg.Clone()
	s.mu.Unlock()

	// 记两本账：文件里有、已按文件覆盖的（restored），和文件里没有、保持了
	// 当前值的（kept）。
	//
	// 为什么要把它返回给界面：v1.7.4 之前的备份文件里没有「记录类型」等六项，
	// 导入时它们只能保持原值——但用户看到的原本只有一句「已恢复」。不说出来，
	// 他会以为一切都回来了，过几天才发现解析里只剩 IPv4，而那时早就想不起
	// 是恢复备份导致的。这类「静默少了一部分」正是这个项目吃过最多的亏。
	restored := make([]string, 0, 16)
	kept := make([]string, 0, 6)
	note := func(label string, present bool) {
		if present {
			restored = append(restored, label)
			return
		}
		kept = append(kept, label)
	}

	cfg.AdGuard.URL = strings.TrimSpace(b.Config.AdGuardURL)
	cfg.AdGuard.Username = strings.TrimSpace(b.Config.AdGuardUsername)
	note("AdGuard 地址与账号", true)
	// 备份里没有 AdGuard 密码时保持原值，别把已存的密码清空。
	if b.Config.AdGuardPassword != "" {
		cfg.AdGuard.Password = b.Config.AdGuardPassword
	}
	note("AdGuard 密码", b.Config.AdGuardPassword != "")

	cfg.Domains = b.Config.Domains
	note("要加速的域名列表", true)
	// 域名的附加信息（是否包含子域、添加时间）。用 nil 判断「文件里没有这一
	// 项」：老文件里没有它，此时保留当前值，不能顺手清空。
	if b.Config.DomainMeta != nil {
		cfg.DomainMeta = b.Config.DomainMeta
	}
	note("域名后面的「包含子域」标记", b.Config.DomainMeta != nil)
	// 列表被整体换掉了，元信息必须跟着对齐：残留的条目会让「删掉再加回来」
	// 的域名继承上一次的勾选。
	cfg.PruneDomainMeta()

	// 账本（本工具在 AdGuard 上认领过哪些域名）**不进 restored / kept 两本账**：
	// 它不是用户设的项，界面上列出来只会让人问「这是啥」。但文件里有它时要用，
	// 否则换机恢复之后，已经不在这份清单里的域名会在 AdGuard 上留下永久残留，
	// 指向换机前的旧 IP。文件里没有（老备份）就保持当前值，别清空。
	if len(b.Config.RewrittenDomains) > 0 {
		cfg.RewrittenDomains = b.Config.RewrittenDomains
	}

	cfg.Speed.TopN = b.Config.TopN
	note("保留候选 IP 数", true)
	cfg.Speed.BandwidthCandidates = b.Config.Candidates
	note("带宽测速候选数", true)
	cfg.Speed.IntervalMinutes = b.Config.IntervalMinutes
	note("测速间隔", true)
	// ExtraSources / EngineOverrides 用 nil 判断「文件里没有这一项」：
	// 老版本导出的文件里没有这两个字段，此时保留当前值，不能顺手清空。
	if b.Config.ExtraSources != nil {
		cfg.Speed.ExtraSources = b.Config.ExtraSources
	}
	note("优选 IP 段", b.Config.ExtraSources != nil)
	if b.Config.EngineOverrides != nil {
		cfg.Speed.EngineOverrides = engine.NormalizeOverrides(b.Config.EngineOverrides)
	}
	note("高级设置里的引擎参数", b.Config.EngineOverrides != nil)
	if b.Config.IPv6ProbeURL != nil {
		cfg.IPv6ProbeURL = *b.Config.IPv6ProbeURL
	}
	note("IPv6 段链接", b.Config.IPv6ProbeURL != nil)
	// hosts 源那一块。用 nil 判断「文件里没有这一项」：老备份里没有它，此时
	// 保持当前值，不能顺手把用户打开的开关关掉、把链接清空。
	if b.Config.HostsEnabled != nil {
		cfg.HostsEnabled = *b.Config.HostsEnabled
	}
	note("GitHub hosts 源开关", b.Config.HostsEnabled != nil)
	if b.Config.HostsSource != nil {
		cfg.HostsSource = *b.Config.HostsSource
	}
	note("GitHub hosts 源链接", b.Config.HostsSource != nil)
	// 账本同 RewrittenDomains：不进 restored / kept（它不是用户设的项），
	// 但文件里有就得用——否则换机恢复之后，源里已经没有的那些域名会在
	// AdGuard 上留下永久残留。文件里没有（老备份）就保持当前值。
	if len(b.Config.HostsEntries) > 0 {
		cfg.HostsEntries = b.Config.HostsEntries
	}

	cfg.DDNS.Enabled = b.Config.DDNSEnabled
	cfg.DDNS.Provider = b.Config.DDNSProvider
	cfg.DDNS.Domain = b.Config.DDNSDomain
	note("DDNS 设置（开关/服务商/优选域名）", true)
	if b.Config.DDNSTTL != nil {
		cfg.DDNS.TTL = *b.Config.DDNSTTL
	}
	note("TTL", b.Config.DDNSTTL != nil)
	if b.Config.DDNSProxied != nil {
		cfg.DDNS.Proxied = *b.Config.DDNSProxied
	}
	note("Cloudflare 代理开关", b.Config.DDNSProxied != nil)
	if b.Config.DDNSIPCount != nil {
		cfg.DDNS.IPCount = *b.Config.DDNSIPCount
	}
	note("同步几条 IP", b.Config.DDNSIPCount != nil)
	if b.Config.DDNSRecordType != nil {
		cfg.DDNS.RecordType = *b.Config.DDNSRecordType
	}
	note("记录类型（A / AAAA / A+AAAA）", b.Config.DDNSRecordType != nil)

	if cfg.DDNS.Provider == "" {
		cfg.DDNS.Provider = "cloudflare"
	}

	if err := cfg.Save(); err != nil {
		writeJSON(w, 500, map[string]string{"error": "保存配置失败: " + friendlyErr(err)})
		return
	}

	// 密钥单独写：不覆盖备份里没有的项（比如这次只导出了 Cloudflare，
	// 原来的阿里云密钥应当留着，而不是被清空）。
	if len(b.Secrets) > 0 {
		if err := config.UpdateEnvFile(config.EnvFilePath(), b.Secrets); err != nil {
			warns = append(warns, "配置已恢复，但密钥写入失败: "+friendlyErr(err))
		}
	}

	s.mu.Lock()
	s.cfg = &cfg
	s.mu.Unlock()

	// 配置里的间隔/域名也要回写 ddns.env，和手动保存保持一致。
	if err := config.UpdateEnvFile(config.EnvFilePath(), map[string]string{
		"CFDDNS_PROVIDER":         cfg.DDNS.Provider,
		"CFDDNS_DOMAIN":           cfg.DDNS.Domain,
		"CFDDNS_INTERVAL_MINUTES": fmt.Sprint(cfg.Speed.IntervalMinutes),
	}); err != nil {
		warns = append(warns, "ddns.env 回写失败: "+friendlyErr(err))
	}

	// 恢复出来的间隔可能和原来不同，同样要把定时器叫醒重算。
	s.wakeScheduler()

	writeJSON(w, 200, map[string]any{
		"ok":       true,
		"warnings": warns,
		// restored / kept 不只是给界面看的日志：它们回答的是「这次恢复到底
		// 恢复了多少」。老备份文件里没有的项，一定要出现在 kept 里。
		"restored": restored,
		"kept":     kept,
	})
}
