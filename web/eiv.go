package web

// 「优选出来的 IP 会触发 Cloudflare 1034（边缘 IP 校验）」的预筛与实测。
//
// 1034 不是「这个 IP 慢」或「挂了」，而是 Cloudflare 判定「你连的这个边缘 IP 不属于这个
// 域名的账号」。官方的 EIV 专门守这类受限 IP 空间（BYOIP 段、企业独占/静态 IP、1.1.1.1
// 这类保留地址）。候选池里混进这种 IP，测速结果本身「一切正常」，用户却在浏览器里看到 1034。
//
// 两道防线，各管一半：
//
//  1. 官方段预筛（纯本地、零请求）。不在官方 15 个 IPv4 段里的 IP 直接丢，野 IP 和别人
//     的 BYOIP 段一刀切掉。这一步不联网，永远能做。
//  2. EIV 实测（一次请求）。剩下的仍可能是「官方段内、但被某个企业独占」的地址，只能
//     钉住候选 IP 请求 `https://<要加速的域名>/cdn-cgi/trace`，回 403 且正文里有
//     `error code: 1034` 就说明这个 IP 对那个域名是废的。这个路径在每个被 CF 接管的
//     域名上都存在，不用改用户的站。
//
// 按 /24 抽样而不是逐个探：受限空间是按块分配的，同一 /24 往往同属一份分配。逐个探 600
// 个 IP 要好几分钟，按 /24 通常只有几十次请求。结果落盘是为了下一轮不用重复问，又必须
// 过期：CF 的分配会变，永久拉黑会让候选池越用越少，最后「优选不出东西」。24 小时是个
// 折中，够短到能跟上变化，够长到一天里只付一次代价。

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/303528084/cf-ddns-sidecar/config"
)

const (
	// eivBlockTTL 是一条黑名单记录的有效期。见文件头「为什么必须过期」。
	eivBlockTTL = 24 * time.Hour
	// eivWorkers 是并发探测数。和 exitgeo 的 traceWorkers 保持同一个量级：
	// 再多也只是把 Cloudflare 那边压得更紧，本机带宽不是瓶颈。
	eivWorkers = 8
	// eivTimeout 是单次探测的超时。比 traceTimeout 宽松 1 秒：这一步的
	// 代价是「漏掉一个好 IP」，宁可多等。
	eivTimeout = 6 * time.Second
	// eivMaxGroups 是单轮最多探多少个 /24。候选池 600 条按 /24 归组通常
	// 只有几十组；这个上限是防「用户给的链接里全是零散 IP」把这一步拖成
	// 好几分钟。超出的组原样保留（不探 = 不判），并在日志里说明。
	eivMaxGroups = 160
	// eivBudget 是这一整步的总时长上限。
	//
	// 单个探测有 eivTimeout 兜着，但 160 组 × 2 个域名 × 6 秒 / 8 并发
	// 最坏能拖到 4 分钟，那是「每个 IP 都不通」的极端情况，而这一步只是
	// 测速前的准备，不该吃掉整轮的预算。到点就收工，没探的组原样保留
	// （不探 = 不判，宁可漏掉也不误杀）。
	eivBudget = 45 * time.Second
	// eivBlockFile 是黑名单文件名，放在数据目录里（和 config.json 同级）。
	//
	// 单独一个文件而不是塞进 config.json：它每轮都可能变，写进主配置会让
	// .bak 和升级备份跟着一起翻新，而它本身是可再生的缓存，丢了只是多探
	// 一次。所以它也不进 restoreFiles 白名单。
	eivBlockFile = "eiv-blocklist.json"
)

// eivBad 是一条「这个网段对某个域名会触发 1034」的记录。
type eivBad struct {
	CIDR   string `json:"cidr"`    // 网段，如 104.16.132.0/24
	Host   string `json:"host"`    // 拿哪个域名测出来的
	LastAt string `json:"last_at"` // RFC3339，判断是否过期
}

type eivBlocklist struct {
	Entries []eivBad `json:"entries"`
}

// officialV4Nets 把官方段编译成 IPNet，只做一次。
var officialV4Nets = func() []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cloudflareIPv4))
	for _, c := range cloudflareIPv4 {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// inOfficialV4 判断一个 IPv4 是否落在 Cloudflare 公布的共享段里。
//
// 只判 IPv4：候选池的 IPv6 不是我们生成的（内置采样只有 v4），贸然拿一份
// 手抄的 v6 段表去判，判错了会把用户能用的 v6 节点整片删掉。v6 交给 EIV
// 实测兜底，那一层是「问出来的」，不依赖任何段表。
func inOfficialV4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return true // 不是 IPv4，交给实测，不在这里判
	}
	for _, n := range officialV4Nets {
		if n.Contains(v4) {
			return true
		}
	}
	return false
}

// cidr24 把 IPv4 归到它所在的 /24，作为「同一块分配」的分组键。
// IPv6 各自成组（用完整地址当键），因为 v6 的分配粒度我们没有可靠依据。
func cidr24(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	}
	return ip.String()
}

// isEIVBlock 判断这次响应是不是「被边缘校验拦下」。
//
// 判据刻意收窄：必须**不是 200**，且正文里出现 1034 的错误码。放宽成
// 「正文里有 1034」会误杀，正常页面里带这个数字的太多了，而误杀的代价是
// 把一个好 IP 从候选里删掉，用户完全看不出来为什么速度变差了。
func isEIVBlock(status int, body string) bool {
	if status == http.StatusOK {
		return false
	}
	b := strings.ToLower(body)
	return strings.Contains(b, "error code: 1034") ||
		strings.Contains(b, "error code 1034") ||
		strings.Contains(b, `"error_code":1034`) ||
		strings.Contains(b, `"error_code": 1034`)
}

// eivProbe 钉住 ip 请求 host 的 /cdn-cgi/trace，返回状态码与正文。
//
// 和 exitgeo 的 traceVia 是同一套路子（DialContext 改写目标 + SNI 用 host），
// 但这里要读正文才能认出 1034，所以不能直接复用，那个函数把非 200 当失败
// 直接返回 error，正好会把我们要找的那个信号丢掉。
func eivProbe(ctx context.Context, host, ip string, port int) (status int, body string, err error) {
	dialer := &net.Dialer{Timeout: 4 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
		},
		TLSClientConfig:   &tls.Config{ServerName: host, InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Transport: tr,
		Timeout:   eivTimeout,
		// 不跟跳转：跟到别处就测不出这个 IP 的归属了。
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/cdn-cgi/trace", nil)
	if err != nil {
		return 0, "", err
	}
	req.Host = host

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(raw), nil
}

// eivProbeFunc 是探测函数的间接引用，只为了测试能把它换成桩。
//
// 单测里没法真去连 Cloudflare，而 screenCandidates 的剔除逻辑（按 /24 归组、
// 命中就整组丢、写黑名单）恰恰是最需要验的部分。留一个可替换的变量，比为了
// 测试把整个函数拆成三段要诚实得多。
var eivProbeFunc = eivProbe

// ---------- 黑名单的读写 ----------

func (b *eivBlocklist) prune(now time.Time) {
	kept := b.Entries[:0]
	for _, e := range b.Entries {
		if t, err := time.Parse(time.RFC3339, e.LastAt); err == nil && now.Sub(t) < eivBlockTTL {
			kept = append(kept, e)
		}
	}
	b.Entries = kept
}

// bad 判断这个网段是否已确认对**当前要探测的域名**会触发 1034。
//
// 必须带上域名一起比：EIV 是按 zone 判的，同一个 IP 对 openai.com 合法、
// 对自己的站可能被拦。只按网段查会让「换了个加速域名」的用户凭空少一堆
// 候选，而且完全看不出原因，那正是这次要消灭的那类静默故障。
func (b *eivBlocklist) bad(cidr string, hosts map[string]bool) bool {
	for _, e := range b.Entries {
		if e.CIDR == cidr && hosts[e.Host] {
			return true
		}
	}
	return false
}

func (b *eivBlocklist) mark(cidr, host string, now time.Time) {
	stamp := now.Format(time.RFC3339)
	for i := range b.Entries {
		if b.Entries[i].CIDR == cidr {
			b.Entries[i].LastAt = stamp
			b.Entries[i].Host = host
			return
		}
	}
	b.Entries = append(b.Entries, eivBad{CIDR: cidr, Host: host, LastAt: stamp})
}

func loadEIVBlocklist(path string) *eivBlocklist {
	b := &eivBlocklist{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return b
	}
	if err := json.Unmarshal(raw, b); err != nil {
		// 文件坏了就当空的：这是一份缓存，重建的代价只是多探一轮，
		// 而「因为缓存坏了导致测速起不来」是不可接受的。
		return &eivBlocklist{}
	}
	b.prune(time.Now())
	return b
}

func (b *eivBlocklist) save(path string) {
	b.prune(time.Now())
	raw, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return
	}
	// 先写临时文件再改名：写到一半断电不会留下半个 JSON，
	// 下次读到坏文件虽然能兜住，但没必要留这个坑。
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// ---------- 探哪些域名 ----------

// eivProbeHosts 决定「拿哪个域名去问归属」。
//
// 这件事必须用**用户实际要访问的域名**，不能用 cloudflare-ech.com：EIV 是
// 按 zone 判的，同一个 IP 对 A 域名合法、对 B 域名 1034。这也是现有反代验证
// 漏掉 1034 的根因，它问的是 cloudflare-ech.com，只证明了「这 IP 是活的
// 边缘节点」，没证明「它属于你的域名」。
//
// 取两个：用户自己的 Cloudflare 域名（且必须开着云朵，否则压根不过 CF）、
// 以及加速列表里的第一个域名（第三方站点那条路）。两个都测，任一报 1034
// 就算这个 IP 不行，用户实测两条路都会中。
func eivProbeHosts(cfg *config.Config) []string {
	var out []string
	seen := make(map[string]bool, 2)
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || seen[h] || len(out) >= 2 {
			return
		}
		// 只接受裸域名：带路径、端口、空格的写法拼进 URL 会变成另一个请求。
		if strings.ContainsAny(h, "/ :?#") {
			return
		}
		seen[h] = true
		out = append(out, h)
	}
	if cfg.DDNS.Enabled && strings.EqualFold(cfg.DDNS.Provider, "cloudflare") && cfg.DDNS.Proxied {
		add(cfg.DDNS.Domain)
	}
	if len(cfg.Domains) > 0 {
		add(cfg.Domains[0])
	}
	return out
}

// ---------- 主流程 ----------

// candLine 是候选列表里的一行，拆成「原样保留的文本」和「用来判断的 IP」。
type candLine struct {
	text string
	ip   net.IP
	port int
}

func parseCandLine(s string) candLine {
	c := candLine{text: s, port: 443}
	host := s
	if i := strings.IndexByte(host, '#'); i >= 0 {
		host = host[:i]
	}
	if h, p, ok := strings.Cut(host, ":"); ok {
		host = h
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 {
			c.port = n
		}
	}
	c.ip = net.ParseIP(host)
	return c
}

// screenCandidates 对候选列表做两道筛选，返回新的候选文本。
//
// 输入输出都是 `/api/candidates` 的正文格式（每行 `ip:port#国家`），中间
// 只删行、不改行，端口和国家标签原样保留，否则一个能用的节点会因为端口被
// 改写而变得不能用。
//
// 认不出的行原样放行：这一步的职责是「剔除确定有问题的」，不是「重新解析
// 用户的输入」。解析不了的东西留给引擎自己判断。
func (s *Server) screenCandidates(ctx context.Context, cfg *config.Config, text string) string {
	raw := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(raw) == 0 || (len(raw) == 1 && raw[0] == "") {
		return text
	}

	// ---- 第一道：官方段预筛 ----
	kept := make([]candLine, 0, len(raw))
	offRange := 0
	for _, line := range raw {
		if strings.TrimSpace(line) == "" {
			continue
		}
		c := parseCandLine(line)
		if c.ip != nil && !inOfficialV4(c.ip) {
			offRange++
			continue
		}
		kept = append(kept, c)
	}
	if offRange > 0 {
		s.appendLog(fmt.Sprintf(
			"候选预筛：剔除 %d 个不在 Cloudflare 官方段内的 IP（共 %d 个）——这类地址常见于 BYOIP 段，正是 1034 的来源",
			offRange, len(raw)))
	}

	// ---- 第二道：EIV 实测 ----
	hosts := eivProbeHosts(cfg)
	if len(hosts) == 0 {
		s.appendLog("归属校验：没有可用来判定的域名（需要开着云朵的自有域名，或已填要加速的域名），跳过 1034 实测")
		// 这句不能省：它是「这一轮候选还剩多少」的唯一交代。少了它，日志会
		// 停在「候选预筛：剔除 N 个」，用户以为后面还要发生什么。
		s.appendLog(fmt.Sprintf("候选池：筛选后剩 %d 条交给测速引擎", len(kept)))
		return rebuildCandidates(kept)
	}
	if len(kept) == 0 {
		s.appendLog("候选池：筛选后剩 0 条交给测速引擎")
		return ""
	}

	// 按 /24 归组，组内顺序保持候选原顺序。
	groups := make(map[string][]int, len(kept))
	order := make([]string, 0, len(kept))
	for i, c := range kept {
		if c.ip == nil {
			continue
		}
		key := cidr24(c.ip)
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], i)
	}

	blPath := filepath.Join(filepath.Dir(s.configPath), eivBlockFile)
	bl := loadEIVBlocklist(blPath)

	hostSet := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		hostSet[h] = true
	}

	// 已知有问题的网段直接整组丢，不再发请求。
	cached := 0
	drop := make(map[int]bool)
	for _, key := range order {
		if bl.bad(key, hostSet) {
			cached++
			for _, idx := range groups[key] {
				drop[idx] = true
			}
		}
	}

	// 剩下的按顺序探，超过上限的组不探（保留）。
	probeKeys := make([]string, 0, len(order))
	for _, key := range order {
		if bl.bad(key, hostSet) {
			continue
		}
		if len(probeKeys) >= eivMaxGroups {
			break
		}
		probeKeys = append(probeKeys, key)
	}

	// 整步的总时长上限。到点后还没开始的组直接算「没来得及校验」，
	// 正在跑的那几个会随 pctx 一起被打断。
	pctx, pcancel := context.WithTimeout(ctx, eivBudget)
	defer pcancel()

	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		blocked = 0
		unknown = 0
		skipped = 0
		newBad  []eivBad
		sem     = make(chan struct{}, eivWorkers)
	)
	for _, key := range probeKeys {
		wg.Add(1)
		go func(key string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if pctx.Err() != nil {
				mu.Lock()
				skipped++
				mu.Unlock()
				return
			}

			// 组内只探第一个：同一 /24 是同一份分配，抽一个代表全组。
			idx := groups[key][0]
			c := kept[idx]
			hitHost := ""
			answered := 0 // 有几个域名真的回了话（回了话才谈得上判断）
			for _, h := range hosts {
				cctx, cancel := context.WithTimeout(pctx, eivTimeout)
				status, body, err := eivProbeFunc(cctx, h, c.ip.String(), c.port)
				cancel()
				if err != nil {
					continue
				}
				answered++
				if isEIVBlock(status, body) {
					hitHost = h
					break
				}
			}
			if hitHost == "" {
				// 一个都没回话 = 没做判断，不能当成「干净」，但也别声张成
				// 剔除，用户会以为这些 IP 有问题。
				if answered == 0 {
					mu.Lock()
					unknown++
					mu.Unlock()
				}
				return
			}
			mu.Lock()
			blocked++
			newBad = append(newBad, eivBad{CIDR: key, Host: hitHost, LastAt: time.Now().Format(time.RFC3339)})
			mu.Unlock()
		}(key)
	}
	wg.Wait()

	// 探测期间可能有别的组已经记过同一个网段（不会：一个 key 只探一次），
	// 但黑名单里可能已有同网段的旧记录，mark 会覆盖时间戳，这里统一写回。
	now := time.Now()
	for _, e := range newBad {
		bl.mark(e.CIDR, e.Host, now)
		for _, idx := range groups[e.CIDR] {
			drop[idx] = true
		}
	}
	if blocked > 0 || cached > 0 {
		bl.save(blPath)
	}

	out := make([]candLine, 0, len(kept))
	for i, c := range kept {
		if drop[i] {
			continue
		}
		out = append(out, c)
	}

	// 日志：说清「探了多少、为什么丢、还剩多少」。用户下一步要判断的是
	// 「这功能是不是在干活」，所以数字必须给。
	parts := make([]string, 0, 3)
	if blocked > 0 {
		parts = append(parts, fmt.Sprintf("本轮实测剔除 %d 个网段（对 %s 返回 1034）",
			blocked, strings.Join(hosts, " / ")))
	}
	if cached > 0 {
		parts = append(parts, fmt.Sprintf("另有 %d 个网段在 24 小时内已确认，直接跳过", cached))
	}
	if unknown > 0 {
		parts = append(parts, fmt.Sprintf("%d 个网段探测超时/连不上，未做判断", unknown))
	}
	if left := len(order) - len(probeKeys) - cached; left > 0 {
		parts = append(parts, fmt.Sprintf("还有 %d 个网段超出本轮上限未校验", left))
	}
	if skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d 个网段本轮没来得及校验（超过 %s 预算）",
			skipped, eivBudget))
	}
	if len(parts) == 0 {
		s.appendLog(fmt.Sprintf("归属校验：探了 %d 个网段，没有发现 1034", len(probeKeys)))
	} else {
		s.appendLog("归属校验：" + strings.Join(parts, "；"))
	}
	s.appendLog(fmt.Sprintf("候选池：筛选后剩 %d 条交给测速引擎", len(out)))
	return rebuildCandidates(out)
}

func rebuildCandidates(lines []candLine) string {
	if len(lines) == 0 {
		return ""
	}
	var b strings.Builder
	for _, c := range lines {
		b.WriteString(c.text)
		b.WriteByte('\n')
	}
	return b.String()
}
