package web

// 「这个域名到底是不是走 Cloudflare 的边缘」，保存域名时用它拦一道。
//
// 本产品做的事是「把域名在局域网里改指向一个优选出来的 CF 边缘 IP」。如果那个域名
// 根本不走 Cloudflare，改指向之后浏览器连到的是一个不认识这个站点的节点，页面直接
// 打不开（1001 / 1034 那类错误），而用户很难想到是「域名压根没接 Cloudflare」。
//
// 判断分两层，先便宜后贵：
//
//	第一层：把域名解析成 IP，看落在不在 CF 公布的段里。走 CF 的域名（橙云）对外
//	        公布的 A 记录就是 CF 的边缘 IP，这一条足以回答，且不发 HTTPS 请求。
//	第二层：第一层说不走时再发一次 HEAD，看响应头有没有 `server: cloudflare` 或
//	        `cf-ray`。这层能兜住「手抄的段表过期了」和「解析出来是第三方 IP 但实际
//	        仍由 CF 边缘代理」。
//
// 两层都不认才拒绝。不用「NS 是不是 CF 的域名服务器」判断：NS 说的是「谁在管解析」，
// 和「请求会不会经过 CF 边缘」不是一回事。NS 在别处、用 CNAME 接到 CF 后面的站很常见，
// 用 NS 判会误杀；反过来 NS 在 CF 但只开灰云（DNS only）的站解析到源站 IP，改指向
// 边缘 IP 一样打不开，用 NS 判会误放。
//
// 第二层借鉴自 cf-dns-select 的 testCloudflareDomain（GPL-3.0，与本项目同许可，
// 见 third_party/cf-dns-select/README.md）。那边只做第二层、点按钮时查一个域名；
// 这里是保存时批量查，所以补了第一层、并发和「查不了」这第三种结果。

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// 单个域名的 DNS 查询上限。正常几十毫秒，3 秒还没回来基本就是不通了。
	domainLookupTimeout = 3 * time.Second
	// 单个域名的 HTTP 探测上限。和上游一致取 6 秒：它的 TLS + HTTP 两步是
	// 并行跑的，各 5 秒，整体兜底 6 秒。
	domainHTTPTimeout = 6 * time.Second
	// 一批域名的总上限。用户最多也就填几个，并行查，但整体封顶，
	// 免得「保存」按钮转半分钟没反应。
	domainBatchTimeout = 8 * time.Second
)

// cfV6Net 是 Cloudflare 的 IPv6 段。只写这一条：v4 段有十几条（见 eiv.go 的
// cloudflareIPv4），而 v6 对外服务的地址全部落在 2606:4700::/32 里，多抄几条只会多
// 几个抄错的机会。
var cfV6Net = func() *net.IPNet {
	_, n, err := net.ParseCIDR("2606:4700::/32")
	if err != nil {
		panic("Cloudflare 的 IPv6 段写错了: " + err.Error())
	}
	return n
}()

// isCloudflareIP 判断一个 IP 是否落在 Cloudflare 的段里。
// 和 eiv.go 的 inOfficialV4 有一处关键差别：那个遇到 IPv6 一律返回 true（不是 IPv4 就
// 放行，交给实测），因为要避免误删能用的 v6 节点。这里的结论是「拦下用户、不让他添加」，
// 方向正好相反，认不出来就得说「不是」，所以不能复用。
func isCloudflareIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		for _, n := range officialV4Nets {
			if n.Contains(v4) {
				return true
			}
		}
		return false
	}
	return cfV6Net.Contains(ip)
}

// DomainCheck 是一个域名的检查结果，直接作为接口返回值给界面用。
type DomainCheck struct {
	Domain string `json:"domain"`
	// OK 表示「确认走 Cloudflare 边缘」。序列化成 `passed` 而不是 `ok`：响应里已经有一个
	// `ok`（表示这次请求本身成功），混在一起前端分不清是哪一个。
	OK bool `json:"passed"`
	// Unknown 表示「没查出来」：DNS 超时、网络不通。它和 OK=false 必须分开：后者是
	// 「查清楚了，不是 Cloudflare」，可以据此拒存；Unknown 是「我们没本事判断」，这种
	// 情况下把人家的域名悄悄删掉是最糟的选择。
	Unknown bool `json:"unknown"`
	// IPs 是解析出来的地址，界面上要显示给用户看（「解析到 220.181.38.148，不是
	// Cloudflare 的段」比「不是 Cloudflare」有用得多）。
	IPs []string `json:"ips,omitempty"`
	// Colo 是从响应头 cf-ray 尾部取到的机房三字码（如 NRT / LAX / FRA），只在第二层
	// 拿到时才有值。
	Colo string `json:"colo,omitempty"`
	// Reason 是一句给用户看的中文说明。
	Reason string `json:"reason"`
}

// lookupIPFunc 是解析函数的间接引用，只为测试能换成桩：单测里不能真去查 DNS（CI 上
// 不一定有网络），而这里最需要验的恰恰是「哪些该拒、哪些该放过」。
var lookupIPFunc = func(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// probeHeadersFunc 是第二层探测的间接引用，同样只为测试能换桩。
var probeHeadersFunc = probeCloudflareHeaders

// probeCloudflareHeaders 发一次 HEAD 请求，看响应头里有没有 Cloudflare 的痕迹。
// 返回 (isCF, colo, err)。判断依据取自 cf-dns-select：`server: cloudflare` 或存在
// `cf-ray` 头都算，两个都拿不到才算不是。用 HEAD 是因为只要响应头、不要正文。
func probeCloudflareHeaders(ctx context.Context, domain string) (bool, string, error) {
	ctx, cancel := context.WithTimeout(ctx, domainHTTPTimeout)
	defer cancel()

	client := &http.Client{
		// 跟到第 3 跳就不再跟：一个把 www 跳来跳去的站，跟到底也只是想看一眼
		// 最终响应头，跟太多跳纯属浪费。
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+domain, nil)
	if err != nil {
		return false, "", err
	}
	// 有些站会把非浏览器 UA 直接拒掉（403），那样就看不到 CF 的头了。
	// 用一段普通的桌面 Chrome UA，只为了拿到响应头，不做任何抓取。
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "+
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	// HEAD 正常没有正文，但有些服务端会硬塞一点，读掉好让连接能复用。
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	server := resp.Header.Get("server")
	cfRay := resp.Header.Get("cf-ray")
	if !strings.EqualFold(server, "cloudflare") && cfRay == "" {
		return false, "", nil
	}
	colo := ""
	// cf-ray 形如 `8a1b2c3d4e5f6a7b-FRA`，最后一段就是处理这次请求的机房。
	if i := strings.LastIndex(cfRay, "-"); i >= 0 && i+1 < len(cfRay) {
		colo = strings.ToUpper(cfRay[i+1:])
	}
	return true, colo, nil
}

// joinIPs 把解析到的地址拼成一句能塞进界面一行的话。
//
// 一个域名解析出四五条 A 记录很常见（CF 自己就会给两个），全列出来会把
// 那一行说明撑成三行。留前三条，剩下的只说个数。
func joinIPs(ips []string) string {
	if len(ips) <= 3 {
		return strings.Join(ips, " / ")
	}
	return strings.Join(ips[:3], " / ") + " 等 " + strconv.Itoa(len(ips)) + " 个"
}

// checkDomainEdge 查一个域名是不是走 Cloudflare 边缘。
func checkDomainEdge(ctx context.Context, domain string) DomainCheck {
	res := DomainCheck{Domain: domain}

	lookupCtx, cancel := context.WithTimeout(ctx, domainLookupTimeout)
	ips, lookupErr := lookupIPFunc(lookupCtx, domain)
	cancel()

	for _, ip := range ips {
		res.IPs = append(res.IPs, ip.String())
	}

	// 第一层：解析结果里有 Cloudflare 的 IP，直接下结论。
	if lookupErr == nil {
		for _, ip := range ips {
			if isCloudflareIP(ip) {
				res.OK = true
				res.Reason = "解析到 " + joinIPs(res.IPs) + "，是 Cloudflare 的边缘 IP"
				return res
			}
		}
	}

	// 域名根本解析不出来时不做第二层：HEAD 请求同样要靠 DNS，必然一起失败，
	// 白等 6 秒。这种情况归到「没验成」，不删用户的域名。
	if lookupErr != nil || len(ips) == 0 {
		res.Unknown = true
		if lookupErr != nil {
			res.Reason = "查不到这个域名的 IP（" + dnsErrText(lookupErr) + "），这次先按原样保留"
		} else {
			res.Reason = "这个域名没有解析到任何 IP，这次先按原样保留"
		}
		return res
	}

	// 第二层：解析到了 IP 但都不是 Cloudflare 的段。可能是我们的段表过期，
	// 也可能这个站确实由 Cloudflare 代理但解析结果落在别处，真发一次请求
	// 看响应头，比只看 IP 表可靠。
	isCF, colo, err := probeHeadersFunc(ctx, domain)
	if isCF {
		res.OK = true
		res.Colo = colo
		res.Reason = "解析到 " + joinIPs(res.IPs) + "，但实际由 Cloudflare 边缘提供服务"
		if colo != "" {
			res.Reason += "（机房 " + colo + "）"
		}
		return res
	}

	res.Reason = "解析到 " + joinIPs(res.IPs) + "，不在 Cloudflare 的 IP 段里 —— 这个域名没走 Cloudflare"
	if err != nil {
		res.Reason += "（另外试着访问了一次也没成功：" + httpErrText(err) + "）"
	}
	return res
}

// dnsErrText 把 net 包的 DNS 错误翻成一句人话。
//
// 原始错误形如 `lookup foo.com on 192.168.65.7:53: no such host`，直接摆给
// 用户看他也不知道该怎么办；这里只留「到底是不存在还是查不通」这个区别。
func dnsErrText(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "no such host"):
		return "这个域名不存在，或者拼错了"
	case strings.Contains(msg, "server misbehaving"),
		strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "i/o timeout"),
		strings.Contains(msg, "network is unreachable"):
		return "DNS 服务器没响应，可能是 NAS 的 DNS 暂时不通"
	case strings.Contains(msg, "deadline exceeded"):
		return "查询超时"
	}
	return msg
}

// httpErrText 把探测阶段的错误压短并翻成一句人话。完整错误里带着
// `Get "https://xxx": dial tcp 1.2.3.4:443: connect: connection refused` 这种内容，
// 对用户没有意义，只留最后一段原因；最常见的几种还要再翻一次，`EOF` 三个字母摆在
// 界面上等于什么都没说。
func httpErrText(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	// 不能只判 `msg == "EOF"`：真实错误被 url.Error 包过，形如 `Get "https://xxx": EOF`，
	// 按「以 EOF 结尾」判才接得住，`unexpected EOF` 也一并落在这一条里。
	case strings.HasSuffix(msg, "EOF"):
		return "连接被中断"
	case strings.Contains(msg, "connection reset"):
		return "连接被对方重置"
	case strings.Contains(msg, "deadline exceeded"):
		return "等太久没响应"
	}
	if i := strings.LastIndex(msg, ": "); i >= 0 && i+1 < len(msg) {
		return msg[i+2:]
	}
	return msg
}

// screenDomains 把用户提交的域名分成三类：确认走 Cloudflare 的、确认不走的、
// 查不了的。
//
// 并行查：串行的话 5 个域名最坏要等 40 秒（每个可能走到第二层），「保存」
// 按钮会像卡死一样。每个 goroutine 只写自己那一格，没有共享状态，不需要锁。
func screenDomains(ctx context.Context, domains []string) (kept []string, rejected, unknown []DomainCheck) {
	if len(domains) == 0 {
		// 返回空切片而不是 nil：config.Domains 存进 JSON 时要是 [] 而不是
		// null，界面上「一个域名都没有」和「这个字段不存在」才不会混。
		return []string{}, nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, domainBatchTimeout)
	defer cancel()

	results := make([]DomainCheck, len(domains))
	var wg sync.WaitGroup
	for i, d := range domains {
		wg.Add(1)
		go func(i int, d string) {
			defer wg.Done()
			results[i] = checkDomainEdge(ctx, d)
		}(i, d)
	}
	wg.Wait()

	kept = make([]string, 0, len(domains))
	for _, r := range results {
		switch {
		case r.OK:
			kept = append(kept, r.Domain)
		case r.Unknown:
			// 查不了不等于不是：保留，但界面上要说清楚「这一条没验过」。
			kept = append(kept, r.Domain)
			unknown = append(unknown, r)
		default:
			rejected = append(rejected, r)
		}
	}
	return kept, rejected, unknown
}
