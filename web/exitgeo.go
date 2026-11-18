package web

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 这一组做的是「这些 IP 的真实出口在哪儿」。
//
// 为什么需要它：候选列表里的 `#US` 不是引擎算出来的，是我们为了满足引擎的
// 解析格式填的占位值（引擎在「节点没有国家标签」时会去逐条探测，那一步既慢
// 又会把探测失败的节点直接丢掉，代价太大）。占位值只用于引擎内部的国家过滤，
// 而那个功能在本产品里是关掉的——所以它对结果没有任何影响，但原样显示出来
// 会让人以为「程序认为这些 IP 都在美国」，而实际出口可能在日本 NRT。
//
// 真实出口用引擎自己的同一套办法取得：**穿过这个 IP** 去请求 Cloudflare 的
// /cdn-cgi/trace，读返回里的 loc（国家）与 colo（机房）。主域名用测速同款
// speed.cloudflare.com——这批 IP 刚用它测过速、证明在当前网络连得上，问位置
// 的命中率最高；失败再换 cloudflare-ech.com 补一次，两个域名的边缘入口不同。
const (
	// traceHost 是问位置的主域名，和测速用的一样；这批 IP 刚证明连得上它。
	traceHost = "speed.cloudflare.com"
	// traceHostFallback 是备用域名：主域名失败时换它再试一次。
	traceHostFallback = "cloudflare-ech.com"
	tracePath         = "/cdn-cgi/trace"
	traceWorkers      = 8

	// traceTimeout 从 5 秒放宽到 8 秒：实测 5 秒时只有亚洲近端机房（SIN/CGK/
	// MNL）问得出来，欧美远端在 5 秒内握不完手就被掐断，一律显示位置未知。
	traceTimeout = 8 * time.Second
	// traceFallbackTimeout 是备用域名的超时，短一些：主域名已经失败，备用
	// 只是补一次机会（多用于主域名 SNI/证书被拦），不用再等满 8 秒。
	traceFallbackTimeout = 4 * time.Second
	// probeAttemptMax 是单个 IP 两次尝试的耗时上限，预算按它算。
	probeAttemptMax = traceTimeout + traceFallbackTimeout

	// exitProbesMax 是机房位置探测的硬上限。
	// 早期写死 5，是因为那时界面只显示 5 条；后来「保留候选 IP 数」可以调大，
	// 界面跟着变多，写死的 5 就让第 6 条往后全成了「位置未知」。
	// 现在探测条数跟着实际结果走，但必须有上限：每探一个都是一次真实外部
	// 请求，用户填 100 时不能真发 100 次、把测速后的等待拖成几分钟。
	// 20 覆盖常见的 10 / 15 / 20，再多只探前 20 并在日志里说明。
	exitProbesMax = 20
)

// exitProbePlan 算「这次探几个、给多久预算」。
// 探测条数 = 实际结果条数（结果已按「保留候选 IP 数」截好），封顶 exitProbesMax。
// 预算按并发轮数算：8 个并发一轮，每个 IP 最坏要先试主域名 8 秒、失败再试备用
// 4 秒（probeAttemptMax），再留 2 秒给建连和收尾。只在这一处算，调用方（超时）
// 和被调方（截断）才不会各算各的、再次对不上。
func exitProbePlan(total int) (probes int, budget time.Duration) {
	if total <= 0 {
		return 0, 0
	}
	probes = total
	if probes > exitProbesMax {
		probes = exitProbesMax
	}
	rounds := (probes + traceWorkers - 1) / traceWorkers
	return probes, time.Duration(rounds)*probeAttemptMax + 2*time.Second
}

// traceThroughIP 穿过指定 IP 取一次 trace，返回国家代码与机房代码。
//
// 先问主域名（测速同款，命中率最高）；失败再换备用域名补一次。两个域名各自
// 带独立超时：主域名用满 traceTimeout 才算失败，失败后备用只给 traceFallbackTimeout。
// 任一次成功就返回，两次都失败才把最后一次的错误交上去。
//
// hosts 参数只为测试可注入（验「主失败→备成功」「两次都失败」两条路径）；
// 正式调用固定传 traceHost / traceHostFallback。
func traceThroughIP(ctx context.Context, ip string, port int) (loc, colo string, err error) {
	return traceThroughHosts(ctx, ip, port, traceHost, traceHostFallback)
}

func traceThroughHosts(ctx context.Context, ip string, port int, mainHost, fbHost string) (loc, colo string, err error) {
	// 主域名：单独给 traceTimeout（8 秒）。
	mainCtx, cancelMain := context.WithTimeout(ctx, traceTimeout)
	loc, colo, err = traceVia(mainCtx, mainHost, ip, port)
	cancelMain()
	if err == nil {
		return loc, colo, nil
	}
	// 主域名失败（连不上、超时、返回里没 loc），换备用域名补一次，只给更短的
	// traceFallbackTimeout（4 秒）——它只是补漏，不值得再占满 8 秒。
	fbCtx, cancelFb := context.WithTimeout(ctx, traceFallbackTimeout)
	defer cancelFb()
	return traceVia(fbCtx, fbHost, ip, port)
}

// traceThrough 是实际探测入口。单独提出来是为了单测能换成假函数，
// 验证「到底探了几个 IP」不必真连 Cloudflare（本机容器连不上）。
var traceThrough = traceThroughIP

// traceVia 是探测本体：穿过 ip 建连，却拿 host 当 SNI 和 Host 头去问 trace。
// host 单独开一个参数有两个用处：一是主域名失败后换备用域名重试，二是单测里
// 指向本地假服务器，不必真连 Cloudflare。超时完全由传入 ctx 的 deadline 控制。
func traceVia(ctx context.Context, host, ip string, port int) (loc, colo string, err error) {
	dialer := &net.Dialer{Timeout: 4 * time.Second}
	tr := &http.Transport{
		// 关键：不管对方要连谁，一律连到这个候选 IP 上。
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
		},
		// 证书是 host 的，但我们连的是 IP，主机名对不上，只能跳过校验。
		// 这里只读一个「你在哪个机房」的公开信息，不传任何凭据，风险可控。
		// （引擎自己也是 ssl=False，做法一致。）
		TLSClientConfig:   &tls.Config{ServerName: host, InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{Transport: tr, Timeout: traceTimeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+tracePath, nil)
	if err != nil {
		return "", "", err
	}
	req.Host = host

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", "", err
	}
	return parseTrace(string(body))
}

// parseTrace 从 trace 的正文里取 loc / colo。
//
// 正文是形如 `key=value` 的一行一项，例如：
//
//	fl=xxx
//	h=cloudflare-ech.com
//	ip=172.64.229.246
//	loc=JP
//	colo=NRT
//
// 没拿到 loc 就当失败：只拿到 colo（甚至什么都没拿到）时说「这个 IP 在
// NRT」同样会误导人，而这一行的存在意义就是不误导。
func parseTrace(body string) (loc, colo string, err error) {
	for _, line := range strings.Split(body, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "loc":
			loc = strings.ToUpper(strings.TrimSpace(v))
		case "colo":
			colo = strings.ToUpper(strings.TrimSpace(v))
		}
	}
	if loc == "" {
		return "", "", fmt.Errorf("返回里没有 loc")
	}
	return loc, colo, nil
}

// exitInfo 是「这个节点落在哪儿」的一句话描述。
//
// 为什么用 colo（机房代码）而不是 loc（国家代码）：2026-11-17 实测了 6 个
// 优选 IP，返回的 loc **全部是 CN**——那是我们自己宽带出口的国家，不是节点的。
// 真正跟着 IP 变的是 colo：同一个网络下，不同 IP 分别落到 FRA / LAX / NRT。
// 所以「这个 IP 把我送进了哪个机房」才是能解释速度差异的那条事实。
func exitInfo(colo string) string {
	if colo == "" {
		return "位置未知"
	}
	if g, ok := coloGeo[colo]; ok {
		return g.country + "·" + g.city + "(" + colo + ")"
	}
	// 表里没有就老实说「位置未知」，只给代码。两百多个机房铺全没必要，
	// 而随手编一个国家比不给更糟。
	return "机房 " + colo + "（位置未知）"
}

// place 是机房代码到「国家 + 城市」的对照表。
//
// 只收常见的那批：Cloudflare 有 300 多个机房，而实际被优选到的就那十几个。
// 表里查不到时调用方会显示「位置未知」，不会瞎猜。
// 注意香港/台湾按国内口径写成「中国香港」「中国台湾」。
type place struct{ country, city string }

var coloGeo = map[string]place{
	// 亚洲
	"NRT": {"日本", "东京"}, "HND": {"日本", "东京"}, "KIX": {"日本", "大阪"},
	"ICN": {"韩国", "首尔"}, "HKG": {"中国香港", "香港"}, "TPE": {"中国台湾", "台北"},
	"SIN": {"新加坡", "新加坡"}, "BKK": {"泰国", "曼谷"}, "KUL": {"马来西亚", "吉隆坡"},
	"CGK": {"印度尼西亚", "雅加达"}, "MNL": {"菲律宾", "马尼拉"},
	"HAN": {"越南", "河内"}, "SGN": {"越南", "胡志明市"},
	"DEL": {"印度", "新德里"}, "BOM": {"印度", "孟买"}, "MAA": {"印度", "金奈"},
	"CMB": {"斯里兰卡", "科伦坡"}, "DAC": {"孟加拉国", "达卡"},
	"KTM": {"尼泊尔", "加德满都"}, "ISB": {"巴基斯坦", "伊斯兰堡"},
	"ALA": {"哈萨克斯坦", "阿拉木图"}, "TAS": {"乌兹别克斯坦", "塔什干"},

	// 北美
	"LAX": {"美国", "洛杉矶"}, "SJC": {"美国", "圣何塞"}, "SFO": {"美国", "旧金山"},
	"SEA": {"美国", "西雅图"}, "PDX": {"美国", "波特兰"}, "DEN": {"美国", "丹佛"},
	"ORD": {"美国", "芝加哥"}, "DFW": {"美国", "达拉斯"}, "IAH": {"美国", "休斯顿"},
	"IAD": {"美国", "华盛顿"}, "EWR": {"美国", "纽瓦克"}, "ATL": {"美国", "亚特兰大"},
	"MIA": {"美国", "迈阿密"}, "BOS": {"美国", "波士顿"}, "PHX": {"美国", "凤凰城"},
	"YYZ": {"加拿大", "多伦多"}, "YVR": {"加拿大", "温哥华"},
	"MEX": {"墨西哥", "墨西哥城"}, "PTY": {"巴拿马", "巴拿马城"},

	// 欧洲
	"FRA": {"德国", "法兰克福"}, "MUC": {"德国", "慕尼黑"}, "BER": {"德国", "柏林"},
	"DUS": {"德国", "杜塞尔多夫"}, "HAM": {"德国", "汉堡"},
	"AMS": {"荷兰", "阿姆斯特丹"}, "BRU": {"比利时", "布鲁塞尔"},
	"LHR": {"英国", "伦敦"}, "LGW": {"英国", "伦敦"}, "MAN": {"英国", "曼彻斯特"},
	"CDG": {"法国", "巴黎"}, "MRS": {"法国", "马赛"},
	"MAD": {"西班牙", "马德里"}, "BCN": {"西班牙", "巴塞罗那"},
	"LIS": {"葡萄牙", "里斯本"}, "FCO": {"意大利", "罗马"}, "MXP": {"意大利", "米兰"},
	"ZRH": {"瑞士", "苏黎世"}, "VIE": {"奥地利", "维也纳"},
	"ARN": {"瑞典", "斯德哥尔摩"}, "CPH": {"丹麦", "哥本哈根"}, "OSL": {"挪威", "奥斯陆"},
	"HEL": {"芬兰", "赫尔辛基"}, "WAW": {"波兰", "华沙"}, "PRG": {"捷克", "布拉格"},
	"BUD": {"匈牙利", "布达佩斯"}, "OTP": {"罗马尼亚", "布加勒斯特"},
	"SOF": {"保加利亚", "索非亚"}, "BEG": {"塞尔维亚", "贝尔格莱德"},
	"ATH": {"希腊", "雅典"}, "DUB": {"爱尔兰", "都柏林"},
	"IST": {"土耳其", "伊斯坦布尔"}, "SVO": {"俄罗斯", "莫斯科"},
	"DME": {"俄罗斯", "莫斯科"}, "LED": {"俄罗斯", "圣彼得堡"},

	// 大洋洲 / 中东 / 非洲 / 南美
	"SYD": {"澳大利亚", "悉尼"}, "MEL": {"澳大利亚", "墨尔本"},
	"BNE": {"澳大利亚", "布里斯班"}, "PER": {"澳大利亚", "珀斯"},
	"AKL": {"新西兰", "奥克兰"},
	"DXB": {"阿联酋", "迪拜"}, "TLV": {"以色列", "特拉维夫"},
	"RUH": {"沙特阿拉伯", "利雅得"}, "KWI": {"科威特", "科威特城"},
	"JNB": {"南非", "约翰内斯堡"}, "CPT": {"南非", "开普敦"},
	"LOS": {"尼日利亚", "拉各斯"}, "NBO": {"肯尼亚", "内罗毕"},
	"GRU": {"巴西", "圣保罗"}, "GIG": {"巴西", "里约热内卢"},
	"EZE": {"阿根廷", "布宜诺斯艾利斯"}, "SCL": {"智利", "圣地亚哥"},
	"LIM": {"秘鲁", "利马"}, "BOG": {"哥伦比亚", "波哥大"},
}

// logExitCountries 探测这一轮选出来的 IP 实际落在哪个机房，写一行日志，
// 并把「IP → 机房代码」的结果返回给调用方。
//
// 返回值是这次改造新加的：位置信息以前只写进日志（用户得自己去那一长行里
// 对序号），现在界面每个节点要显示「日本·东京 NRT」。同一次探测的结果
// 两处都要用，不能各探一遍——那是两倍的外部请求，还可能给出两个答案。
//
// 探几个由 exitProbePlan 决定：跟着实际结果条数走（界面有几条就探几条），
// 封顶 exitProbesMax。这些正是列表里排在最前面的那几条，所以输出的序号
// 和界面一一对应（1 对 1、2 对 2）。超出上限时写一行日志说明，不让后半段
// 突然变成「位置未知」却没人解释。
//
// 探不到的 IP 不会出现在返回的 map 里——查不到就说查不到，不编。
func (s *Server) logExitCountries(ctx context.Context, ips []string) map[string]string {
	return s.logExitColos(ctx, ips, "")
}

// logExitColos 是 logExitCountries 的带标签版本：tag 会插在日志开头。
//
// 为什么要多这个参数：v6 那一轮也要探机房位置（用户要求「IPv6 的真实机房
// 位置也展示出来」），而一次测速里 v4 先探、v6 后探，两行日志去掉标签是
// 一模一样的中文 —— 用户看到两条相同的「各节点实际出口」根本分不清哪条
// 对应哪张表。tag 传空串时输出和历史完全一致（v4 那条路径行为不变）。
func (s *Server) logExitColos(ctx context.Context, ips []string, tag string) map[string]string {
	colos := make(map[string]string, len(ips))
	n, _ := exitProbePlan(len(ips))
	if n == 0 {
		return colos
	}
	head := ips[:n]
	if len(ips) > n {
		s.appendLog(tag + fmt.Sprintf("机房位置只探前 %d 个（共 %d 个结果），其余显示位置未知", n, len(ips)))
	}

	results := make([]string, n)
	okCount := make([]bool, n)
	// 每个 goroutine 只写自己那个下标，所以不用加锁。
	probed := make([]string, n)
	var wg sync.WaitGroup
	sem := make(chan struct{}, traceWorkers)
	for i, ip := range head {
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// 单个 IP 的窗口 = 主域名 8 秒 + 备用 4 秒。若沿用 traceTimeout，
			// 主域名用满后备用就没时间了，重试形同虚设。
			cctx, cancel := context.WithTimeout(ctx, probeAttemptMax)
			defer cancel()
			_, colo, err := traceThrough(cctx, ip, 443)
			if err != nil {
				results[i] = fmt.Sprintf("%d. %s→探测不到", i+1, ip)
				return
			}
			okCount[i] = true
			probed[i] = colo
			results[i] = fmt.Sprintf("%d. %s→%s", i+1, ip, exitInfo(colo))
		}(i, ip)
	}
	wg.Wait()

	for i, ip := range head {
		if probed[i] != "" {
			colos[ip] = probed[i]
		}
	}

	known := 0
	for _, ok := range okCount {
		if ok {
			known++
		}
	}
	// 一个都没探到就只留一句结论，别把 5 条「探测不到」铺开——那既占地方，
	// 又像是出了问题（其实只是这个网络到那个域名不通，和测速结果无关）。
	if known == 0 {
		s.appendLog(tag + "各节点实际出口：探测不到（连不上 " + traceHost + "，与测速结果无关）")
		return colos
	}
	s.appendLog(tag + "各节点实际出口（对应上面同样序号那一条）：" + strings.Join(results, "、"))
	return colos
}
