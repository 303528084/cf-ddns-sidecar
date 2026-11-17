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
// /cdn-cgi/trace，读返回里的 loc（国家）与 colo（机房）。引擎在反代验证里
// 用的就是这个域名，能连上说明这条路在当前网络是通的。
const (
	traceHost    = "cloudflare-ech.com"
	tracePath    = "/cdn-cgi/trace"
	traceWorkers = 8
	traceTimeout = 5 * time.Second

	// exitBudget 是整行探测的总预算：一条请求最多 traceTimeout，8 个并发，
	// 而下面只探前 exitProbes 个 IP（一轮就跑完），所以最坏就是 traceTimeout。
	// 它排在测速完成之后、写 DNS 之前，多等这一下换来一行可信的解释，值。
	exitBudget = 8 * time.Second

	// exitProbes 为什么不探全部：日志把这一轮选出来的节点按质量排好列出来，
	// 用户看到的就是最前面那几个；后面的探了也没人看，却要多花好几轮时间。
	exitProbes = 5
)

// traceThroughIP 穿过指定 IP 取一次 trace，返回国家代码与机房代码。
func traceThroughIP(ctx context.Context, ip string, port int) (loc, colo string, err error) {
	return traceVia(ctx, traceHost, ip, port)
}

// traceVia 是 traceThroughIP 的本体，host 单独开一个参数只为可测：
// 单测里可以指向一个本地假服务器，不必真连 Cloudflare。
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
// 只探前 exitProbes 个：这一行的用途是让用户对「这些 IP 到底在哪儿」有个
// 可信的说法，不是做全量地理库。这些正是日志里排在最前面的那几条，所以
// 输出的序号和上面的列表一一对应（1 对 1、2 对 2）。
//
// 探不到的 IP 不会出现在返回的 map 里——查不到就说查不到，不编。
func (s *Server) logExitCountries(ctx context.Context, ips []string) map[string]string {
	colos := make(map[string]string, len(ips))
	n := len(ips)
	if n == 0 {
		return colos
	}
	if n > exitProbes {
		n = exitProbes
	}
	head := ips[:n]

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

			cctx, cancel := context.WithTimeout(ctx, traceTimeout)
			defer cancel()
			_, colo, err := traceThroughIP(cctx, ip, 443)
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
		s.appendLog("各节点实际出口：探测不到（连不上 " + traceHost + "，与测速结果无关）")
		return colos
	}
	s.appendLog("各节点实际出口（对应上面同样序号那一条）：" + strings.Join(results, "、"))
	return colos
}
