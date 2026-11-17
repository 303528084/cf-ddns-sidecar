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

// exitInfo 是「哪个 IP 落在哪个机房」的一句话描述。
func exitInfo(loc, colo string) string {
	switch {
	case loc != "" && colo != "":
		return loc + "/" + colo
	case loc != "":
		return loc
	default:
		return "未知"
	}
}

// logExitCountries 探测这一轮选出来的 IP 实际落在哪个机房，并写一行日志。
//
// 只探前 exitProbes 个：这一行的用途是让用户对「这些 IP 到底在哪儿」有个
// 可信的说法，不是做全量地理库。并发拉高一点让这一批一次跑完，尽量不拖慢
// 紧接着的写 DNS。
func (s *Server) logExitCountries(ctx context.Context, ips []string) {
	n := len(ips)
	if n == 0 {
		return
	}
	if n > exitProbes {
		n = exitProbes
	}
	head := ips[:n]

	results := make([]string, n)
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
			loc, colo, err := traceThroughIP(cctx, ip, 443)
			if err != nil {
				results[i] = ip + "→未知"
				return
			}
			results[i] = ip + "→" + exitInfo(loc, colo)
		}(i, ip)
	}
	wg.Wait()

	known := 0
	for _, r := range results {
		if !strings.HasSuffix(r, "→未知") {
			known++
		}
	}
	// 括号里那半句是必须的：日志里那些 `#US` 就在上一屏，用户看到的第一反应
	// 就是「它把我这些 IP 全认成美国了」。不在这里挑明，等于让他带着一个
	// 错误的结论去怀疑测速结果。
	if known == 0 {
		s.appendLog("各节点实际出口：探测不到（连不上 " + traceHost +
			"，与测速结果无关；上面每行结尾的 #US 是占位值，不是真实位置）")
		return
	}
	s.appendLog("各节点实际出口（上面每行结尾的 #US 是占位值，不是真实位置）：" +
		strings.Join(results, "、"))
}
