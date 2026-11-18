package web

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// 这一组是「把链接当成另一份 IP 列表」用的正则。
//
// 为什么不由测速引擎去拉链接：cfnb 的解析器只认**单个 IP**
// （`1.2.3.4` / `1.2.3.4:443` / `1.2.3.4:443#US`），遇到 `104.16.0.0/13`
// 这种**段**一律 `continue` 丢掉。用户给的「高爆IP段.txt」正是段列表，
// 于是它拉到内容、解析出 0 节点，日志只说「数据源解析完成（0 节点）」，
// 看起来像地址失效，其实是格式没人认。2026-11-17 22:01 就是这个现象。
var (
	// 1.2.3.4 / 1.2.3.4:443 / 1.2.3.4:8443#JP
	nodeTokenRe = regexp.MustCompile(`^(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?(?:#(\S+))?$`)
	// 1.2.3.4-1.2.3.10（部分「IP 段」列表是这种连字符区间）
	rangeTokenRe = regexp.MustCompile(`^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$`)
)

// sourceStats 记录一次文本解析认出了什么、漏掉了什么。
//
// skipped 那几条不是调试信息的摆设：用户给的链接格式千奇百怪（有的混着中文
// 说明、有的是 base64 订阅、有的干脆是 404 网页），把「认不出的样子」打出来，
// 下一次就能直接判断是格式问题还是地址问题，不用再靠猜。
type sourceStats struct {
	ips, nodes, cidrs int
	skippedTotal      int
	skipped           []string
}

// commentRe 去掉注释：行首的 `#`，或者空白之后的 `#` 到最后。
//
// 不能简单地把 `#` 当分隔符：`1.2.3.4:443#US` 里的 `#` 是国家标签的一部分。
// 判据是「`#` 前面是不是空白或行首」，这样两种用法都照顾到了。
var commentRe = regexp.MustCompile(`(?m)(^|\s)#.*$`)

// tokenize 把一段文本切成候选 token。
//
// 分隔符要放宽：有的列表用逗号、有的用制表符、有的每行带中文说明。
// IP 是纯 ASCII，把说明文字当 token 切出来之后识别不了，会落进 skipped
// 被打印出来，比整行丢弃更容易发现格式变了。
func tokenize(text string) []string {
	text = commentRe.ReplaceAllString(text, " ")
	repl := strings.NewReplacer(
		",", " ", "，", " ", ";", " ", "；", " ", "|", " ", "\t", " ", "\r", " ", "\n", " ",
	)
	var out []string
	for _, f := range strings.Fields(repl.Replace(text)) {
		f = strings.Trim(f, `"'()[]<>{}=+`)
		if f == "" || strings.HasPrefix(f, "//") {
			continue
		}
		out = append(out, f)
	}
	return out
}

// validPort 校验端口；空串表示「没写」，视为合法。
func validPort(s string) bool {
	if s == "" {
		return true
	}
	p, err := strconv.Atoi(s)
	return err == nil && p > 0 && p <= 65535
}

// addToken 尝试把一个 token 认成一个地址，认出来返回 true。
//
// 宽容处理是刻意的：这里处理的是**外部文本**，不是用户手输的配置。外面多一行
// 说明文字就该跳过这一行，不能让整批来源作废（用户手输的那条路径仍然严格报错，
// 见 parseExtraSources）。
func addToken(out *extraSources, tok string) bool {
	if strings.Contains(tok, "/") {
		_, n, err := net.ParseCIDR(tok)
		if err != nil {
			return false
		}
		ip4 := n.IP.To4()
		if ip4 == nil {
			return false
		}
		if ones, bits := n.Mask.Size(); bits-ones == 0 {
			out.ips = append(out.ips, ip4.String())
			return true
		}
		out.cidrs = append(out.cidrs, tok)
		return true
	}

	if m := nodeTokenRe.FindStringSubmatch(tok); m != nil {
		ip := net.ParseIP(m[1])
		if ip == nil || ip.To4() == nil || !validPort(m[2]) {
			return false
		}
		if m[2] == "" && m[3] == "" {
			out.ips = append(out.ips, m[1])
			return true
		}
		port, cc := m[2], m[3]
		if port == "" {
			port = "443"
		}
		if cc == "" {
			cc = "US"
		}
		out.nodes = append(out.nodes, m[1]+":"+port+"#"+cc)
		return true
	}

	if m := rangeTokenRe.FindStringSubmatch(tok); m != nil {
		a, b := net.ParseIP(m[1]), net.ParseIP(m[2])
		if a == nil || b == nil || a.To4() == nil || b.To4() == nil {
			return false
		}
		lo := ipToUint32(a.To4())
		hi := ipToUint32(b.To4())
		if hi < lo || hi-lo >= 4096 {
			return false // 区间太大就当认不出，别一口气展开几十万个
		}
		for v := lo; v <= hi; v++ {
			out.ips = append(out.ips, uint32ToIP(v))
		}
		return true
	}
	return false
}

// parseSourceText 把下载到的文本解析成来源。
//
// 一个 token 都认不出时会再试一次「base64 解码后再解析」：订阅类链接
// （路径里带 /sub/ 的）相当一部分是把整份列表 base64 之后吐出来的。
func parseSourceText(text string) (extraSources, sourceStats) {
	var out extraSources
	st := parseInto(&out, text)
	if st.ips+st.nodes+st.cidrs == 0 {
		if decoded, ok := decodeBase64Blob(text); ok {
			var second extraSources
			st2 := parseInto(&second, decoded)
			if st2.ips+st2.nodes+st2.cidrs > 0 {
				return second, st2
			}
		}
	}
	return out, st
}

func parseInto(out *extraSources, text string) sourceStats {
	var st sourceStats
	for _, tok := range tokenize(text) {
		if !addToken(out, tok) {
			st.skippedTotal++
			if len(st.skipped) < 5 {
				st.skipped = append(st.skipped, tok)
			}
		}
	}
	st.ips, st.nodes, st.cidrs = len(out.ips), len(out.nodes), len(out.cidrs)
	return st
}

// decodeBase64Blob 尝试把整段文本当 base64 解开。
func decodeBase64Blob(s string) (string, bool) {
	flat := strings.Join(strings.Fields(s), "")
	if len(flat) < 32 {
		return "", false
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(flat); err == nil && strings.Contains(string(b), ".") {
			return string(b), true
		}
	}
	return "", false
}

// sourceHTTP 是下载外部列表用的客户端。
//
// 20 秒是整次请求的上限：用户可能填好几个链接，一个卡住不该把整轮测速拖死。
var sourceHTTP = &http.Client{Timeout: 20 * time.Second}

// fetchSourceText 下载一个链接的正文。
//
// 刻意**不请求 brotli**：Go 标准库不会解 br，请求了就会拿到二进制乱码
// （v1.5.2 之前 cfnb 正是这么踩的坑）。不设 Accept-Encoding 时 Go 会自己加
// gzip 并透明解压。内容里的 IP 是 ASCII，即便编码是 GBK 也不影响识别。
func fetchSourceText(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	// 部分站点会拦默认 UA，这里跟 cfnb 用同一个。
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36")

	resp, err := sourceHTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// mergeSources 把 src 并进 dst，按 IP 去重（同一个 IP 换个端口也只留一条）。
func mergeSources(dst *extraSources, src extraSources) {
	seenIP := make(map[string]bool, len(dst.ips)+len(dst.nodes))
	seenCidr := make(map[string]bool, len(dst.cidrs))
	for _, n := range dst.nodes {
		ip, _, _ := strings.Cut(n, ":")
		seenIP[ip] = true
	}
	for _, ip := range dst.ips {
		seenIP[ip] = true
	}
	for _, c := range dst.cidrs {
		seenCidr[c] = true
	}

	for _, n := range src.nodes {
		ip, _, _ := strings.Cut(n, ":")
		if !seenIP[ip] {
			seenIP[ip] = true
			dst.nodes = append(dst.nodes, n)
		}
	}
	for _, ip := range src.ips {
		if !seenIP[ip] {
			seenIP[ip] = true
			dst.ips = append(dst.ips, ip)
		}
	}
	for _, c := range src.cidrs {
		if !seenCidr[c] {
			seenCidr[c] = true
			dst.cidrs = append(dst.cidrs, c)
		}
	}
}

func ipToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}
