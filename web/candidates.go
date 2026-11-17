package web

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"

	"github.com/303528084/cf-ddns-sidecar/config"
)

// cloudflareIPv4 是 Cloudflare 官方公布的 IPv4 地址段（https://www.cloudflare.com/ips-v4）。
// 内置一份快照，用于在外部数据源不可达时本地生成候选 IP —— 这是本产品
// 「测速一定能出结果」的兜底：不依赖任何第三方列表，随机采样官方段即可。
//
// 但兜底也有副作用：官方这 15 个段里 104.16/104.24/172.64 三块占了绝大多数，
// 平均配额之后，优选结果会明显往这几段集中。用户 2026-11-17 报的「优选出来
// 都是同一批段」就是这个原因。要跳出这个范围只能用 SpeedConfig.ExtraSources。
var cloudflareIPv4 = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

// extraSources 是解析之后的用户自定义来源，四类分开存。
type extraSources struct {
	cidrs []string // 已校验的 IP 段
	ips   []string // 已校验的单 IP（不含端口）
	// nodes 是「已经写全了」的节点：IP:端口#国家。
	// 和 ips 分开存，是为了不丢掉用户（或链接）明确给出的端口和国家标签
	// ——下游统一按 `ip:443#US` 输出，端口被改写会让一个能用的节点变不能用。
	nodes []string
	urls  []string // http(s) 链接，由本程序下载后当文本解析
}

// parseExtraSources 解析后台里填的「优选 IP 段」。
//
// 每行一条，空行与 `#` 开头的行当注释跳过。任何一行看不懂就**整体报错并
// 指明第几行** —— 静默忽略是最坏的处理方式：用户会以为设置生效了，测出来
// 还是原来那些段，然后怀疑「这个功能根本没用」。
func parseExtraSources(lines []string) (extraSources, error) {
	var out extraSources
	seen := make(map[string]bool, len(lines))

	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)

		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			if !seen["u:"+lower] {
				seen["u:"+lower] = true
				out.urls = append(out.urls, line)
			}
			continue
		}

		if strings.Contains(line, "/") {
			_, n, err := net.ParseCIDR(line)
			if err != nil {
				return out, fmt.Errorf(
					"第 %d 行「%s」不是合法的 IP 段，正确写法例如 104.16.0.0/13", i+1, line)
			}
			// /32 就是个单 IP，归到单 IP 去——采样时位宽为 0 会把它当空段跳掉。
			if ones, bits := n.Mask.Size(); bits-ones == 0 {
				if ip := n.IP.To4(); ip != nil && !seen["i:"+ip.String()] {
					seen["i:"+ip.String()] = true
					out.ips = append(out.ips, ip.String())
				}
				continue
			}
			if !seen["c:"+line] {
				seen["c:"+line] = true
				out.cidrs = append(out.cidrs, line)
			}
			continue
		}

		// 1.2.3.4 / 1.2.3.4:443 / 1.2.3.4:8443#JP 三种都认。
		// 带端口的一律保留原端口：cfnb 默认只保留 443，把它改写成 443
		// 会让用户明确给出的非 443 节点在下一轮被过滤掉。
		if m := nodeTokenRe.FindStringSubmatch(line); m != nil {
			if ip := net.ParseIP(m[1]); ip != nil && ip.To4() != nil && validPort(m[2]) {
				if m[2] == "" && m[3] == "" {
					if !seen["i:"+m[1]] {
						seen["i:"+m[1]] = true
						out.ips = append(out.ips, m[1])
					}
					continue
				}
				port, cc := m[2], m[3]
				if port == "" {
					port = "443"
				}
				if cc == "" {
					cc = "US"
				}
				node := m[1] + ":" + port + "#" + cc
				if !seen["n:"+node] {
					seen["n:"+node] = true
					out.nodes = append(out.nodes, node)
				}
				continue
			}
		}

		return out, fmt.Errorf(
			"第 %d 行「%s」既不是 IP、也不是 IP 段、也不是链接。"+
				"单个 IP 写成 1.2.3.4（可带端口如 1.2.3.4:8443），"+
				"IP 段写成 1.2.3.0/24", i+1, line)
	}
	return out, nil
}

// cidrEntry 是一段 CIDR 展开后的采样信息：起始值 + 主机位数量。
type cidrEntry struct {
	base uint32
	bits int
}

// sampleFromCIDRs 从给定段里随机采样 count 个 IP，输出 `ip:443#US`。
//
// 为什么随机采样而不是顺序取：同一 /24 内的 IP 往往落在同一台边缘设备上，
// 顺序取会让候选高度集中，测出来的「最优」只是这一小块的局部最优。
// 随机采样能覆盖更多段和更多机房。
func sampleFromCIDRs(cidrs []string, count int) []string {
	if count <= 0 {
		count = 600
	}

	var list []cidrEntry
	for _, s := range cidrs {
		_, n, err := net.ParseCIDR(strings.TrimSpace(s))
		if err != nil {
			continue
		}
		ip4 := n.IP.To4()
		if ip4 == nil {
			continue
		}
		ones, _ := n.Mask.Size()
		list = append(list, cidrEntry{
			base: binary.BigEndian.Uint32(ip4),
			bits: 32 - ones, // 主机位数量
		})
	}
	if len(list) == 0 {
		return nil
	}

	seen := make(map[uint32]bool, count)
	out := make([]string, 0, count)

	// 每个段分配大约相等的配额，保证覆盖广度
	perCIDR := count / len(list)
	if perCIDR < 4 {
		perCIDR = 4
	}

	for _, c := range list {
		size := uint32(1) << uint(c.bits)
		if size <= 1 {
			continue
		}
		for i := 0; i < perCIDR; i++ {
			v := c.base + rand.Uint32()%size
			// 去掉网络地址与广播地址
			if v == c.base || v == c.base+size-1 {
				continue
			}
			if seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, uint32ToIP(v)+":443#US")
		}
	}

	// 配额没凑够时再补一轮
	for i := 0; i < 3 && len(out) < count; i++ {
		c := list[rand.Intn(len(list))]
		size := uint32(1) << uint(c.bits)
		v := c.base + rand.Uint32()%size
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, uint32ToIP(v)+":443#US")
	}

	return out
}

// sampleFromSources 按「写全的节点 → 单 IP → 段里随机补足」的顺序生成候选。
//
// 前两类不抽样：那是用户（或他给的链接）明确点名的地址，抽样就等于随机丢掉
// 他想测的那个。同一个 IP 只出现一次，端口不同也算同一个 IP——重复测只是白花时间。
func sampleFromSources(src extraSources, count int) []string {
	if count <= 0 {
		count = 600
	}
	out := make([]string, 0, count)
	seen := make(map[string]bool, count)

	add := func(node string) bool {
		ip, _, _ := strings.Cut(node, ":")
		if ip == "" || seen[ip] {
			return false
		}
		seen[ip] = true
		out = append(out, node)
		return true
	}

	for _, node := range src.nodes {
		if len(out) >= count {
			return out
		}
		add(node)
	}
	for _, ip := range src.ips {
		if len(out) >= count {
			return out
		}
		add(ip + ":443#US")
	}

	rest := count - len(out)
	if rest <= 0 || len(src.cidrs) == 0 {
		return out
	}
	for _, item := range sampleFromCIDRs(src.cidrs, rest) {
		if len(out) >= count {
			break
		}
		add(item)
	}
	return out
}

// isEmpty 判断这批来源里有没有任何可用地址。
func (e extraSources) isEmpty() bool {
	return len(e.nodes) == 0 && len(e.ips) == 0 && len(e.cidrs) == 0
}

// candidatesText 把一批来源渲染成 /api/candidates 的响应正文（每行 `ip:port#国家`）。
func candidatesText(src extraSources, count int) string {
	var b strings.Builder
	for _, ip := range sampleFromSources(src, count) {
		b.WriteString(ip)
		b.WriteByte('\n')
	}
	return b.String()
}

func uint32ToIP(v uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return net.IP(b[:]).String()
}

// candidateList 返回用于测速的候选列表文本（每行 `ip:port#国家`）。
//
// 三种情形，语义必须清楚区分：
//  1. 用户没设置自定义来源 → 内置 Cloudflare 官方段（升级前行为，一字未改）；
//  2. 用户给了 IP 段/单 IP  → **只**从这些里采样；
//  3. 用户只给了链接       → 本地一个候选都不出，全部交给引擎去拉。
//     这一条最容易做错：若这里偷偷回落到官方段，用户就会看到「我填了链接，
//     结果测出来还是原来那些段」，而程序看起来一切正常。
func candidateList(cfg *config.Config, count int) string {
	var ips []string

	switch {
	case cfg == nil || len(cfg.Speed.ExtraSources) == 0:
		ips = sampleFromCIDRs(cloudflareIPv4, count)
	default:
		src, err := parseExtraSources(cfg.Speed.ExtraSources)
		if err != nil {
			// 保存时已经校验过，能走到这里的只有「config.json 被手工改坏」。
			// 这时宁可用内置段，也别返回空：返回空会让整轮测速一个候选都没有，
			// 用户看到的是「测速失败」，比「配置写错了」难判断得多。
			ips = sampleFromCIDRs(cloudflareIPv4, count)
		} else if len(src.cidrs) == 0 && len(src.ips) == 0 {
			ips = nil
		} else {
			ips = sampleFromSources(src, count)
		}
	}

	var b strings.Builder
	for _, ip := range ips {
		b.WriteString(ip)
		b.WriteByte('\n')
	}
	return b.String()
}

// atoiDefault 是 strconv.Atoi 的容错版本。
func atoiDefault(s string, def int) int {
	if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return v
	}
	return def
}
