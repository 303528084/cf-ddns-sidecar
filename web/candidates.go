package web

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
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

// cloudflareIPv6 是 Cloudflare 官方公布的 IPv6 段（https://www.cloudflare.com/ips-v6）。
// 官方只公布一条 /32，和 IPv4 那 15 条完全不同：v6 是 Anycast，
// 采样再广也很可能落在同一批边缘设备上——所以 v6 优选有没有意义要靠真机测，
// 不能凭"段多"想当然（见 docs/IPv6方案.md 第八节）。
var cloudflareIPv6 = []string{
	"2606:4700::/32",
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

// ipv6Prefix 存一段 v6 CIDR 采样所需的信息：网络前缀 16 字节、主机位数量。
const (
	// ipv6PerPrefix 是每个 v6 段采样的地址数。
	//
	// 以前是「总数 600 按段数平分」：用户填 97 个段时每段只剩 6 个，真机实测
	// 585 个候选里只有 30 个能完成 TCP 握手（约 5%）。参考项目 cf-dns-select
	// 每个 /48 撒约 540 个，同样的命中率下能捞出几百个可用节点——差距全在采样量。
	// 改成每段固定 30 个：97 段约 2900 候选，探测从约 1 分钟涨到 3 分钟左右。
	ipv6PerPrefix = 30

	// maxIPv6Candidates 是探测候选的总上限，防止用户填几百个段时把一次探测
	// 拖成十几分钟。超出时按段顺序截断（前面的段优先）。
	maxIPv6Candidates = 20000
)

// 和 v4 的 cidrEntry（uint32）分开——v6 主机位最多 128 位，uint32 装不下，
// 用 netip.Addr 的 As16() 拿到完整的 128 位再随机填。
type ipv6Prefix struct {
	base [16]byte
	bits int // 主机位数量（128 - ones）
}

// sampleFromIPv6CIDRs 每个 v6 段采样 perPrefix 个地址，输出 `[ipv6]:443#US`。
// 总条数 = perPrefix × 段数，超过 maxIPv6Candidates 时按段顺序截断。
//
// 为什么按段固定、不按总数平分：总量固定时段越多每段越少，用户填几十个段
// 就等于每段只测几个地址，命中率被稀释得很低（真机 97 段 → 每段 6 个 →
// 585 个候选只通 30 个）。按段固定后每个段都有足够的采样点。
//
// 方括号是硬要求：Go 的 parseOutput 用 net.SplitHostPort 拆 host/port，
// 裸写法 2606:4700::1:443 会因冒号过多拆不开，端口被并进地址（静默错误）。
// 引擎侧（main.py）已同步改成认 [v6]:port 形式。
func sampleFromIPv6CIDRs(cidrs []string, perPrefix int) []string {
	if perPrefix <= 0 {
		perPrefix = ipv6PerPrefix
	}
	var prefixes []ipv6Prefix
	for _, s := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil || !p.Addr().Is6() {
			continue
		}
		ones := p.Bits()
		bits := p.Addr().BitLen() // v6 恒为 128
		hostBits := bits - ones
		if hostBits < 2 { // 主机位太少（/127、/128）没有采样空间
			continue
		}
		a := p.Masked().Addr().As16()
		prefixes = append(prefixes, ipv6Prefix{base: a, bits: hostBits})
	}
	if len(prefixes) == 0 {
		return nil
	}

	total := perPrefix * len(prefixes)
	if total > maxIPv6Candidates {
		total = maxIPv6Candidates
	}
	seen := make(map[netip.Addr]bool, total)
	out := make([]string, 0, total)
	for _, p := range prefixes {
		got := 0
		// 每段抽满 perPrefix 个；撞到重复/全零地址就重抽。重抽次数封顶，
		// 免得 /126 这种只剩几个可用地址的小段原地打转。
		for tries := 0; tries < perPrefix*3 && got < perPrefix && len(out) < total; tries++ {
			addr := randomIPv6(p)
			if addr.IsUnspecified() || seen[addr] {
				continue
			}
			seen[addr] = true
			out = append(out, "["+addr.String()+"]:443#US")
			got++
		}
	}
	return out
}

// randomIPv6 在一段 v6 前缀里随机出一个地址：保留前缀字节，主机位随机填。
func randomIPv6(p ipv6Prefix) netip.Addr {
	var b [16]byte
	copy(b[:], p.base[:])
	hostBytes := p.bits / 8
	hostRem := p.bits % 8
	// 前缀长度总是 8 的倍数时（如 /32、/48、/64），只需随机填后面的整字节。
	for i := 16 - hostBytes; i < 16; i++ {
		b[i] = byte(rand.Intn(256))
	}
	if hostRem > 0 {
		// 非整字节的前缀：掩码掉高位，只随机低位（本项目用的 /32 不走这里，
		// 但留着让这个函数对任意 CIDR 都正确）。
		idx := 16 - hostBytes - 1
		mask := byte((1 << uint(hostRem)) - 1)
		b[idx] = (b[idx] &^ mask) | (byte(rand.Intn(256)) & mask)
	}
	return netip.AddrFrom16(b)
}

// parseIPv6CIDRs 从「外部链接下载到的正文」里挑出 IPv6 段。
//
// 和 parseExtraSources / addToken 是两条完全独立的解析路：那条只认 IPv4
// （net.ParseCIDR 之后还要求 To4() 非空），把 v6 段交过去会被静默丢掉，
// 用户就会看到「链接明明填了，探测还是只用那一个内置段」。
//
// 这里仍复用 tokenize 做宽容切分——用户贴的列表常混着中文说明、逗号、
// 分号和 # 注释；认不出的 token 只记下来做日志，不让整批作废。
// RFC 3849 的文档示例段 2001:db8::/32 直接排除：它不可能路由到 CF，
// 采样进去只是白花测速时间（真机 IPv6 阶段①就碰到过一次）。
func parseIPv6CIDRs(text string) (cidrs []string, skipped []string) {
	docPrefix := netip.MustParsePrefix("2001:db8::/32")
	seen := make(map[string]bool)
	for _, tok := range tokenize(text) {
		p, err := netip.ParsePrefix(tok)
		if err != nil || !p.Addr().Is6() || p.Overlaps(docPrefix) {
			if len(skipped) < 5 {
				skipped = append(skipped, tok)
			}
			continue
		}
		key := p.Masked().String()
		if seen[key] {
			continue
		}
		seen[key] = true
		cidrs = append(cidrs, key)
	}
	return cidrs, skipped
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
