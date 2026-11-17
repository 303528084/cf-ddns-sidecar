package web

import (
	"encoding/binary"
	"math/rand"
	"net"
	"strconv"
	"strings"
)

// cloudflareIPv4 是 Cloudflare 官方公布的 IPv4 地址段（https://www.cloudflare.com/ips-v4）。
// 内置一份快照，用于在外部数据源不可达时本地生成候选 IP —— 这是本产品
// 「测速一定能出结果」的兜底：不依赖任何第三方列表，随机采样官方段即可。
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

// sampleCandidateIPs 从 Cloudflare 官方段中随机采样 count 个 IP。
//
// 为什么随机采样而不是顺序取：同一 /24 内的 IP 往往落在同一台边缘设备上，
// 顺序取会让候选高度集中，测出来的「最优」只是这一小块的局部最优。
// 随机采样能覆盖更多段和更多机房。
func sampleCandidateIPs(count int) []string {
	if count <= 0 {
		count = 600
	}

	type cidr struct {
		base uint32
		bits int
	}
	var list []cidr
	for _, s := range cloudflareIPv4 {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		ip4 := n.IP.To4()
		if ip4 == nil {
			continue
		}
		ones, _ := n.Mask.Size()
		list = append(list, cidr{
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

func uint32ToIP(v uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return net.IP(b[:]).String()
}

// candidateList 返回用于测速的候选列表文本（每行 ip:port#国家）。
func candidateList(count int) string {
	ips := sampleCandidateIPs(count)
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
