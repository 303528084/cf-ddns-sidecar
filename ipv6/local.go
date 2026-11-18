// Package ipv6 只读地找出本机「稳定的公网 IPv6 地址」，供后台显示。
//
// 现在是阶段①：只读取、只显示，不写任何解析记录、不碰 AdGuard。
// 目的只有一个——回答「这台机器到底有没有能用的公网 v6」，如果连地址都没有，
// 后面的 AAAA / 前缀巡检全都不用做。
//
// 为什么读 /proc/net/if_inet6 而不是问外部服务：
// 容器是 network_mode: host，和 NAS 共用网络栈，直接读内核维护的这个文件就能
// 看到所有网卡地址。不发外部请求、不需要任何依赖（只用标准库），也不会因为
// 机器上挂了全局代理而问出代理的地址。
//
// 为什么把 flags 原文留在结果里：
// 方案文档第五节特别提醒——IFA_F_TEMPORARY 与 IFA_F_SECONDARY 共用 0x01，
// 不同内核/发行版打印出来可能不一样，不能凭记忆写死。所以这里既按标准判据
// 过滤，也把每个地址的原始 flags 一起返回，让人能拿 `ip -6 addr` 对照真机核对。
package ipv6

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// ProcPath 是内核维护的 IPv6 地址表。它是只读的伪文件，不需要任何权限。
const ProcPath = "/proc/net/if_inet6"

// Candidate 是一条「合格」的候选地址——已经排除了回环、link-local、私有段、
// 临时/废弃/未检测完的地址。界面只显示这个列表。
type Candidate struct {
	Address   string `json:"address"`   // 展开后的完整地址（带冒号）
	Interface string `json:"interface"` // 来自哪块网卡
	Prefix    int    `json:"prefix"`    // 前缀长度，如 64
	Scope     string `json:"scope"`     // global / link-local 等，按 scope 值翻译
	FlagsRaw  string `json:"flags_raw"` // flags 原文（如 "0x80"），给人核对用
	Permanent bool   `json:"permanent"` // flags 含 0x80（内核标记为稳定地址）
	Selected  bool   `json:"selected"`  // 是不是被挑中的那条
	Why       string `json:"why"`       // 为什么挑它 / 为什么它是合格候选
}

// FilterStats 是各类被过滤掉的条数统计。只给数量、不列被过滤的地址本身——
// 界面上不能出现 fe80:: / fc00:: / 临时地址，否则用户会误以为那些也能用。
type FilterStats struct {
	LinkLocal int `json:"link_local"`
	ULA       int `json:"ula"`
	Loopback  int `json:"loopback"`
	Tentative int `json:"tentative"`
	Deprecated int `json:"deprecated"`
	Temporary  int `json:"temporary"`
	Other      int `json:"other"`
	BadLine    int `json:"bad_line"`
}

// Report 是一次检测的完整结果。
type Report struct {
	Available  bool         `json:"available"`   // 有没有合格地址
	Selected   *Candidate   `json:"selected"`    // 挑中的那条；没有就是 null
	Candidates []Candidate  `json:"candidates"`  // 所有合格候选
	Total      int          `json:"total"`       // 读到的地址总行数
	Filtered   FilterStats  `json:"filtered"`    // 各类过滤计数
	Source     string       `json:"source"`      // 数据来源文件
	Note       string       `json:"note"`        // 给界面显示的一句人话
}

// ReadLocal 用系统默认路径检测本机地址。
func ReadLocal() (*Report, error) {
	return ReadFrom(ProcPath)
}

// ReadFrom 从指定文件读取并检测。生产传 ProcPath，测试传假文件。
func ReadFrom(path string) (*Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("读取 %s 失败: %w", path, err)
	}
	defer f.Close()

	rep := &Report{
		Source:     path,
		Candidates: make([]Candidate, 0),
	}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		rep.Total++
		line, reason := classify(sc.Text())
		if reason != reasonNone {
			bumpFilter(&rep.Filtered, reason)
			continue
		}
		rep.Candidates = append(rep.Candidates, Candidate{
			Address:   line.addr.String(),
			Interface: line.ifname,
			Prefix:    line.prefix,
			Scope:     scopeName(line.scope),
			FlagsRaw:  line.flagsRaw,
			Permanent: line.flags&flagPermanent != 0,
			Why:       "公网地址，非临时/废弃/未检测完",
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("读取 %s 出错: %w", path, err)
	}

	rep.Available = len(rep.Candidates) > 0
	if rep.Available {
		pick := chooseBest(rep.Candidates)
		// chooseBest 返回的是副本索引，回写选中标记到结果切片。
		chosen := rep.Candidates[pick]
		chosen.Selected = true
		chosen.Why = pickWhy(rep.Candidates, pick)
		rep.Candidates[pick] = chosen
		sel := rep.Candidates[pick]
		rep.Selected = &sel
		rep.Note = fmt.Sprintf("找到 %d 条可用地址，挑中 %s（网卡 %s）", len(rep.Candidates), sel.Address, sel.Interface)
	} else {
		rep.Note = "没有找到可用的公网 IPv6 地址。后面做 AAAA 解析也就没有意义——先别急。"
	}
	return rep, nil
}

// ---------- 解析与过滤 ----------

// addrLine 是一条解析 success 的原始行。
type addrLine struct {
	addr      netip.Addr
	ifname    string
	prefix    int
	scope     uint64
	flags     uint64
	flagsRaw  string
}

// filterReason 是过滤原因，也决定统计计到哪一栏。
type filterReason int

const (
	reasonNone filterReason = iota
	reasonLoopback
	reasonLinkLocal
	reasonULA
	reasonTentative
	reasonDeprecated
	reasonTemporary
	reasonOther
	reasonBadLine
)

// Linux include/uapi/linux/if_addr.h 的地址标志位。
// 注意 0x01 同时是 IFA_F_TEMPORARY 和 IFA_F_SECONDARY——这正是方案提醒的坑，
// 所以过滤时按"有这个位就排除"处理，并把原文留给人核对。
const (
	flagTemporary  uint64 = 0x01
	flagDeprecated uint64 = 0x20
	flagTentative  uint64 = 0x40
	flagPermanent  uint64 = 0x80
)

// classify 解析一行 /proc/net/if_inet6，返回解析结果和过滤原因。
//
// /proc/net/if_inet6 每行 6 列，例如：
//
//	20010db80000000000000000000001 02 40 00 80 eth0
//	└─ 32 位十六进制地址 ──────────┘ └if│pf│sc│fl┘ └名┘
//	                                 索引 前缀 scope flags
func classify(line string) (addrLine, filterReason) {
	fields := strings.Fields(line)
	if len(fields) != 6 {
		return addrLine{}, reasonBadLine
	}

	addr, err := hexAddr(fields[0])
	if err != nil {
		return addrLine{}, reasonBadLine
	}
	prefix, err := strconv.ParseUint(fields[2], 16, 8)
	if err != nil {
		return addrLine{}, reasonBadLine
	}
	scope, err := strconv.ParseUint(fields[3], 16, 8)
	if err != nil {
		return addrLine{}, reasonBadLine
	}
	flags, err := strconv.ParseUint(fields[4], 16, 16)
	if err != nil {
		return addrLine{}, reasonBadLine
	}
	if fields[5] == "" {
		return addrLine{}, reasonBadLine
	}

	out := addrLine{
		addr:     addr,
		ifname:   fields[5],
		prefix:   int(prefix),
		scope:    scope,
		flags:    flags,
		flagsRaw: "0x" + fields[4],
	}

	// 过滤顺序是有意的：先按地址本身排除（这几类永远不能用），再看 flags。
	// 一条地址只计一个原因，统计数加起来才等于总数。
	switch {
	case addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast():
		return out, reasonLoopback
	case addr.IsLinkLocalUnicast():
		return out, reasonLinkLocal
	case addr.IsPrivate(): // IPv6 下就是 fc00::/7（ULA，私有段）
		return out, reasonULA
	case flags&flagTentative != 0:
		return out, reasonTentative
	case flags&flagDeprecated != 0:
		return out, reasonDeprecated
	case flags&flagTemporary != 0:
		return out, reasonTemporary
	}
	return out, reasonNone
}

// hexAddr 把 /proc 里的 32 位无冒号十六进制转成 netip.Addr。
func hexAddr(s string) (netip.Addr, error) {
	if len(s) != 32 {
		return netip.Addr{}, fmt.Errorf("地址字段应为 32 个十六进制字符，实际 %d 个", len(s))
	}
	groups := make([]string, 8)
	for i := 0; i < 8; i++ {
		g := s[i*4 : i*4+4]
		if _, err := strconv.ParseUint(g, 16, 16); err != nil {
			return netip.Addr{}, err
		}
		groups[i] = g
	}
	return netip.ParseAddr(strings.Join(groups, ":"))
}

func bumpFilter(s *FilterStats, r filterReason) {
	switch r {
	case reasonLoopback:
		s.Loopback++
	case reasonLinkLocal:
		s.LinkLocal++
	case reasonULA:
		s.ULA++
	case reasonTentative:
		s.Tentative++
	case reasonDeprecated:
		s.Deprecated++
	case reasonTemporary:
		s.Temporary++
	case reasonBadLine:
		s.BadLine++
	default:
		s.Other++
	}
}

// scopeName 把 /proc 的 scope 列翻译成人话。IPV6_ADDR_SCOPE_*：
// 0x01 节点本地、0x02 链路本地、0x05 站点本地、0x08 组织本地、0x10 全局。
func scopeName(scope uint64) string {
	switch scope {
	case 0x01:
		return "node-local"
	case 0x02:
		return "link-local"
	case 0x05:
		return "site-local"
	case 0x08:
		return "org-local"
	case 0x10:
		return "global"
	default:
		return fmt.Sprintf("0x%x", scope)
	}
}

// ---------- 挑选 ----------

// chooseBest 返回挑中的候选在切片里的索引。
//
// 判据（方案第五节）：优先前缀 64，再挑网卡名最短的（家用主网卡通常就是
// eth0 / enp1s0 这种短名字，虚拟网卡、docker 网桥名字更长）；最后按地址排序，
// 保证同样的输入永远挑同一条，不会每次刷新换来换去。
func chooseBest(cs []Candidate) int {
	best := 0
	for i := 1; i < len(cs); i++ {
		if better(cs[i], cs[best]) {
			best = i
		}
	}
	return best
}

func better(a, b Candidate) bool {
	// 前缀 64 优先（/64 是家用宽带的正常前缀）。
	pa, pb := a.Prefix == 64, b.Prefix == 64
	if pa != pb {
		return pa
	}
	// 网卡名短的优先。
	if len(a.Interface) != len(b.Interface) {
		return len(a.Interface) < len(b.Interface)
	}
	// 名字一样长就按名字排，再一样就按地址排，保证确定性。
	if a.Interface != b.Interface {
		return a.Interface < b.Interface
	}
	return a.Address < b.Address
}

func pickWhy(cs []Candidate, pick int) string {
	c := cs[pick]
	parts := make([]string, 0, 3)
	if c.Prefix == 64 {
		parts = append(parts, "前缀 64（家用宽带的正常前缀）")
	} else {
		parts = append(parts, fmt.Sprintf("前缀 %d", c.Prefix))
	}
	parts = append(parts, fmt.Sprintf("网卡 %s 名字最短", c.Interface))
	if c.Permanent {
		parts = append(parts, "内核标记为稳定地址(0x80)")
	}
	return strings.Join(parts, "；")
}
