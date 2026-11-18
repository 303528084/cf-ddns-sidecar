// Package ddns 定义 DNS 服务商适配的统一接口与各家实现。
package ddns

import (
	"fmt"
	"net/netip"
	"strings"
)

// 记录类型。用常量而不是到处写 "A"/"AAAA"：这两个字母一写错，
// 服务商那边不会报错，只会把记录写到另一个类型上去（或找不到记录）。
const (
	TypeA    = "A"    // IPv4 地址
	TypeAAAA = "AAAA" // IPv6 地址
)

// ModeBoth 是「同步模式」，**不是** DNS 记录类型：表示 A 和 AAAA 两族都要写。
//
// 它只出现在配置和界面上，永远不会被传给服务商——真正写记录前一定会被
// FamiliesOf 展开成 TypeA / TypeAAAA 逐个写。之所以要单独一个概念：DNS
// 协议里没有「A+AAAA」这种记录，硬塞进 NormalizeRecordType 只会让那层
// 校验对自己说谎。
const ModeBoth = "A+AAAA"

// NormalizeRecordMode 把用户选的同步模式收敛成 TypeA / TypeAAAA / ModeBoth。
//
// 空值一律按 A 处理——老配置文件里没有这个字段，读出来是空串，行为必须和
// 以前完全一致。**非法值返回错误而不是回落成 A**：用户以为在写 AAAA、
// 实际写了 A，这种错误不会在任何地方报出来，只有访问变慢才可能被发现。
func NormalizeRecordMode(m string) (string, error) {
	switch strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(m), " ", "")) {
	case "", TypeA:
		return TypeA, nil
	case TypeAAAA:
		return TypeAAAA, nil
	case ModeBoth, "AAAA+A":
		// 「AAAA+A」也认，省得用户手写配置文件时顺序反了就被判非法。
		return ModeBoth, nil
	default:
		return "", fmt.Errorf("不支持的记录类型 %q（只有 A / AAAA / %s）", m, ModeBoth)
	}
}

// FamiliesOf 把同步模式展开成这一轮要写哪几种记录。
//
// 顺序固定 A 在前：写日志、报错时先讲 IPv4，和用户平时看测速结果的顺序一致。
// 传进任何认不出来的值都当 A——这是给「配置已经读进来了」的路径用的，
// 那条路不该报错；拦住非法值的是保存时的 NormalizeRecordMode。
func FamiliesOf(mode string) []string {
	switch strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(mode), " ", "")) {
	case TypeAAAA:
		return []string{TypeAAAA}
	case ModeBoth, "AAAA+A":
		return []string{TypeA, TypeAAAA}
	default:
		return []string{TypeA}
	}
}

// NormalizeRecordType 把调用方传进来的记录类型收敛成 TypeA / TypeAAAA。
//
// 注意它**只认单族**：ModeBoth 是同步模式，不是记录类型，传进来会报错。
// 要按用户选的模式写记录，先用 FamiliesOf 展开再逐个调这里。
//
// 空值一律按 A 处理——老配置文件里没有这个字段，读出来是空串，行为必须和
// 以前完全一致。**非法值返回错误而不是回落成 A**：用户以为在写 AAAA、
// 实际写了 A，这种错误不会在任何地方报出来，只有访问变慢才可能被发现。
func NormalizeRecordType(t string) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(t)) {
	case "", TypeA:
		return TypeA, nil
	case TypeAAAA:
		return TypeAAAA, nil
	default:
		return "", fmt.Errorf("不支持的记录类型 %q（只有 A / AAAA）", t)
	}
}

// RecordState 是只读校验时看到的「这条域名现在什么样」。
type RecordState struct {
	// Found 为 false 表示账号里还没有这条记录（第一次跑之前就是这种状态）。
	Found bool
	// CurrentIP 是当前记录的值；Found 为 false 时为空。
	// 有多条时取第一条——界面上的「现在指向」仍然只显示一个位置。
	CurrentIP string
	// CurrentIPs 是全部记录的值，按接口返回顺序。
	// 一个域名可以有多条（本程序按用户设定的条数写入），
	// 只说第一条会让用户误以为其余的丢了。
	CurrentIPs []string
}

// RecordOptions 是写记录时的可选项。零值等于「一切按服务商默认」，
// 也就是升级前写死的那套行为——老配置文件里没有这些字段时，写出去的结果
// 和以前一模一样，不会因为加了选项就悄悄改掉用户现有的记录。
type RecordOptions struct {
	// Type 是记录类型：空串按 A 处理（老配置零值行为不变），
	// 另一个合法值是 AAAA。用 NormalizeRecordType 收敛。
	Type string
	// TTL 是这条记录的生存时间（秒）。0 表示不指定，用本程序一直以来的默认值：
	// Cloudflare 自动（1）、DNSPod 600、华为云 300、阿里云不传（账号默认）。
	TTL int
	// Proxied 只对 Cloudflare 有意义：true 表示开橙色云朵，让解析走 Cloudflare
	// 代理。开了云朵之后域名不再直接指向优选 IP，DDNS 的意义就没了，界面上要
	// 明确劝一句。其余三家忽略此字段。
	Proxied bool
}

// recordType 返回已经校验过的记录类型，拿不到就报错（绝不悄悄当 A 写出去）。
func (o RecordOptions) recordType() (string, error) {
	return NormalizeRecordType(o.Type)
}

// cfTTL 返回 Cloudflare 该用的 ttl 值。
//
// Cloudflare 用 1 表示「自动」。另外代理记录（云朵打开）的缓存完全由
// Cloudflare 接管，TTL 只能是自动，传别的值接口会直接报错——所以开了云朵
// 就不要再把用户填的 TTL 递上去。
func (o RecordOptions) cfTTL() int {
	if o.Proxied || o.TTL <= 0 {
		return 1
	}
	return o.TTL
}

// Provider 是 DNS 服务商的统一接缝：把目标域名的「某一类记录」**对齐**到给定的一组 IP。
//
// 为什么是「某一类」而不是「A 记录」：2026-11-18 起支持写 AAAA（IPv6 优选）。
// A 和 AAAA 是同一域名下互相独立的两族记录，能同时存在，客户端按自己支持的
// 协议族各取一条。所以每一处「查/建/改/删」都必须明确是针对哪一类——
// **写 AAAA 时绝不能碰到 A，反之亦然**，删错会让正在用的解析安静地断掉。
type Provider interface {
	// EnsureRecords 把 domain 的 opt.Type 类记录对齐到 ips 这一组：
	// 缺的补上、多的删掉、已在其中的顺手校准 TTL / 云朵。幂等。
	//
	// 三个刻意的约定：
	//  1. ips 为空时**什么都不做**。测速失败或结果被过滤空时可能传进空列表，
	//     那一下要是理解成「期望集合为空」就会把域名清空——访问直接断掉。
	//  2. 顺序是先补齐、再删多余。反过来先删的话，中间会有一小段时间这个域名
	//     一条记录都没有，正在访问的人会解析失败。
	//  3. 只认和处理 opt.Type 那一族记录；另一族的记录既不查也不删。
	EnsureRecords(domain string, ips []string, opt RecordOptions) error
	// Verify 只读校验：确认密钥有效、能查到该域名，并返回 rtype 那类记录的当前值。
	// 绝不写任何东西——用户点「测试密钥」时不该改到线上解析。
	//
	// rtype 传空按 A 处理（老调用方行为不变）；传 AAAA 就只看 AAAA，
	// 这样才能如实回答「v6 那条到底写进去了没有」。
	Verify(domain string, rtype string) (RecordState, error)
	// Name 返回服务商名称，用于日志。
	Name() string
}

// New 按类型构造 Provider。creds 为从环境变量注入的密钥集合。
func New(kind string, domain string, creds map[string]string) (Provider, error) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "cloudflare":
		return newCloudflare(domain, creds)
	case "aliyun":
		return newAliyun(domain, creds)
	case "dnspod":
		return newDNSPod(domain, creds)
	case "huawei":
		return newHuawei(domain, creds)
	default:
		return nil, fmt.Errorf("不支持的 provider: %q", kind)
	}
}

// normalizeIPs 丢掉空白项并去重（保持原有顺序，排名是从优到劣）。
//
// 空项必须丢：把空字符串当成一个 IP 写到服务商那里，轻则报错，
// 重则在 Cloudflare 上留下一条把域名指向 "" 的坏记录。
func normalizeIPs(ips []string) []string {
	out := make([]string, 0, len(ips))
	seen := make(map[string]bool, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		out = append(out, ip)
	}
	return out
}

// prepareIPs 是写记录前的最后一道闸：先去空去重，再校验地址族。
//
// 为什么必须查地址族：配置说写 AAAA、传进来的却是 IPv4（或反过来）时，
// 服务商那边要么报一句看不懂的参数错误，要么更糟——按字符串收下，域名上就
// 多出一条 `AAAA = 1.2.3.4` 的坏记录。这种错误不会自己冒出来，只能在这里拦住。
//
// 4-in-6 形式的 `::ffff:1.2.3.4` 不算合法 AAAA：它在 DNS 里既不是 v6 地址，
// 客户端也不会拿它当 v6 用，写进去纯属埋雷。
func prepareIPs(ips []string, rtype string) ([]string, error) {
	out := normalizeIPs(ips)
	if len(out) == 0 {
		return out, nil
	}
	want6 := rtype == TypeAAAA
	for _, ip := range out {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, fmt.Errorf("要写进 %s 记录的 %q 不是合法 IP 地址", rtype, ip)
		}
		if want6 && (!addr.Is6() || addr.Is4In6()) {
			return nil, fmt.Errorf("记录类型是 %s，但拿到的是 IPv4 地址 %q（地址族不对，一条都没写）", rtype, ip)
		}
		if !want6 && !addr.Is4() {
			return nil, fmt.Errorf("记录类型是 %s，但拿到的是 IPv6 地址 %q（地址族不对，一条都没写）", rtype, ip)
		}
	}
	return out, nil
}

// splitDomain 把完整域名拆成根域与记录名。
// 依据传入的 root（服务商里配置的根域）判断：
// 若 domain 等于 root，记录名为 "@"；若 domain 以 "."+root 结尾，记录名为其前缀；
// 否则视为 domain 本身就是根域（记录名 "@"，root=domain）。
// 返回 (root, recordName)。
func splitDomain(domain, root string) (string, string) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	root = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(root), "."))
	if root == "" {
		return domain, "@"
	}
	if domain == root {
		return root, "@"
	}
	if strings.HasSuffix(domain, "."+root) {
		rec := strings.TrimSuffix(domain, "."+root)
		if rec != "" {
			return root, rec
		}
	}
	return domain, "@"
}
