// Package ddns 定义 DNS 服务商适配的统一接口与各家实现。
package ddns

import (
	"fmt"
	"strings"
)

// RecordState 是只读校验时看到的「这条域名现在什么样」。
type RecordState struct {
	// Found 为 false 表示账号里还没有这条 A 记录（第一次跑之前就是这种状态）。
	Found bool
	// CurrentIP 是当前 A 记录的值；Found 为 false 时为空。
	// 有多条时取第一条——界面上的「现在指向」仍然只显示一个位置。
	CurrentIP string
	// CurrentIPs 是全部 A 记录的值，按接口返回顺序。
	// 一个域名可以有多条 A（本程序按用户设定的条数写入），
	// 只说第一条会让用户误以为其余的丢了。
	CurrentIPs []string
}

// RecordOptions 是写 A 记录时的可选项。零值等于「一切按服务商默认」，
// 也就是升级前写死的那套行为——老配置文件里没有这两个字段时，写出去的结果
// 和以前一模一样，不会因为加了选项就悄悄改掉用户现有的记录。
type RecordOptions struct {
	// TTL 是这条记录的生存时间（秒）。0 表示不指定，用本程序一直以来的默认值：
	// Cloudflare 自动（1）、DNSPod 600、华为云 300、阿里云不传（账号默认）。
	TTL int
	// Proxied 只对 Cloudflare 有意义：true 表示开橙色云朵，让解析走 Cloudflare
	// 代理。开了云朵之后域名不再直接指向优选 IP，DDNS 的意义就没了，界面上要
	// 明确劝一句。其余三家忽略此字段。
	Proxied bool
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

// Provider 是 DNS 服务商的统一接缝：把目标域名的 A 记录**对齐**到给定的一组 IP。
type Provider interface {
	// EnsureARecords 把 domain 的 A 记录对齐到 ips 这一组：
	// 缺的补上、多的删掉、已在其中的顺手校准 TTL / 云朵。幂等。
	//
	// 两个刻意的约定：
	//  1. ips 为空时**什么都不做**。测速失败或结果被过滤空时可能传进空列表，
	//     那一下要是理解成「期望集合为空」就会把域名清空——访问直接断掉。
	//  2. 顺序是先补齐、再删多余。反过来先删的话，中间会有一小段时间这个域名
	//     一条 A 记录都没有，正在访问的人会解析失败。
	EnsureARecords(domain string, ips []string, opt RecordOptions) error
	// Verify 只读校验：确认密钥有效、能查到这个域名，并返回当前 A 记录值。
	// 绝不写任何东西——用户点「测试密钥」时不该改到线上解析。
	Verify(domain string) (RecordState, error)
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
