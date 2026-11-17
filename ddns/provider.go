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
	CurrentIP string
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

// Provider 是 DNS 服务商的统一接缝：把目标域名的 A 记录设为指定 IP（幂等）。
type Provider interface {
	// EnsureARecord 确保 domain 的 A 记录指向 ip：记录存在则更新，不存在则创建。
	// opt 里的 TTL / 云朵只在真正写记录时起作用；已经符合期望就不发请求。
	EnsureARecord(domain, ip string, opt RecordOptions) error
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
