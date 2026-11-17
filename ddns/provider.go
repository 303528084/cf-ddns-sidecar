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

// Provider 是 DNS 服务商的统一接缝：把目标域名的 A 记录设为指定 IP（幂等）。
type Provider interface {
	// EnsureARecord 确保 domain 的 A 记录指向 ip：记录存在则更新，不存在则创建。
	EnsureARecord(domain, ip string) error
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
