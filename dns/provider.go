// Package dns 定义「把最优 IP 写进局域网 DNS」的能力。
//
// 本项目只支持 AdGuard Home。原上游项目还支持 Technitium / dnsmasq /
// SmartDNS / MosDNS 等，这些对本产品的目标场景（家庭 NAS 上跑一个
// AdGuard Home）是用不到的复杂度，已在本分支移除。
package dns

import (
	"errors"

	"github.com/303528084/cf-ddns-sidecar/config"
)

// ErrUnknownProvider 表示请求了不支持的 DNS 类型。
var ErrUnknownProvider = errors.New("不支持的 DNS 类型（仅支持 adguard）")

// RewriteEntry 一条重写记录（域名 → 解析目标）。
type RewriteEntry struct {
	Domain  string `json:"domain"`
	Answer  string `json:"answer"`
	Enabled bool   `json:"enabled"`
}

// SyncStats 记录一次 ReplaceRewrites 的操作统计。
type SyncStats struct {
	Written int // 新增或更新的条目数
	Removed int // 清理的条目数
}

// Provider 是一个 DNS 实例的统一操作接口。
// want 的语义为「期望的完整重写集合」：domain → 允许的 answer 集合
// （空集合表示该域名不应存在任何记录）。
type Provider interface {
	// Name 返回 provider 类型标识。
	Name() string
	// TestConnection 测试实例可达性/可用性。
	TestConnection() error
	// ListRewrites 列出当前生效的重写记录。
	ListRewrites() ([]RewriteEntry, error)
	// ReplaceRewrites 把重写状态收敛到期望集合。
	ReplaceRewrites(want map[string]map[string]bool) (SyncStats, error)
}

// New 构造 AdGuard Home 客户端。
func New(inst config.AdguardInstance) (Provider, error) {
	switch inst.Type {
	case "", "adguard":
		return NewAdGuard(inst), nil
	default:
		return nil, ErrUnknownProvider
	}
}
