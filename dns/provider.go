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
	Written int // 本次新增的条目数
	Removed int // 本次删除的条目数
	// Kept 是「不归本工具管、原样留着」的条目数。
	//
	// 单独记一个数不是为了好看：用户最担心的事就是「我这个工具会不会顺手
	// 删掉我别处加的规则」。日志里出现「保留了 N 条别人的记录」时，这个担心
	// 才算被证明过一次，而不是靠我们口头保证。
	Kept int
}

// Provider 是一个 DNS 实例的统一操作接口。
// want 的语义为「本工具认领的域名 → 期望的答案集合」：
//   - want 的**键**就是认领范围，不在这里面的域名一律不碰（用户自己加的、
//     AdGuard 自带的重写规则都靠这一条保住）；
//   - want[d] 里没有的答案会被删掉，缺的会被补上；
//   - want[d] 是**空集合**表示「这个域名不该有任何记录」，用于清掉用户已经
//     从域名列表里删掉、但 AdGuard 上还留着的旧记录（见
//     config.Config.RewrittenDomains）。
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
