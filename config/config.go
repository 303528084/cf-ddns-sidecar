// Package config 定义本应用的统一配置。
//
// 设计原则：用户只需要在一个界面里看到「AdGuard 在哪」「要加速哪些域名」
// 「测速怎么跑」「域名解析推给谁」四件事，其余参数一概不暴露。
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// AdguardInstance 是 dns 包需要的实例描述（保留该类型以复用 AdGuard 客户端）。
type AdguardInstance struct {
	Name     string `json:"name"`
	Type     string `json:"type,omitempty"`
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// AdGuardConfig 描述局域网里的 AdGuard Home（界面上只有一组）。
type AdGuardConfig struct {
	URL      string `json:"url"`      // 例如 http://192.168.1.2:3000
	Username string `json:"username"` // 用户名
	Password string `json:"password"` // 密码
}

// Instance 把界面上的单一 AdGuard 配置转成 dns 包需要的实例结构。
func (a AdGuardConfig) Instance() AdguardInstance {
	return AdguardInstance{
		Name:     "AdGuard Home",
		Type:     "adguard",
		URL:      a.URL,
		Username: a.Username,
		Password: a.Password,
	}
}

// SpeedConfig 描述测速行为（映射到测速引擎 cfnb 的参数）。
type SpeedConfig struct {
	IntervalMinutes     int `json:"interval_minutes"`     // 自动测速间隔（分钟），0 表示不自动测
	TopN                int `json:"top_n"`                // 最终保留的候选 IP 数量
	BandwidthCandidates int `json:"bandwidth_candidates"` // 进入带宽测速的候选数
}

// DDNSConfig 描述把最优 IP 写到自有域名解析记录的行为。
// 密钥不在此结构中（单独存 ddns.env，便于用户用文本编辑器批量改）。
type DDNSConfig struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"` // cloudflare / aliyun / dnspod / huawei
	Domain   string `json:"domain"`   // 目标域名，如 cf.example.com

	// TTL 是写出的解析记录的生存时间（秒），0 表示用本程序的默认值
	// （Cloudflare 自动、DNSPod 600、华为云 300、阿里云不传）。
	// 这两个字段是 2026-11-17 才加的，老配置文件里没有，反序列化后就是零值，
	// 效果等同于以前写死的 1/600/300——升级不会改变用户现有记录的样子。
	TTL int `json:"ttl,omitempty"`
	// Proxied 只对 Cloudflare 有效：true 表示开橙色云朵（走 Cloudflare 代理）。
	Proxied bool `json:"proxied,omitempty"`

	// IPCount 是一次往域名里写几条 A 记录：按测速排名从优到劣取前 N 条。
	// 0 表示 1 条——老配置文件没有这个字段，行为必须和以前一模一样。
	IPCount int `json:"ip_count,omitempty"`
}

// EffectiveIPCount 返回实际要写几条 A 记录。零值和负数都按 1 条处理。
func (d DDNSConfig) EffectiveIPCount() int {
	if d.IPCount <= 0 {
		return 1
	}
	return d.IPCount
}

// Config 是全部配置，持久化为 config.json。
type Config struct {
	AdGuard AdGuardConfig `json:"adguard"`
	Domains []string      `json:"domains"` // 要写入 AdGuard 重写的域名列表
	Speed   SpeedConfig   `json:"speed"`
	DDNS    DDNSConfig    `json:"ddns"`

	// 运行状态（持久化便于重启后回显）
	LastIP   string `json:"last_ip,omitempty"`
	LastTime string `json:"last_time,omitempty"`
	// LastIPs 是上次测速里真正写进解析的那几条（按排名）。存下来是为了
	// 重启之后点「立即更新一次」还能把同一组推回去，不用重新测速；
	// 只存 LastIP 的话，重启后那一下会把多出来的几条悄悄删掉。
	LastIPs []string `json:"last_ips,omitempty"`

	// PendingSave 为 true 表示本次 Load 从 ddns.env 应用了一次性覆盖，
	// 调用方需要把结果落盘并清掉覆盖标记。不参与序列化。
	PendingSave bool `json:"-"`

	// RestoredFromBackup 为 true 表示主配置文件不见了，本次是从 config.json.bak
	// 恢复出来的。调用方应当把这个情况显式告诉用户——「静默退回默认值」正是
	// 2026-11-17 配置丢失事故里最误导人的地方：后台看起来一切正常，只是全空了。
	RestoredFromBackup bool `json:"-"`
}

var (
	cfgPath     = "/app/data/config.json"
	cfgPathOnce sync.Once
	mu          sync.Mutex
)

// backupSuffix 是配置文件的备份后缀。
//
// 每次写 config.json 前都会把旧内容留在 config.json.bak 里。目的有两个：
//  1. 新写的那份如果本身是坏的（磁盘满、被截断），还能拿回上一版；
//  2. config.json 万一被外部删掉（升级/清理脚本），Load 能从 .bak 恢复，
//     而不是静默退回默认值。
const backupSuffix = ".bak"

// resolvePath 返回配置文件路径，可用 CFDDNS_CONFIG 环境变量覆盖。
func resolvePath() string {
	cfgPathOnce.Do(func() {
		if p := os.Getenv("CFDDNS_CONFIG"); p != "" {
			cfgPath = p
		}
	})
	return cfgPath
}

// Default 返回带合理默认值的配置。
func Default() *Config {
	return &Config{
		Domains: []string{},
		Speed: SpeedConfig{
			IntervalMinutes:     60,
			TopN:                5,
			BandwidthCandidates: 100,
		},
		DDNS: DDNSConfig{Enabled: false, Provider: "cloudflare"},
	}
}

// Load 从磁盘加载配置；文件不存在时返回默认配置（不报错，首次启动即如此）。
//
// 两种情况下会从 ddns.env / 进程环境取值：
//  1. 首次启动（config.json 还不存在）——用安装向导填的域名、服务商、间隔打底；
//  2. ddns.env 里带 CFDDNS_APPLY_ENV=1——表示用户在「应用设置」里刚改过，
//     需要一次性覆盖已有配置（应用后由调用方清掉标记）。
//
// 除此之外 config.json 就是唯一真相，后台界面改了就以它为准。
func Load() (*Config, error) {
	c := Default()
	data, err := os.ReadFile(resolvePath())
	switch {
	case err == nil:
		if err := json.Unmarshal(data, c); err != nil {
			return nil, err
		}
		// 用户在飞牛「应用设置」里保存过：一次性覆盖
		if kv := LoadEnvFile(EnvFilePath()); envOrFile(kv, "CFDDNS_APPLY_ENV") == "1" {
			seedFromEnvFile(c, kv)
			c.PendingSave = true
		}
	case os.IsNotExist(err):
		// 主文件不见了。先看有没有上一次写入前留下的 .bak（见 Save）：
		// 有就恢复它，别让整份配置静默退回默认值。
		//
		// 这一条是为 2026-11-17 那次事故加的。当时升级把整个数据目录清空了，
		// 程序读到「文件不存在」就当成首次启动、用默认值继续跑，用户看到的是
		// 一个空白的后台——如果当时有 .bak，至少能自己爬起来。
		if bak, berr := os.ReadFile(resolvePath() + backupSuffix); berr == nil && len(bak) > 0 {
			if uerr := json.Unmarshal(bak, c); uerr == nil {
				c.RestoredFromBackup = true
				c.PendingSave = true
				break
			}
		}
		// 首次启动（安装向导刚写完 ddns.env）：用它打底，并立刻落盘。
		// 这里必须也置 PendingSave —— 否则 config.json 一直不存在、
		// 「已应用」标记永远清不掉，等用户以后在后台改了配置，
		// 下次重启又会被安装时的旧值覆盖回去。
		seedFromEnvFile(c, LoadEnvFile(EnvFilePath()))
		c.PendingSave = true
	default:
		return nil, err
	}
	if c.Domains == nil {
		c.Domains = []string{}
	}
	// 校正非法值，避免用户手改配置后行为诡异
	if c.Speed.IntervalMinutes < 0 {
		c.Speed.IntervalMinutes = 0
	}
	if c.Speed.TopN <= 0 {
		c.Speed.TopN = 5
	}
	if c.Speed.BandwidthCandidates <= 0 {
		c.Speed.BandwidthCandidates = 100
	}
	if c.DDNS.Provider == "" {
		c.DDNS.Provider = "cloudflare"
	}
	return c, nil
}

// seedFromEnvFile 用安装向导写进 ddns.env 的值给配置打底。
func seedFromEnvFile(c *Config, kv map[string]string) {
	if p := envOrFile(kv, "CFDDNS_PROVIDER"); p != "" {
		p = strings.ToLower(p)
		if _, ok := RequiredEnvByProvider[p]; ok {
			c.DDNS.Provider = p
		}
	}
	if d := envOrFile(kv, "CFDDNS_DOMAIN"); d != "" {
		if v := NormalizeDomain(d); v != "" {
			c.DDNS.Domain = v
			c.DDNS.Enabled = true
		}
	}
	if n := envOrFile(kv, "CFDDNS_INTERVAL_MINUTES"); n != "" {
		if v, err := strconv.Atoi(n); err == nil && v >= 0 {
			c.Speed.IntervalMinutes = v
		}
	}
}

// envOrFile 读一个值：进程环境变量优先，其次 ddns.env 文件。
func envOrFile(kv map[string]string, name string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return strings.TrimSpace(kv[name])
}

// NormalizeDomain 把用户可能粘贴进来的 "https://a.com/x" 归一化成 "a.com"。
func NormalizeDomain(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")
	return s
}

// Save 原子写回磁盘。
func (c *Config) Save() error {
	mu.Lock()
	defer mu.Unlock()

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	p := resolvePath()
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".cfddns-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return err
	}
	// 落盘前把上一版留一份 .bak。失败不影响主流程——备份是加分项，
	// 不能因为它写不了就导致用户存不了配置。
	if old, rerr := os.ReadFile(p); rerr == nil && len(old) > 0 {
		_ = os.WriteFile(p+backupSuffix, old, 0o600)
	}
	return os.Rename(name, p)
}

// Clone 深拷贝，供并发读快照。
func (c *Config) Clone() Config {
	cp := *c
	// 注意：append([]string(nil), 空slice...) 会得到 nil，
	// 序列化后变成 "domains": null，前端还得额外兜底。这里保持空数组。
	if len(c.Domains) == 0 {
		cp.Domains = []string{}
	} else {
		cp.Domains = append(make([]string, 0, len(c.Domains)), c.Domains...)
	}
	// LastIPs 同样要拷一份：它是会被写进解析的列表，共享底层数组
	// 就意味着一个 goroutine 在读、另一个在改，属于最难查的那种问题。
	if len(c.LastIPs) > 0 {
		cp.LastIPs = append(make([]string, 0, len(c.LastIPs)), c.LastIPs...)
	}
	return cp
}
