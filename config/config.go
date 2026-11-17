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

	// PendingSave 为 true 表示本次 Load 从 ddns.env 应用了一次性覆盖，
	// 调用方需要把结果落盘并清掉覆盖标记。不参与序列化。
	PendingSave bool `json:"-"`
}

var (
	cfgPath     = "/app/data/config.json"
	cfgPathOnce sync.Once
	mu          sync.Mutex
)

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
		seedFromEnvFile(c, LoadEnvFile(EnvFilePath()))
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
	return cp
}
