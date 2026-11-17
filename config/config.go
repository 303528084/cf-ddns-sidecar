// Package config 加载旁路容器的配置：config.yaml 提供非敏感项，
// 密钥类信息从环境变量注入（名字由 config.yaml 的 env 字段指定），不落盘。
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config 是旁路容器的完整运行配置。
type Config struct {
	// Provider 服务商类型：cloudflare / aliyun / dnspod / huawei
	Provider string `yaml:"provider"`

	// Domain 目标域名（可为子域名，如 cf.example.com）
	Domain string `yaml:"domain"`

	// PollIntervalSeconds 轮询最优 IP 的间隔秒数，<=0 使用默认 30
	PollIntervalSeconds int `yaml:"poll_interval_seconds"`

	// SubjectConfigPath 主体容器 config.json 在旁路容器内的挂载路径
	SubjectConfigPath string `yaml:"subject_config_path"`

	// StatePath 本容器状态文件路径（记录上次成功推送的 IP）
	StatePath string `yaml:"state_path"`

	// Listen 健康检查监听地址，如 :8080
	Listen string `yaml:"listen"`

	// Credentials 从环境变量读取的密钥（键名由各 Provider 决定）
	Credentials map[string]string `yaml:"-"`
}

// 各服务商需要的环境变量名。
var requiredEnvByProvider = map[string][]string{
	"cloudflare": {"CF_API_TOKEN", "CF_ZONE_ID"},
	"aliyun":     {"ALIYUN_ACCESS_KEY_ID", "ALIYUN_ACCESS_KEY_SECRET"},
	"dnspod":     {"TENCENT_SECRET_ID", "TENCENT_SECRET_KEY"},
	"huawei":     {"HUAWEI_AK", "HUAWEI_SK", "HUAWEI_ZONE_ID"},
}

// 各服务商可选的环境变量名（设置则覆盖默认的根域推断）。
var optionalEnvByProvider = map[string][]string{
	"aliyun": {"ALIYUN_ROOT_DOMAIN"},
	"dnspod": {"DNSPOD_ROOT_DOMAIN"},
}

// Load 从 YAML 文件读取配置（文件不存在时允许纯环境变量配置），
// 补齐默认值、用环境变量覆盖关键项、并注入密钥。
// 环境变量优先级高于 YAML，便于 FPK 安装后不进容器改文件即可配置。
func Load(path string) (*Config, error) {
	var c Config
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("读取配置文件 %s 失败: %w", path, err)
		}
	} else if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("解析配置文件 %s 失败: %w", path, err)
	}

	// 环境变量覆盖（CFDDNS_ 前缀避免与其它工具冲突）
	if v := os.Getenv("CFDDNS_PROVIDER"); v != "" {
		c.Provider = v
	}
	if v := os.Getenv("CFDDNS_DOMAIN"); v != "" {
		c.Domain = v
	}
	if v := os.Getenv("CFDDNS_SUBJECT_CONFIG_PATH"); v != "" {
		c.SubjectConfigPath = v
	}
	if v := os.Getenv("CFDDNS_STATE_PATH"); v != "" {
		c.StatePath = v
	}
	if v := os.Getenv("CFDDNS_LISTEN"); v != "" {
		c.Listen = v
	}
	if v := os.Getenv("CFDDNS_POLL_INTERVAL"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil {
			return nil, fmt.Errorf("CFDDNS_POLL_INTERVAL=%q 不是整数: %w", v, e)
		}
		c.PollIntervalSeconds = n
	}

	c.Provider = strings.ToLower(strings.TrimSpace(c.Provider))
	if _, ok := requiredEnvByProvider[c.Provider]; !ok {
		return nil, fmt.Errorf("不支持的 provider %q（可选: cloudflare/aliyun/dnspod/huawei）", c.Provider)
	}
	c.Domain = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(c.Domain), ".")))
	if c.Domain == "" {
		return nil, fmt.Errorf("domain 不能为空")
	}
	if c.PollIntervalSeconds <= 0 {
		c.PollIntervalSeconds = 30
	}
	if strings.TrimSpace(c.SubjectConfigPath) == "" {
		c.SubjectConfigPath = "/app/subject/config.json"
	}
	if strings.TrimSpace(c.StatePath) == "" {
		c.StatePath = "/app/data/state.json"
	}
	if strings.TrimSpace(c.Listen) == "" {
		c.Listen = ":8080"
	}

	c.Credentials = make(map[string]string)
	for _, name := range requiredEnvByProvider[c.Provider] {
		val := os.Getenv(name)
		if strings.TrimSpace(val) == "" {
			return nil, fmt.Errorf("缺少环境变量 %s（provider=%s）", name, c.Provider)
		}
		c.Credentials[name] = val
	}
	for _, name := range optionalEnvByProvider[c.Provider] {
		if val := strings.TrimSpace(os.Getenv(name)); val != "" {
			c.Credentials[name] = val
		}
	}
	return &c, nil
}

// PollInterval 返回轮询间隔的 time.Duration。
func (c *Config) PollInterval() time.Duration {
	return time.Duration(c.PollIntervalSeconds) * time.Second
}
