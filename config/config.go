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

// DefaultEnvFile 是容器内默认的 KEY=VALUE 配置文件路径。
// 由宿主机共享目录挂载而来（见 docker-compose），用户直接编辑该文件即可配置。
const DefaultEnvFile = "/app/data/ddns.env"

// LoadEnvFile 读取 KEY=VALUE 形式的配置文件（如 ddns.env）。
// 支持 # 注释、空行、值两侧引号与 CRLF；文件不存在时返回空表而不报错，
// 因为 compose 挂载目录在首次启动前可能还没有该文件。
func LoadEnvFile(path string) map[string]string {
	kv := make(map[string]string)
	data, err := os.ReadFile(path)
	if err != nil {
		return kv
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		if key != "" {
			kv[key] = val
		}
	}
	return kv
}

// Load 从 YAML 文件读取配置（文件不存在时允许纯环境变量配置），
// 补齐默认值、用环境变量覆盖关键项、并注入密钥。
// 优先级：进程环境变量 > ddns.env 文件 > config.yaml > 默认值。
// 之所以不依赖 compose 的 env_file：飞牛在安装阶段就会校验 env_file 是否存在，
// 而该文件要等应用首次启动才生成，会导致安装直接失败。
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

	envFile := strings.TrimSpace(os.Getenv("CFDDNS_ENV_FILE"))
	if envFile == "" {
		envFile = DefaultEnvFile
	}
	fileEnv := LoadEnvFile(envFile)
	// getenv：进程环境优先，其次读 ddns.env，缺省返回空串。
	getenv := func(name string) string {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return v
		}
		return fileEnv[name]
	}

	// 环境变量/配置文件覆盖（CFDDNS_ 前缀避免与其它工具冲突）
	if v := getenv("CFDDNS_PROVIDER"); v != "" {
		c.Provider = v
	}
	if v := getenv("CFDDNS_DOMAIN"); v != "" {
		c.Domain = v
	}
	if v := getenv("CFDDNS_SUBJECT_CONFIG_PATH"); v != "" {
		c.SubjectConfigPath = v
	}
	if v := getenv("CFDDNS_STATE_PATH"); v != "" {
		c.StatePath = v
	}
	if v := getenv("CFDDNS_LISTEN"); v != "" {
		c.Listen = v
	}
	if v := getenv("CFDDNS_POLL_INTERVAL"); v != "" {
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
		val := getenv(name)
		if strings.TrimSpace(val) == "" {
			return nil, fmt.Errorf("缺少配置项 %s（provider=%s）：请在 %s 中填写，或检查该文件是否存在",
				name, c.Provider, envFile)
		}
		c.Credentials[name] = val
	}
	for _, name := range optionalEnvByProvider[c.Provider] {
		if val := getenv(name); val != "" {
			c.Credentials[name] = val
		}
	}
	return &c, nil
}

// PollInterval 返回轮询间隔的 time.Duration。
func (c *Config) PollInterval() time.Duration {
	return time.Duration(c.PollIntervalSeconds) * time.Second
}
