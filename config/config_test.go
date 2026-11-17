package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTemp 写入临时文件并返回路径。
func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	return p
}

func TestLoadEnvFileParsing(t *testing.T) {
	p := writeTemp(t, "ddns.env", strings.Join([]string{
		"# 注释行应被忽略",
		"",
		"CFDDNS_PROVIDER=cloudflare\r",
		"CFDDNS_DOMAIN = cf.example.com ",
		`CF_API_TOKEN="quoted-token"`,
		"没有等号的行",
		"=空键应被忽略",
		"CF_ZONE_ID=zone123",
	}, "\n"))

	kv := LoadEnvFile(p)
	if kv["CFDDNS_PROVIDER"] != "cloudflare" {
		t.Fatalf("应去掉 CRLF，实际 %q", kv["CFDDNS_PROVIDER"])
	}
	if kv["CFDDNS_DOMAIN"] != "cf.example.com" {
		t.Fatalf("应去掉首尾空格，实际 %q", kv["CFDDNS_DOMAIN"])
	}
	if kv["CF_API_TOKEN"] != "quoted-token" {
		t.Fatalf("应去掉引号，实际 %q", kv["CF_API_TOKEN"])
	}
	if kv["CF_ZONE_ID"] != "zone123" {
		t.Fatalf("正常行应被解析，实际 %q", kv["CF_ZONE_ID"])
	}
	if _, ok := kv[""]; ok {
		t.Fatal("空键不应进入结果")
	}
}

func TestLoadEnvFileMissingIsEmpty(t *testing.T) {
	kv := LoadEnvFile(filepath.Join(t.TempDir(), "not-exist.env"))
	if kv == nil || len(kv) != 0 {
		t.Fatalf("缺失文件应返回空表，实际 %v", kv)
	}
}

// clearProviderEnv 清空可能影响测试的进程环境变量。
func clearProviderEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"CFDDNS_PROVIDER", "CFDDNS_DOMAIN", "CFDDNS_POLL_INTERVAL",
		"CFDDNS_ENV_FILE", "CF_API_TOKEN", "CF_ZONE_ID",
		"ALIYUN_ACCESS_KEY_ID", "ALIYUN_ACCESS_KEY_SECRET",
	} {
		t.Setenv(k, "")
	}
}

func TestLoadFromEnvFileOnly(t *testing.T) {
	clearProviderEnv(t)
	envFile := writeTemp(t, "ddns.env", strings.Join([]string{
		"CFDDNS_PROVIDER=cloudflare",
		"CFDDNS_DOMAIN=CF.Example.com.",
		"CF_API_TOKEN=token-from-file",
		"CF_ZONE_ID=zone-from-file",
		"CFDDNS_POLL_INTERVAL=45",
	}, "\n"))
	t.Setenv("CFDDNS_ENV_FILE", envFile)

	// config.yaml 不存在时应能纯靠 ddns.env 启动
	c, err := Load(filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatalf("应加载成功，实际错误: %v", err)
	}
	if c.Provider != "cloudflare" {
		t.Fatalf("provider 错误: %q", c.Provider)
	}
	if c.Domain != "cf.example.com" {
		t.Fatalf("域名应小写并去掉末尾点，实际 %q", c.Domain)
	}
	if c.Credentials["CF_API_TOKEN"] != "token-from-file" {
		t.Fatalf("密钥应来自 ddns.env，实际 %q", c.Credentials["CF_API_TOKEN"])
	}
	if c.PollIntervalSeconds != 45 {
		t.Fatalf("轮询间隔应为 45，实际 %d", c.PollIntervalSeconds)
	}
	if c.Listen != ":8080" || c.StatePath != "/app/data/state.json" {
		t.Fatalf("默认值未补齐: listen=%q state=%q", c.Listen, c.StatePath)
	}
}

func TestProcessEnvOverridesEnvFile(t *testing.T) {
	clearProviderEnv(t)
	envFile := writeTemp(t, "ddns.env", strings.Join([]string{
		"CFDDNS_PROVIDER=aliyun",
		"CFDDNS_DOMAIN=from-file.example.com",
		"ALIYUN_ACCESS_KEY_ID=file-id",
		"ALIYUN_ACCESS_KEY_SECRET=file-secret",
	}, "\n"))
	t.Setenv("CFDDNS_ENV_FILE", envFile)
	t.Setenv("CFDDNS_DOMAIN", "from-env.example.com")

	c, err := Load(filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatalf("应加载成功，实际错误: %v", err)
	}
	if c.Domain != "from-env.example.com" {
		t.Fatalf("进程环境应优先于文件，实际 %q", c.Domain)
	}
	if c.Credentials["ALIYUN_ACCESS_KEY_ID"] != "file-id" {
		t.Fatalf("未设置的项应回退到文件，实际 %q", c.Credentials["ALIYUN_ACCESS_KEY_ID"])
	}
}

func TestLoadMissingRequiredCredential(t *testing.T) {
	clearProviderEnv(t)
	envFile := writeTemp(t, "ddns.env", "CFDDNS_PROVIDER=cloudflare\nCFDDNS_DOMAIN=cf.example.com\n")
	t.Setenv("CFDDNS_ENV_FILE", envFile)

	_, err := Load(filepath.Join(t.TempDir(), "config.yaml"))
	if err == nil {
		t.Fatal("缺少密钥时应报错")
	}
	if !strings.Contains(err.Error(), "CF_API_TOKEN") || !strings.Contains(err.Error(), "ddns.env") {
		t.Fatalf("错误信息应指明缺失项与文件路径，实际: %v", err)
	}
}

func TestLoadInvalidPollInterval(t *testing.T) {
	clearProviderEnv(t)
	envFile := writeTemp(t, "ddns.env", strings.Join([]string{
		"CFDDNS_PROVIDER=cloudflare",
		"CFDDNS_DOMAIN=cf.example.com",
		"CF_API_TOKEN=t",
		"CF_ZONE_ID=z",
		"CFDDNS_POLL_INTERVAL=30s",
	}, "\n"))
	t.Setenv("CFDDNS_ENV_FILE", envFile)

	if _, err := Load(filepath.Join(t.TempDir(), "config.yaml")); err == nil {
		t.Fatal("非法轮询间隔应报错而不是静默回退")
	}
}
