package web

// 配置的导出与导入。
//
// 为什么要有它：数据目录一旦被清空，用户就得手抄八项设置——AdGuard 地址/
// 用户名/密码、要加速的域名列表、测速参数、服务商、优选域名、以及可能两家
// 以上的密钥。2026-11-17 那天他正是这么重填了一遍，其中 Cloudflare 令牌
// 还得回 Cloudflare 后台重新生成（旧的那份随数据目录一起没了）。
// 能导出一个文件、换机或重装时上传回来，才是真正兜住这件事。
//
// 两条硬约束：
//  1. 文件里带密钥和 AdGuard 密码，必须只走已登录的接口，并且不让浏览器
//     或中间代理缓存它（Cache-Control: no-store）；
//  2. 导入时只允许写白名单里的 key 进 ddns.env。备份文件是用户可以手改的，
//     不能让它变成往密钥文件里塞任意变量的入口。

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/303528084/cf-ddns-sidecar/config"
)

const (
	// bundleApp 是导出文件里标识「这是谁的文件」的字段值。
	bundleApp = "cf-ddns-sidecar"
	// bundleFormat 是格式版本。以后改结构就 +1，导入侧据此拒绝未来版本。
	bundleFormat = 1
	// maxBundleBytes 是导入文件的大小上限。正常备份只有几 KB。
	maxBundleBytes = 1 << 20
)

// bundleConfig 是跟着文件走的那部分配置。
//
// 刻意用显式字段而不是直接序列化 config.Config：
//   - 运行状态（last_ip / last_time）不该跟着走，那是这台机器的实际结果，
//     换台机器后照搬过来只会误导人；
//   - 以后给 Config 加字段时，不会因为「顺手 Marshal」把不该出门的东西
//     一起导出去。
type bundleConfig struct {
	AdGuardURL      string   `json:"adguard_url"`
	AdGuardUsername string   `json:"adguard_username"`
	AdGuardPassword string   `json:"adguard_password,omitempty"`
	Domains         []string `json:"domains"`
	TopN            int      `json:"top_n"`
	Candidates      int      `json:"bandwidth_candidates"`
	IntervalMinutes int      `json:"interval_minutes"`
	DDNSEnabled     bool     `json:"ddns_enabled"`
	DDNSProvider    string   `json:"ddns_provider"`
	DDNSDomain      string   `json:"ddns_domain"`
}

// bundle 是可导出、也可导入的文件格式。
type bundle struct {
	App        string            `json:"app"`
	Format     int               `json:"format"`
	Version    string            `json:"version"`
	ExportedAt string            `json:"exported_at"`
	Note       string            `json:"note,omitempty"`
	Config     bundleConfig      `json:"config"`
	Secrets    map[string]string `json:"secrets,omitempty"`
}

// bundleNote 写在导出文件里，提醒拿到这份文件的人该怎么保管。
const bundleNote = "这个文件包含 AdGuard 密码和各 DNS 服务商的密钥，请当作密码保管。" +
	"换机或重装后在后台「备份与恢复」里上传即可一键恢复；后台登录密码不在其中。"

// allowedSecretKeys 是允许通过导入写进 ddns.env 的变量名白名单。
var allowedSecretKeys = func() map[string]bool {
	m := make(map[string]bool)
	for _, k := range config.AllCredentialKeys() {
		m[k] = true
	}
	return m
}()

// buildBundle 组装导出内容。creds 传 config.DDNCredentials() 的结果。
func buildBundle(cfg config.Config, creds map[string]string, ver string, now time.Time) bundle {
	secrets := make(map[string]string, len(creds))
	for _, k := range config.AllCredentialKeys() {
		if v := strings.TrimSpace(creds[k]); v != "" {
			secrets[k] = v
		}
	}

	domains := cfg.Domains
	if domains == nil {
		domains = []string{}
	}

	return bundle{
		App:        bundleApp,
		Format:     bundleFormat,
		Version:    ver,
		ExportedAt: now.Format(time.RFC3339),
		Note:       bundleNote,
		Config: bundleConfig{
			AdGuardURL:      cfg.AdGuard.URL,
			AdGuardUsername: cfg.AdGuard.Username,
			AdGuardPassword: cfg.AdGuard.Password,
			Domains:         append([]string{}, domains...),
			TopN:            cfg.Speed.TopN,
			Candidates:      cfg.Speed.BandwidthCandidates,
			IntervalMinutes: cfg.Speed.IntervalMinutes,
			DDNSEnabled:     cfg.DDNS.Enabled,
			DDNSProvider:    cfg.DDNS.Provider,
			DDNSDomain:      cfg.DDNS.Domain,
		},
		Secrets: secrets,
	}
}

// parseBundle 解析并校验导入文件，返回「纠正过什么」的提示列表。
//
// 校验原则：能修的直接修（域名去协议前缀、服务商小写、数值越界归位）、
// 修不了的报错（不是本应用的文件、格式版本太新）。宁可能用也别让人白填八项。
func parseBundle(raw []byte) (bundle, []string, error) {
	var b bundle
	if len(raw) == 0 {
		return b, nil, fmt.Errorf("文件是空的")
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return b, nil, fmt.Errorf("这不是有效的 JSON 文件（%v）", err)
	}
	if b.App != bundleApp {
		return b, nil, fmt.Errorf("这不是本应用导出的配置文件（文件里写着 app=%q）", b.App)
	}
	if b.Format <= 0 || b.Format > bundleFormat {
		return b, nil, fmt.Errorf("文件格式版本是 %d，当前程序只认到 %d，请先升级应用", b.Format, bundleFormat)
	}

	var warns []string

	// 域名：去重、去协议前缀、小写；非法项丢掉。
	before := len(b.Config.Domains)
	b.Config.Domains = normalizeDomains(b.Config.Domains)
	if dropped := before - len(b.Config.Domains); dropped > 0 {
		warns = append(warns, fmt.Sprintf("忽略了 %d 个看不懂的域名", dropped))
	}

	if b.Config.DDNSProvider != "" {
		p := strings.ToLower(strings.TrimSpace(b.Config.DDNSProvider))
		if _, ok := config.RequiredEnvByProvider[p]; ok {
			b.Config.DDNSProvider = p
		} else {
			warns = append(warns, fmt.Sprintf("服务商 %q 不认识，已按 Cloudflare 处理", b.Config.DDNSProvider))
			b.Config.DDNSProvider = "cloudflare"
		}
	}
	if b.Config.DDNSDomain != "" {
		b.Config.DDNSDomain = config.NormalizeDomain(b.Config.DDNSDomain)
	}

	// 数值越界归位，别让一个手改的文件把定时器搞成 0 或负数。
	if b.Config.TopN <= 0 {
		b.Config.TopN = 5
	}
	if b.Config.Candidates <= 0 {
		b.Config.Candidates = 100
	}
	if b.Config.IntervalMinutes < 0 {
		b.Config.IntervalMinutes = 0
	}

	// 密钥白名单：不在表里的 key 直接丢掉并提示，别静默吞了。
	if len(b.Secrets) > 0 {
		kept := make(map[string]string, len(b.Secrets))
		var dropped []string
		for k, v := range b.Secrets {
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			if !allowedSecretKeys[k] {
				dropped = append(dropped, k)
				continue
			}
			kept[k] = v
		}
		if len(dropped) > 0 {
			warns = append(warns, "忽略了不认识的密钥项 "+strings.Join(dropped, "、"))
		}
		b.Secrets = kept
	}

	return b, warns, nil
}

// handleExport 把当前设置（含密钥）打包成一个文件返回。
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	cfg := s.cfg.Clone()
	s.mu.Unlock()

	now := time.Now()
	b := buildBundle(cfg, config.DDNCredentials(), version, now)
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "生成备份文件失败: " + friendlyErr(err)})
		return
	}

	name := "cf-ddns-sidecar-" + now.Format("20060102-150405") + ".json"
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	// 里面是明文密钥，绝不能被中间代理或浏览器缓存住。
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

// handleImport 用上传的文件覆盖当前设置。
func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBundleBytes+1))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "读取上传内容失败: " + friendlyErr(err)})
		return
	}
	if len(raw) > maxBundleBytes {
		writeJSON(w, 400, map[string]string{"error": "文件太大了（正常备份只有几 KB）"})
		return
	}

	b, warns, err := parseBundle(raw)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}

	s.mu.Lock()
	cfg := s.cfg.Clone()
	s.mu.Unlock()

	cfg.AdGuard.URL = strings.TrimSpace(b.Config.AdGuardURL)
	cfg.AdGuard.Username = strings.TrimSpace(b.Config.AdGuardUsername)
	// 备份里没有 AdGuard 密码时保持原值，别把已存的密码清空。
	if b.Config.AdGuardPassword != "" {
		cfg.AdGuard.Password = b.Config.AdGuardPassword
	}
	cfg.Domains = b.Config.Domains
	cfg.Speed.TopN = b.Config.TopN
	cfg.Speed.BandwidthCandidates = b.Config.Candidates
	cfg.Speed.IntervalMinutes = b.Config.IntervalMinutes
	cfg.DDNS.Enabled = b.Config.DDNSEnabled
	cfg.DDNS.Provider = b.Config.DDNSProvider
	cfg.DDNS.Domain = b.Config.DDNSDomain
	if cfg.DDNS.Provider == "" {
		cfg.DDNS.Provider = "cloudflare"
	}

	if err := cfg.Save(); err != nil {
		writeJSON(w, 500, map[string]string{"error": "保存配置失败: " + friendlyErr(err)})
		return
	}

	// 密钥单独写：不覆盖备份里没有的项（比如这次只导出了 Cloudflare，
	// 原来的阿里云密钥应当留着，而不是被清空）。
	if len(b.Secrets) > 0 {
		if err := config.UpdateEnvFile(config.EnvFilePath(), b.Secrets); err != nil {
			warns = append(warns, "配置已恢复，但密钥写入失败: "+friendlyErr(err))
		}
	}

	s.mu.Lock()
	s.cfg = &cfg
	s.mu.Unlock()

	// 配置里的间隔/域名也要回写 ddns.env，和手动保存保持一致。
	if err := config.UpdateEnvFile(config.EnvFilePath(), map[string]string{
		"CFDDNS_PROVIDER":         cfg.DDNS.Provider,
		"CFDDNS_DOMAIN":           cfg.DDNS.Domain,
		"CFDDNS_INTERVAL_MINUTES": fmt.Sprint(cfg.Speed.IntervalMinutes),
	}); err != nil {
		warns = append(warns, "ddns.env 回写失败: "+friendlyErr(err))
	}

	writeJSON(w, 200, map[string]any{"ok": true, "warnings": warns})
}
