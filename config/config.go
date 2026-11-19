// Package config 定义本应用的统一配置。
//
// 设计原则：用户只需要在一个界面里看到「AdGuard 在哪」「要加速哪些域名」
// 「测速怎么跑」「域名解析推给谁」四件事，其余参数一概不暴露。
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/303528084/cf-ddns-sidecar/ddns"
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

// 来源模式：界面上下拉的三项。
const (
	SourceBuiltin = "builtin" // 用程序内置的链接，地址不出现在界面、配置、备份、日志里
	SourceCustom  = "custom"  // 用用户自己填的那份
	SourceOff     = "off"     // 这一族不测速
)

// 内置来源的链接。写死在程序里而不是放进配置：用户要的是「给这个应用装一个默认来源」，
// 不是把地址贴到别人眼前，所以配置、备份、日志里都只有「内置」两个字。
// 代价是换链接必须改这里重新发版。
const (
	BuiltinV4Source = "https://github.71557.qzz.io/https://raw.githubusercontent.com/303528084/cf-dns-select/refs/heads/main/ip.txt"
	BuiltinV6Source = "https://github.71557.qzz.io/https://raw.githubusercontent.com/303528084/cf-dns-select/refs/heads/main/ipv6.txt"
)

// SpeedConfig 描述测速行为（映射到测速引擎 cfnb 的参数）。
type SpeedConfig struct {
	IntervalMinutes     int `json:"interval_minutes"`     // 自动测速间隔（分钟），0 表示不自动测
	TopN                int `json:"top_n"`                // 最终保留的候选 IP 数量
	BandwidthCandidates int `json:"bandwidth_candidates"` // 进入带宽测速的候选数
	// SourceMode 决定「优选 IP 段」这一栏怎么生效，见上面的 SourceXxx。空值按
	// builtin 读：升级前的配置里没有这个字段，按关闭读会让所有人升级后一轮都没有
	// v4 候选，表现是解析记录停在原地不动。
	// ExtraSources 无论哪种模式都留着：用户切到「自定义」时要能看见上次填的东西。
	SourceMode string `json:"source_mode,omitempty"`
	// ExtraSources 是用户自己指定的候选来源，一行一条，三种写法：
	//   · IP 段   104.16.0.0/13  ：本地在这些段里随机采样
	//   · 单 IP   104.16.1.1     ：直接进候选，不抽样
	//   · 链接    https://...    ：不本地解析，原样交给测速引擎自己去拉
	//
	// 只在 SourceMode=custom 时生效。填了就只用这些，既不叠加官方段，也不再拉
	// 内置的两个外部聚合源：实测一个聚合源就能给 12757 个 IP，叠加等于用户填的
	// 段被彻底淹没。
	ExtraSources []string `json:"extra_sources,omitempty"`

	// EngineOverrides 是用户在「高级设置」里改过的测速引擎参数，键名与 engine.Schema
	// 一一对应（比如 "HTTP_LATENCY_ENABLED": true）。用 map 而不是四十多个具名字段：
	// cfnb 有 99 个参数、24 个布尔开关，做成字段会变成参数垃圾桶，且每加一个要动
	// config / engine / web / 前端四处，漏一处就静默失效。
	// 只存和默认值不同的项（见 engine.NormalizeOverrides），全是默认值时这里是 nil。
	EngineOverrides map[string]any `json:"engine_overrides,omitempty"`
}

// DDNSConfig 描述把最优 IP 写到自有域名解析记录的行为。
// 密钥不在此结构中（单独存 ddns.env，便于用户用文本编辑器批量改）。
type DDNSConfig struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"` // cloudflare / aliyun / dnspod / huawei
	Domain   string `json:"domain"`   // 目标域名，如 cf.example.com

	// TTL 是写出的解析记录的生存时间（秒），0 表示用本程序的默认值
	// （Cloudflare 自动、DNSPod 600、华为云 300、阿里云不传）。
	// 这两个字段 2026-11-17 才加，老配置反序列化后是零值，效果等同于以前写死的
	// 1/600/300，升级不会改变用户现有记录的样子。
	TTL int `json:"ttl,omitempty"`
	// Proxied 只对 Cloudflare 有效：true 表示开橙色云朵（走 Cloudflare 代理）。
	Proxied bool `json:"proxied,omitempty"`

	// IPCount 是一次往域名里写几条记录：按测速排名从优到劣取前 N 条。
	// 0 表示 1 条，老配置没有这个字段，行为必须和以前一模一样。
	IPCount int `json:"ip_count,omitempty"`

	// RecordType 是要写的记录类型：空 / "A" 只写 A，"AAAA" 只写 AAAA，
	// "A+AAAA" 两族都写（2026-11-18 新增）。老配置读进来是空串，效果等同于 A。
	// JSON key 保持 record_type 不变：改名会让已存下来的配置升级后读不出自己选过
	// 什么，一声不响地回到 A。
	RecordType string `json:"record_type,omitempty"`
}

// EffectiveRecordMode 返回实际要写的同步模式：A / AAAA / A+AAAA。
// 收敛规则本身在 ddns.NormalizeRecordMode（单一出处）。这里只保证读配置不报错：
// 空串和写坏的值都按 A，开机不该因为一个字段写错就整体失败，拦住非法值是保存时的事。
func (d DDNSConfig) EffectiveRecordMode() string {
	if m, err := ddns.NormalizeRecordMode(d.RecordType); err == nil {
		return m
	}
	return ddns.TypeA
}

// EffectiveIPCount 返回实际要写几条 A 记录。零值和负数都按 1 条处理。
func (d DDNSConfig) EffectiveIPCount() int {
	if d.IPCount <= 0 {
		return 1
	}
	return d.IPCount
}

// NodeStat 是「上次测速里每个 IP 的质量数据」，只用于界面展示。
// 要落盘是因为这几个数字测速现算、不在任何接口里，重启就没了；而用户重启容器的
// 频率远高于跑测速，不存下来打开页面就是一排「—」，反而像坏了。
// 全部字段可省略：老配置读进来是空切片，界面按「只有 IP、没有质量数据」渲染。
type NodeStat struct {
	IP    string  `json:"ip"`
	Speed float64 `json:"speed,omitempty"` // Mbps，0 表示这轮没测到
	Delay float64 `json:"delay,omitempty"` // 毫秒，0 表示这轮没测到
	Colo  string  `json:"colo,omitempty"`  // 真实机房代码，如 NRT
	Place string  `json:"place,omitempty"` // 「日本·东京(NRT)」，查不到机房时为空
}

// DomainMeta 是一个域名的附加信息。零值表示「不包含子域、没有时间」，
// 和「老配置里没有这一项」是同一个意思，不需要区分。
type DomainMeta struct {
	// Wildcard 表示这个域名要连子域一起管：AdGuard 里会多写一条 `*.域名`。
	Wildcard bool `json:"wildcard,omitempty"`
	// AddedAt 是添加时间（`2006-01-02 15:04:05`），只给界面显示，不参与任何逻辑。
	AddedAt string `json:"added_at,omitempty"`
}

// Config 是全部配置，持久化为 config.json。
type Config struct {
	AdGuard AdGuardConfig `json:"adguard"`
	Domains []string      `json:"domains"` // 要写入 AdGuard 重写的域名列表
	// DomainMeta 是每个域名的附加信息（是否包含子域、什么时候加的）。
	// 没有把 Domains 换成结构体切片：`Domains []string` 这件事已被引擎参数、DDNS 推送、
	// 导入导出、老配置全依赖着，换类型风险远大于收益。用「主列表 + 旁挂元信息」，
	// Domains 仍是唯一权威，缺条目就当「不包含子域」。
	DomainMeta map[string]DomainMeta `json:"domain_meta,omitempty"`
	Speed      SpeedConfig           `json:"speed"`
	DDNS       DDNSConfig            `json:"ddns"`

	// IPv6ProbeURL 是 v6 测速用的 IPv6 段来源，一行一个链接。
	// 用多行字符串而不是 []string：字段和 json 键都已写进用户的 config.json 和备份，
	// 换类型等于所有老配置都要迁移。取列表用 IPv6SourceURLs()，别自己 split。
	// 不塞进 Speed.ExtraSources：那里的解析器只认 IPv4（nodeTokenRe / To4），v6 段
	// 混进去会被静默丢掉。只在 IPv6SourceMode=custom 时生效。
	IPv6ProbeURL string `json:"ipv6_probe_url,omitempty"`
	// IPv6SourceMode 是 v6 那一栏的来源模式，取值同 SourceXxx。空值按 off 读：
	// 升级前 v6 留空就是不跑 v6，默认打开等于替用户改了行为。
	IPv6SourceMode string `json:"ipv6_source_mode,omitempty"`

	// HostsEnabled / HostsSource / HostsEntries 是「GitHub Hosts 源」那一块：不测速，
	// 把别人维护的 hosts 列表原样写进 AdGuard 重写表。开关、来源、结果各一套，不碰
	// Speed / DDNS；关掉就等于这一块不存在，由它写的域名会被清掉（靠 HostsEntries 对账）。
	// 不复用「要加速的域名」：那一栏所有域名共用同一个最优 IP，而 hosts 源里每个域名
	// 各有各的 IP。
	HostsEnabled bool `json:"hosts_enabled,omitempty"`
	// HostsSource 是 hosts 列表来源，**一行一个链接**（和 IPv6ProbeURL 同构，
	// 连校验函数都是同一个）。空 = 没配来源。
	HostsSource string `json:"hosts_source,omitempty"`
	// HostsEntries 是上一次成功拉取并解析出来的「域名 → IP」，一身两职，都得持久化：
	// 拉取失败时兜底（否则网络抖一下几十条重写全删、下轮再全加回来）；以及当「上一轮
	// 我认领了哪些域名」的账本（某域名从源里消失后只有它还记得，下次同步才能清掉旧记录）。
	// 存原始解析结果而不是「已写进 AdGuard 的域名」：两者在冲突时不一样（与加速域名同名
	// 的不归它写），用原始结果才能正确判断「这条现在还该不该存在」。
	HostsEntries map[string]string `json:"hosts_entries,omitempty"`
	// HostsSyncedAt 是上次成功同步的时间（只给界面显示，不参与判断）。
	HostsSyncedAt string `json:"hosts_synced_at,omitempty"`

	// 运行状态（持久化便于重启后回显）
	LastIP   string `json:"last_ip,omitempty"`
	LastTime string `json:"last_time,omitempty"`
	// LastIPs 是上次测速里真正写进解析的那几条（按排名）。存下来是为了
	// 重启之后点「立即更新一次」还能把同一组推回去，不用重新测速；
	// 只存 LastIP 的话，重启后那一下会把多出来的几条悄悄删掉。
	LastIPs []string `json:"last_ips,omitempty"`
	// LastNodes 与 LastIPs 一一对应，多带速度、延迟、机房。
	// 只给界面看，不参与任何推送逻辑，推送认的仍然是 LastIPs。
	LastNodes []NodeStat `json:"last_nodes,omitempty"`

	// 上一条 v6 优选的结果。和上面那组 v4 字段是两套独立记录，谁失败都不影响另一个。
	// 要落盘：v6 优选一次要 1~2 分钟，只放内存的话用户升级应用、容器重启一下就没了，
	// 打开界面看到「还没有结果」，反而像功能坏了。
	LastIPv6      string     `json:"last_ipv6,omitempty"`
	LastIPv6IPs   []string   `json:"last_ipv6_ips,omitempty"`
	LastIPv6Nodes []NodeStat `json:"last_ipv6_nodes,omitempty"`
	LastIPv6Time  string     `json:"last_ipv6_time,omitempty"`

	// RewrittenDomains 是「上一次成功写进 AdGuard 重写的域名清单」，也就是本工具认领过的
	// 域名，只用来回答一个问题：哪些旧记录现在可以删了。写 AdGuard 只动自己管的域名，
	// 而「自己管的」就是当前域名列表；用户删掉 a.com 之后就再没理由碰它，AdGuard 上那条
	// a.com → 旧 IP 会一直留着，家里设备还走老地址，界面上却看不出来，等于把明目张胆的
	// 误删换成一个看不见的残留。域名加回列表时它立刻变回「自己管的」，不需要迁移。
	RewrittenDomains []string `json:"rewritten_domains,omitempty"`

	// PendingSave 为 true 表示本次 Load 从 ddns.env 应用了一次性覆盖，
	// 调用方需要把结果落盘并清掉覆盖标记。不参与序列化。
	PendingSave bool `json:"-"`

	// RestoredFromBackup 为 true 表示主配置文件不见了，本次是从 config.json.bak
	// 恢复出来的。调用方应当把这个情况显式告诉用户，「静默退回默认值」正是
	// 2026-11-17 配置丢失事故里最误导人的地方：后台看起来一切正常，只是全空了。
	RestoredFromBackup bool `json:"-"`

	// RestoredFromUpgradeBackup 为 true 表示这次是从「升级前自动备份」恢复的
	// （数据目录整个被清空、config.json.bak 也没了那种），来源见 RestoreMarkerSource()。
	// 和上面那个分两个字段，是因为严重程度不一样：只有 .bak 没了是「升级删了备份还在
	// 同一个目录」，连 .bak 都没了是「整个目录被删、靠搬到外面那份救回来」。
	RestoredFromUpgradeBackup bool `json:"-"`
}

var (
	cfgPath     = "/app/data/config.json"
	cfgPathOnce sync.Once
	mu          sync.Mutex
)

// backupSuffix 是配置文件的备份后缀。每次写 config.json 前都把旧内容留在
// config.json.bak：新写的那份本身坏了（磁盘满、被截断）还能拿回上一版，
// config.json 被外部删掉时 Load 也能从它恢复，而不是静默退回默认值。
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
// 两种情况下会从 ddns.env / 进程环境取值：首次启动时用安装向导填的域名、服务商、
// 间隔打底；ddns.env 里带 CFDDNS_APPLY_ENV=1 时一次性覆盖已有配置。除此之外
// config.json 就是唯一真相。
func Load() (*Config, error) {
	c := Default()
	data, err := os.ReadFile(resolvePath())
	switch {
	case err == nil:
		if err := json.Unmarshal(data, c); err != nil {
			return nil, err
		}
		// 这份配置是从「升级前备份」捡回来的（见 restore.go）。必须让界面也知道：
		// 捡回来的配置看起来和正常的完全一样，不说的话用户会以为升级一切顺利。
		if restoredFromUpgradeBackup() {
			c.RestoredFromBackup = true
			c.RestoredFromUpgradeBackup = true
		}
		// 用户在飞牛「应用设置」里保存过：一次性覆盖
		if kv := LoadEnvFile(EnvFilePath()); envOrFile(kv, "CFDDNS_APPLY_ENV") == "1" {
			seedFromEnvFile(c, kv)
			c.PendingSave = true
		}
	case os.IsNotExist(err):
		// 主文件不见了。先看有没有上一次写入前留下的 .bak（见 Save）：有就恢复它，
		// 别让整份配置静默退回默认值。2026-11-17 那次升级把整个数据目录清空，
		// 程序把「文件不存在」当成首次启动、用默认值继续跑，用户看到的是空白后台。
		if bak, berr := os.ReadFile(resolvePath() + backupSuffix); berr == nil && len(bak) > 0 {
			if uerr := json.Unmarshal(bak, c); uerr == nil {
				c.RestoredFromBackup = true
				c.PendingSave = true
				break
			}
		}
		// 首次启动（安装向导刚写完 ddns.env）：用它打底，并立刻落盘。
		// 这里必须也置 PendingSave，否则 config.json 一直不存在、
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
	// 手改过的配置可能留下「域名已经不在列表里、元信息还在」的残留。
	c.PruneDomainMeta()
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

// IPv6SourceURLs 把 v6 段来源按行拆成链接列表，规则和「优选 IP 段」一致：
// 一行一个，空行和 # 注释跳过，顺序保持原样（先填的先拉，日志按这个顺序报错）。
// 抽成方法是为了「用户到底填没填」只有一个判据，各处分头 split 迟早会出现
// 「这里认为填了、那里认为没填」的分歧。
func (c *Config) IPv6SourceURLs() []string {
	var out []string
	for _, line := range strings.Split(c.IPv6ProbeURL, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		out = append(out, t)
	}
	return out
}

// HostsSourceURLs 和 IPv6SourceURLs 同一套规矩，单独一个方法是为了两处能各改各的：
// 哪天 hosts 那栏允许「只填域名不要协议」之类的例外，改这里不会连带改掉 v6 的解析。
func (c *Config) HostsSourceURLs() []string {
	var out []string
	for _, line := range strings.Split(c.HostsSource, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		out = append(out, t)
	}
	return out
}

// NormalizeSourceMode 校验界面传上来的来源模式。写错的值当场退回、不回落成默认：
// 静默改掉用户的选择（比如以为在测 v6、其实被关掉）只能等他自己发现记录不更新。
func NormalizeSourceMode(s string) (string, error) {
	switch s = strings.TrimSpace(s); s {
	case SourceBuiltin, SourceCustom, SourceOff:
		return s, nil
	}
	return "", fmt.Errorf("来源模式 %q 不认识，只有内置、自定义、关闭三种", s)
}

// EffectiveSourceMode 返回「优选 IP 段」实际生效的模式。缺字段按 builtin：
// 见 SpeedConfig.SourceMode 的说明。
func (c *Config) EffectiveSourceMode() string {
	switch c.Speed.SourceMode {
	case SourceCustom, SourceOff:
		return c.Speed.SourceMode
	}
	return SourceBuiltin
}

// EffectiveIPv6SourceMode 返回 v6 那一栏实际生效的模式。缺字段按 off：
// 见 IPv6SourceMode 的说明。
func (c *Config) EffectiveIPv6SourceMode() string {
	switch c.IPv6SourceMode {
	case SourceBuiltin, SourceCustom:
		return c.IPv6SourceMode
	}
	return SourceOff
}

// IPv4Sources 返回这一轮真正要用的 v4 来源原文（可能混着 IP 段 / 单 IP / 链接）。
// 关闭时返回空——调用方据此判定「这一族不测」，不要自己看 ExtraSources 猜。
func (c *Config) IPv4Sources() []string {
	switch c.EffectiveSourceMode() {
	case SourceBuiltin:
		return []string{BuiltinV4Source}
	case SourceCustom:
		return c.Speed.ExtraSources
	}
	return nil
}

// IPv6Sources 返回这一轮真正要用的 v6 链接。
func (c *Config) IPv6Sources() []string {
	switch c.EffectiveIPv6SourceMode() {
	case SourceBuiltin:
		return []string{BuiltinV6Source}
	case SourceCustom:
		return c.IPv6SourceURLs()
	}
	return nil
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
	// 落盘前把上一版留一份 .bak。失败不影响主流程，备份是加分项，
	// 不能因为它写不了就导致用户存不了配置。
	if old, rerr := os.ReadFile(p); rerr == nil && len(old) > 0 {
		_ = os.WriteFile(p+backupSuffix, old, 0o600)
	}
	if err := os.Rename(name, p); err != nil {
		return err
	}
	// 主文件已经落盘了，顺手在备份目录里也留一份（见 backup.go）。不交给宿主机的
	// upgrade_init：那条路 2026-11-17 证明靠不住（脚本没跑，装完配置就空了）。
	// 返回值刻意丢掉：备份写不进去绝不能让「保存配置」这个动作失败。
	writeSnapshot()
	return nil
}

// RewriteDomains 返回真正要写进 AdGuard 重写的域名：勾了「包含子域」的会多出一条
// `*.域名`（重写支持通配符，一条能盖住所有子域，也不会漏掉用户后来新建的）。
// 顺序是「主域名，紧跟它的通配符」，和界面上一致，日志读起来才对得上。
func (c Config) RewriteDomains() []string {
	out := make([]string, 0, len(c.Domains)*2)
	for _, d := range c.Domains {
		out = append(out, d)
		if m, ok := c.DomainMeta[d]; ok && m.Wildcard {
			out = append(out, "*."+d)
		}
	}
	return out
}

// PruneDomainMeta 删掉不在 Domains 里的元信息。不清理的话，用户删掉一个域名再加回来
// 会「继承」上一次的包含子域设置和添加时间，看起来像删不掉。每次 Load 都对一遍。
func (c *Config) PruneDomainMeta() {
	if len(c.DomainMeta) == 0 {
		return
	}
	keep := make(map[string]bool, len(c.Domains))
	for _, d := range c.Domains {
		keep[d] = true
	}
	for k := range c.DomainMeta {
		if !keep[k] {
			delete(c.DomainMeta, k)
		}
	}
	// 清空之后把 map 置 nil：留一个空 map 虽然会被 omitempty 忽略，但
	// 「有没有这张表」在代码里会被当成两件事，不如统一成没有。
	if len(c.DomainMeta) == 0 {
		c.DomainMeta = nil
	}
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
	// DomainMeta 是 map，浅拷贝只会拷到同一个底层哈希表，保存配置时一边写、
	// 测速线程一边读，和下面 EngineOverrides 是同一类问题。
	if len(c.DomainMeta) > 0 {
		m := make(map[string]DomainMeta, len(c.DomainMeta))
		for k, v := range c.DomainMeta {
			m[k] = v
		}
		cp.DomainMeta = m
	}
	// LastIPs 同样要拷一份：它是会被写进解析的列表，共享底层数组
	// 就意味着一个 goroutine 在读、另一个在改，属于最难查的那种问题。
	if len(c.LastIPs) > 0 {
		cp.LastIPs = append(make([]string, 0, len(c.LastIPs)), c.LastIPs...)
	}
	// LastNodes 和 LastIPs 一样是「测速线程写、状态接口读」，必须各存一份。
	if len(c.LastNodes) > 0 {
		cp.LastNodes = append(make([]NodeStat, 0, len(c.LastNodes)), c.LastNodes...)
	}
	// v6 那组同理：自动流程和手动探测都可能同时碰它们。
	if len(c.LastIPv6IPs) > 0 {
		cp.LastIPv6IPs = append(make([]string, 0, len(c.LastIPv6IPs)), c.LastIPv6IPs...)
	}
	if len(c.LastIPv6Nodes) > 0 {
		cp.LastIPv6Nodes = append(make([]NodeStat, 0, len(c.LastIPv6Nodes)), c.LastIPv6Nodes...)
	}
	// RewrittenDomains 是「测速线程写、域名页读」的一份账本，同样不能共享底层
	// 数组：测速那一路会在同步成功后整段替换它，而另一处正在遍历判断哪些域名
	// 该清，共享底层数组就会边读边改。
	if len(c.RewrittenDomains) > 0 {
		cp.RewrittenDomains = append(make([]string, 0, len(c.RewrittenDomains)), c.RewrittenDomains...)
	}
	// HostsEntries 是 map，同样一身两职：一轮测速结束会把整张表换成新拉到的
	// 结果，同一时刻 AdGuard 同步那一路正在遍历它算「该写哪些、该清哪些」。
	// 浅拷贝就是同一个底层哈希表，一边改一边读会直接 panic。
	if len(c.HostsEntries) > 0 {
		m := make(map[string]string, len(c.HostsEntries))
		for k, v := range c.HostsEntries {
			m[k] = v
		}
		cp.HostsEntries = m
	}
	// ExtraSources 同理：保存配置时会整段替换，测速时另一个 goroutine 正在读它。
	if len(c.Speed.ExtraSources) > 0 {
		cp.Speed.ExtraSources = append(make([]string, 0, len(c.Speed.ExtraSources)), c.Speed.ExtraSources...)
	}
	// EngineOverrides 是 map，浅拷贝只会拷到同一个底层哈希表，保存配置时
	// 一边删键一边被测速线程读，是 Go 里会直接 panic 的那种并发写。
	if len(c.Speed.EngineOverrides) > 0 {
		m := make(map[string]any, len(c.Speed.EngineOverrides))
		for k, v := range c.Speed.EngineOverrides {
			m[k] = v
		}
		cp.Speed.EngineOverrides = m
	}
	return cp
}
