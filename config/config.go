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

// SpeedConfig 描述测速行为（映射到测速引擎 cfnb 的参数）。
type SpeedConfig struct {
	IntervalMinutes     int `json:"interval_minutes"`     // 自动测速间隔（分钟），0 表示不自动测
	TopN                int `json:"top_n"`                // 最终保留的候选 IP 数量
	BandwidthCandidates int `json:"bandwidth_candidates"` // 进入带宽测速的候选数
	// ExtraSources 是用户自己指定的候选来源，一行一条，三种写法：
	//   · IP 段   104.16.0.0/13   —— 本地在这些段里随机采样
	//   · 单 IP   104.16.1.1      —— 直接进候选，不抽样
	//   · 链接    https://...     —— 不本地解析，原样交给测速引擎自己去拉
	//
	// 留空 = 用内置的 Cloudflare 官方 15 个段（升级前的行为，一字未改）。
	// 非空 = **只用这些**：既不叠加官方段，也不再拉内置的两个外部聚合源。
	//
	// 为什么必须是「只用」而不是「叠加」：实测 zip.cm.edu.kg 一个源就能给
	// 12757 个 IP，叠加进来等于用户填的段被彻底淹没，设了跟没设一样。
	ExtraSources []string `json:"extra_sources,omitempty"`

	// EngineOverrides 是用户在「高级设置」里改过的测速引擎参数，
	// 键名与 engine.Schema 一一对应（比如 "HTTP_LATENCY_ENABLED": true）。
	//
	// 为什么用 map 而不是四十多个具名字段：cfnb 有 99 个参数、24 个布尔开关，
	// 全做成字段会让这个结构体变成一个没人看得懂的参数垃圾桶，而每加一个
	// 参数要动 config / engine / web / 前端四处，漏一处就静默失效。
	// 用一张表（engine.Schema）+ 一个 map，只有一处需要改。
	//
	// 只存「和默认值不同」的项（见 engine.NormalizeOverrides）：全是默认值时
	// 这里是 nil，config.json 里不会多出一个空对象，也不会因为以后改默认值
	// 而让老配置「被用户设定过」。
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
	// 这两个字段是 2026-11-17 才加的，老配置文件里没有，反序列化后就是零值，
	// 效果等同于以前写死的 1/600/300——升级不会改变用户现有记录的样子。
	TTL int `json:"ttl,omitempty"`
	// Proxied 只对 Cloudflare 有效：true 表示开橙色云朵（走 Cloudflare 代理）。
	Proxied bool `json:"proxied,omitempty"`

	// IPCount 是一次往域名里写几条记录：按测速排名从优到劣取前 N 条。
	// 0 表示 1 条——老配置文件没有这个字段，行为必须和以前一模一样。
	IPCount int `json:"ip_count,omitempty"`

	// RecordType 是要写的记录类型 / 同步模式：
	//   空 / "A"  → 只写 A（IPv4）
	//   "AAAA"    → 只写 AAAA（IPv6）
	//   "A+AAAA"  → 两族都写（2026-11-18 新增）
	// 老配置文件没有这个字段，反序列化后是空串，效果等同于 A——升级不会改变
	// 用户现有记录的任何一行。
	//
	// 字段名和 JSON key 保持 record_type 不变：改名会让所有已经存下来的配置
	// 在升级后「读不出自己选过什么」，一声不响地回到 A。
	RecordType string `json:"record_type,omitempty"`
}

// EffectiveRecordMode 返回实际要写的同步模式：A / AAAA / A+AAAA。
//
// 收敛规则本身在 ddns.NormalizeRecordMode（单一出处，别在这儿再抄一遍
// switch——抄了就会有两份规则各自漂移）。这里只负责「读进来的路径不报错」：
// 空串和任何写坏的值都按 A。开机、升级读配置不该因为一个字段写错就整体失败；
// 真正拦住非法值的是保存 `/api/config` 时的校验。
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
//
// 为什么要落盘：这几个数字是测速现算的，不在任何接口里，重启就没了。
// 而用户升级 App、重启容器的频率远高于他跑测速的频率——不存下来，
// 打开页面看到的就是一排「—」，反而像坏了。
//
// 全部字段都可省略：老配置文件里没有这一项，读进来是空切片，
// 界面就按「只有 IP、没有质量数据」渲染，和以前一样。
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
	//
	// 没有把 Domains 直接换成结构体切片，是因为 `Domains []string` 这件事
	// 已经被引擎参数、DDNS 推送、导入导出、老配置全部依赖着——换类型等于
	// 每一处都要跟着改，风险远大于收益。这里用「主列表 + 旁挂元信息」：
	// Domains 仍是唯一的权威（有哪些域名），缺条目就当「不包含子域」，
	// 老配置读进来照样能用。
	DomainMeta map[string]DomainMeta `json:"domain_meta,omitempty"`
	Speed      SpeedConfig           `json:"speed"`
	DDNS       DDNSConfig            `json:"ddns"`

	// IPv6ProbeURL 是 v6 测速用的 IPv6 段来源，**一行一个链接**。
	//
	// 为什么是一个多行字符串而不是 []string：这一栏原来只收一个链接，字段和
	// json 键（ipv6_probe_url）都已经写进了用户的 config.json 和备份文件。
	// 换类型等于所有老配置都要迁移，而多行字符串天然向后兼容——老值里没有换行，
	// 拆出来就是一条。想取链接列表用 IPv6SourceURLs()，别自己 split。
	//
	// 为什么不塞进 Speed.ExtraSources：那里是 IPv4 主测速的来源，解析器只认
	// IPv4 地址（nodeTokenRe / To4 判断）。v6 段混进去会被静默丢掉，用户看到
	// 的就是「我明明填了，测速还是只用那一个内置段」。两条链路各自存各自的，
	// 改这里不会影响主测速，也不会动 AdGuard / DDNS 的任何写入。
	//
	// 空 = 自动测速不跑 v6（只测 IPv4）；手动点「开始探测」时仍会回退到
	// 内置的 CF v6 段（v1.6.7 行为）。
	IPv6ProbeURL string `json:"ipv6_probe_url,omitempty"`

	// 运行状态（持久化便于重启后回显）
	LastIP   string `json:"last_ip,omitempty"`
	LastTime string `json:"last_time,omitempty"`
	// LastIPs 是上次测速里真正写进解析的那几条（按排名）。存下来是为了
	// 重启之后点「立即更新一次」还能把同一组推回去，不用重新测速；
	// 只存 LastIP 的话，重启后那一下会把多出来的几条悄悄删掉。
	LastIPs []string `json:"last_ips,omitempty"`
	// LastNodes 与 LastIPs 一一对应，多带速度、延迟、机房。
	// 只给界面看，不参与任何推送逻辑——推送认的仍然是 LastIPs。
	LastNodes []NodeStat `json:"last_nodes,omitempty"`

	// 上一条 v6 优选的结果。和上面那组 v4 字段是**两套独立的记录**，
	// 谁失败都不该影响另一个：v6 这一轮跑空时，v4 的结果照旧。
	//
	// 为什么要落盘而不是只放内存：v6 优选一次要 1~2 分钟，跑完只存在
	// 内存里的话，用户升级一次应用、或者容器重启一下，结果就没了，
	// 打开界面看到「还没有结果」，反而像功能坏了。
	LastIPv6      string     `json:"last_ipv6,omitempty"`
	LastIPv6IPs   []string   `json:"last_ipv6_ips,omitempty"`
	LastIPv6Nodes []NodeStat `json:"last_ipv6_nodes,omitempty"`
	LastIPv6Time  string     `json:"last_ipv6_time,omitempty"`

	// RewrittenDomains 是「上一次成功写进 AdGuard 重写的域名清单」，也就是
	// 本工具在 AdGuard 上认领过的域名。它只用来回答一个问题：**哪些旧记录
	// 现在可以删了**。
	//
	// 为什么非要有这个账本：写 AdGuard 从 2026-11-18 起改成「只动自己管的
	// 域名」，而「自己管的」就是当前域名列表（RewriteDomains）。用户从列表里
	// 删掉 a.com 之后，a.com 就不在列表里了，程序也就再没理由碰它——AdGuard
	// 上那条 a.com → 旧 IP 的记录会一直留着，家里设备查 a.com 还是走老地址，
	// 而界面上什么都看不出来。等于把一个「明目张胆的误删」换成一个「看不见的
	// 残留」。有这份账本，下次同步就知道「a.com 以前归我管、现在不管了」，
	// 把它清掉。
	//
	// 不删它也不影响别的：账本里的域名如果又加回列表，它立刻变回「自己管的」，
	// 照常重写，不需要任何迁移。
	RewrittenDomains []string `json:"rewritten_domains,omitempty"`

	// PendingSave 为 true 表示本次 Load 从 ddns.env 应用了一次性覆盖，
	// 调用方需要把结果落盘并清掉覆盖标记。不参与序列化。
	PendingSave bool `json:"-"`

	// RestoredFromBackup 为 true 表示主配置文件不见了，本次是从 config.json.bak
	// 恢复出来的。调用方应当把这个情况显式告诉用户——「静默退回默认值」正是
	// 2026-11-17 配置丢失事故里最误导人的地方：后台看起来一切正常，只是全空了。
	RestoredFromBackup bool `json:"-"`

	// RestoredFromUpgradeBackup 为 true 表示这次是从「升级前自动备份」恢复的
	// （数据目录整个被清空、config.json.bak 也没了那种），恢复来源目录见
	// RestoreMarkerSource()。
	//
	// 和上面那个分成两个字段，是因为要让用户看懂到底出了什么事：
	//   · 只有 .bak → 「升级把它们删了，但备份文件还在同一个目录里」
	//   · 连 .bak 都没了 → 「整个目录被删了，靠升级前搬到外面的那份救回来」
	// 两句话的严重程度不一样，混成一句用户就没法判断要不要报警。
	RestoredFromUpgradeBackup bool `json:"-"`
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
		// 这份配置是启动时从「升级前备份」捡回来的（见 restore.go）。
		// 必须让界面也知道——捡回来的配置看起来和正常的完全一样，
		// 不说的话用户会以为升级一切顺利，而实际上中间出过事。
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

// IPv6SourceURLs 把 v6 段来源按行拆成链接列表。
//
// 规则和「优选 IP 段」那边保持一致：一行一个，空行和 # 开头的注释行跳过。
// 返回的每条都已 trim，顺序保持原样（先填的先拉，日志里按这个顺序报错）。
//
// 为什么要有这个方法、而不是各处自己 strings.Split：判断「用户到底填没填」
// 分散在好几个地方（自动流程要不要跑 v6、探测要不要去拉、界面提示怎么写），
// 每处都自己拆一次迟早会出现「这里认为填了、那里认为没填」的分歧。
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
	if err := os.Rename(name, p); err != nil {
		return err
	}
	// 主文件已经落盘了，顺手在备份目录里也留一份（见 backup.go）。
	//
	// 放在这里、而不是只交给宿主机的 upgrade_init：那条路 2026-11-17 证明过
	// 靠不住（脚本没跑，装完配置就空了）。用户只要在后台点过一次保存，
	// 这里就会有一份最新的，下一次升级才真的能自己捡回来。
	//
	// 返回值刻意丢掉：备份写不进去（目录不存在、只读挂着、权限不对）绝不能
	// 让「保存配置」这个动作失败——那才是真要命的事。
	writeSnapshot()
	return nil
}

// RewriteDomains 返回真正要写进 AdGuard 重写的域名。
//
// 勾了「包含子域」的域名会多出一条 `*.域名`：AdGuard Home 的重写支持通配符，
// 一条 `*.a.com` 能盖住所有子域，比逐条列省事，也不会漏掉用户后来新建的子域。
//
// 顺序是「主域名，紧跟它的通配符」，和界面上的顺序一致，日志读起来才对得上。
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

// PruneDomainMeta 删掉不在 Domains 里的元信息。
//
// 不清理的话，用户删掉一个域名再加回来，会「继承」上一次的包含子域设置和
// 添加时间——看起来像删不掉。所以每次 Load 都按 Domains 对一遍。
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
	// DomainMeta 是 map，浅拷贝只会拷到同一个底层哈希表——保存配置时一边写、
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
	// 该清——共享底层数组就会边读边改。
	if len(c.RewrittenDomains) > 0 {
		cp.RewrittenDomains = append(make([]string, 0, len(c.RewrittenDomains)), c.RewrittenDomains...)
	}
	// ExtraSources 同理：保存配置时会整段替换，测速时另一个 goroutine 正在读它。
	if len(c.Speed.ExtraSources) > 0 {
		cp.Speed.ExtraSources = append(make([]string, 0, len(c.Speed.ExtraSources)), c.Speed.ExtraSources...)
	}
	// EngineOverrides 是 map，浅拷贝只会拷到同一个底层哈希表——保存配置时
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
