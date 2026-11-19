package engine

// 测速引擎（cfnb）的参数表，以及「用户在后台改过的值」如何盖到默认值上。
//
// 为什么要有这张表，而不是把参数直接写进 config.json 结构体：
//
//	cfnb 有 99 个参数，其中 24 个是布尔开关。如果每个都做成一个 Go 字段，
//	config 包会被塞进四十多个字段，前端还要再手写四十多段 HTML，加一个
//	参数要改三处、漏一处就静默失效。这张表是唯一真相：后端拿它校验和合并，
//	前端拿它渲染界面和问号说明，两边不会走散。
//
// 表里**故意不收录**三类参数，理由写在 excludedKeys 里：它们要么会和我们
// 自己的 DDNS 抢写同一条解析记录，要么在没有对应凭证时填了也只是空转。
// 用户要的是「所有开关」，但把「开了就会弄坏现有功能」的开关递到手上不是
// 满足需求，是埋雷。

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// OptKind 决定界面上用什么控件，以及值怎么从 JSON 转成 cfnb 认识的样子。
type OptKind string

const (
	KindBool      OptKind = "bool"      // 开关
	KindInt       OptKind = "int"       // 整数
	KindFloat     OptKind = "float"     // 小数
	KindText      OptKind = "text"      // 单行文本
	KindLevel     OptKind = "level"     // 风险等级（枚举）
	KindPorts     OptKind = "ports"     // 端口列表，界面上一行 "443,8443"
	KindCountries OptKind = "countries" // 国家代码列表，界面上是可搜索的多选下拉
)

// OptSpec 描述一个可以覆盖的引擎参数。
type OptSpec struct {
	Key   string  `json:"key"`
	Label string  `json:"label"`
	Group string  `json:"group"`
	Kind  OptKind `json:"kind"`
	// Help 是问号里那段话。写给完全不懂编程的人看：先说这是什么，
	// 再说「动了会发生什么」，最后说「什么时候该动」。不写参数名。
	Help string `json:"help"`
	// Def 是程序实际写进引擎的值，也就是「恢复默认」的目标值。
	// 注意它不一定等于 cfnb 自己的默认值：比如前置黑名单 cfnb 默认是开的，
	// 我们替用户关掉了（聚合源的国家标签大多不准），这里的 Def 就是 false。
	// 界面上的「已改」标记和「恢复默认」都以这个值为准。
	Def any `json:"def"`
	// Min/Max 只对 int/float 生效，0 表示不限。越界直接钳住而不是报错，
	// 用户填 0 个并发不该被弹窗挡住，钳到 1 继续跑更符合预期。
	Min float64 `json:"min,omitempty"`
	Max float64 `json:"max,omitempty"`
	// Options 只对 level 生效。
	Options []string `json:"options,omitempty"`
}

// OptGroup 是界面上的一个分组标题。
type OptGroup struct {
	Key   string `json:"key"`
	Title string `json:"title"`
	Sub   string `json:"sub"`
}

// Groups 是分组列表，顺序即界面顺序。
var Groups = []OptGroup{
	{"flow", "验证与筛选", "决定「哪些 IP 算合格」。改动会直接影响结果，也会影响耗时"},
	{"quality", "排序与质量", "决定「合格的那些怎么排」。不影响能不能用，只影响先后"},
	{"perf", "性能与超时", "并发数、超时、重试。调错只会变慢或失败，没有「更对」的方向"},
	{"output", "输出与探测", "结果文件里写什么、拿哪个地址去验证节点"},
}

// riskLevels 是 cfnb 的风险等级枚举，顺序从最干净到最脏（见 RISK_LEVEL_ORDER）。
var riskLevels = []string{"极度纯净", "纯净", "轻微风险", "高风险", "极度危险"}

// Schema 是全部可覆盖参数。加参数就在这里加一行。
var Schema = []OptSpec{
	// ---------- flow：验证与筛选 ----------
	{
		Key: "TEST_AVAILABILITY", Label: "反代验证", Group: "flow", Kind: KindBool, Def: true,
		Help: "TCP 连得上不等于网页打得开。打开后会把候选 IP 真的当代理去访问一次目标站，连不通的直接淘汰。" +
			"这是本产品最有价值的一步，关掉之后选出来的 IP 可能「测速很好看，但浏览器打不开」。建议一直开着。",
	},
	{
		Key: "AVAILABILITY_TEST_ROUNDS", Label: "反代验证轮数", Group: "flow", Kind: KindInt, Def: 3, Min: 1, Max: 10,
		Help: "同一个 IP 验证几次，全过才算合格。调高更稳（偶发抖动能被滤掉），但这一轮耗时也成倍增加；" +
			"调低到 1 会快，代价是偶尔把「刚好抖了一下」的好 IP 丢掉。默认 3 是实测下来比较平衡的值。",
	},
	{
		Key: "AVAILABILITY_RETRY_MAX", Label: "反代验证整轮重试次数", Group: "flow", Kind: KindInt, Def: 3, Min: 1, Max: 10,
		Help: "整轮一个都没通过时，最多再重来几轮。只有「一个都没过」才会触发，正常情况下不会多花时间。" +
			"如果你的网络本来就时通时不通，调高一点能少丢一轮结果。",
	},
	{
		Key: "AVAILABILITY_INNER_RETRY_ENABLED", Label: "单个节点失败后内部重试", Group: "flow", Kind: KindBool, Def: true,
		Help: "某个 IP 验证失败时，立刻再试一两次再判死刑。网络抖动大多是一瞬间的事，开了能少误杀好 IP。" +
			"关掉会让反代验证更快，但误杀率会上升。",
	},
	{
		Key: "PRE_FILTER_PORT_ENABLED", Label: "端口预过滤", Group: "flow", Kind: KindBool, Def: true,
		Help: "验证之前先按端口筛一遍，只留下「端口列表」里的那些。聚合源里混着大量非 443 的地址，" +
			"先筛掉能省下大把验证时间。除非你确实要用别的端口，否则别关。",
	},
	{
		Key: "PRE_FILTER_PORTS", Label: "允许的端口", Group: "flow", Kind: KindPorts, Def: []int{443},
		Help: "只有这些端口的节点会进入验证。Cloudflare 支持的 HTTPS 端口是 443 / 2053 / 2083 / 2087 / 2096 / 8443。" +
			"填多个用逗号隔开，比如 443,8443。填了别的端口（比如 80）会导致验证全部失败。",
	},
	{
		Key: "FORCE_DIRECT", Label: "强制直连（不走代理）", Group: "flow", Kind: KindBool, Def: true,
		Help: "测速时清掉所有代理环境变量，保证量的是「你的宽带」到 Cloudflare 的速度。" +
			"关掉之后如果 NAS 上恰好配了全局代理，测出来的速度就是代理的速度——那不是你要优选的东西。",
	},
	{
		Key: "PRE_FILTER_BLOCKED_ENABLED", Label: "前置黑名单", Group: "flow", Kind: KindBool, Def: false,
		Help: "按「前置黑名单的国家」剔节点。**默认关着**。" +
			"注意它其实也是**测完、探到真实机房位置之后**才剔的（和「DNS 黑名单」同一套办法），" +
			"不是按候选自带的国家标签——那个 #US 是我们为了跑通流程补的占位值，不是真实位置。" +
			"查不到位置的节点会留着不动。",
	},
	{
		Key: "PRE_FILTER_BLOCKED_COUNTRIES", Label: "前置黑名单的国家", Group: "flow", Kind: KindCountries, Def: []string{"CN"},
		Help: "点开下拉勾选国家，可多选，也能搜中文名或代码。不用手填两位代码。只有上面那个开关打开时才生效。",
	},
	// 下面这两个开关以前标签接反了：叫「前置白名单」的那个对应引擎的
	// 黑名单开关，叫「DNS 黑名单」的那个才是白名单开关。引擎自己的日志就是
	// 铁证，它把白名单那条印成「前置白名单 启用」，把黑名单那条印成
	// 「DNS黑名单过滤」。接反的后果不是显示难看，而是**开了正好反着来**：
	// 想只留香港的人打开「前置白名单」，实际打开的是那份含 HK 的黑名单。
	// 现在按引擎的真实归属摆，并且让每个开关紧挨着它管的那份名单。
	{
		Key: "FILTER_COUNTRIES_ENABLED", Label: "前置白名单", Group: "flow", Kind: KindBool, Def: false,
		Help: "打开后只留下「前置白名单的国家」里那些。**默认关**。" +
			"注意筛的是**测完之后探到的真实机房位置**——IPv4 和 IPv6 都一样，" +
			"所以筛不到位置的节点算不通过（没证据是香港就不算数）。" +
			"代价是被筛掉的节点也测了一遍，一轮会慢一些；想快就把这个开关关掉。",
	},
	{
		Key: "ALLOWED_COUNTRIES", Label: "前置白名单的国家", Group: "flow", Kind: KindCountries, Def: []string{"HK"},
		Help: "只保留名单里的国家。注意这个名单**默认是 HK**：一旦打开「前置白名单」，" +
			"非香港节点会全部消失，这是很多人「优选不出东西」的原因。在下拉里勾选国家，不用手填代码。",
	},
	{
		Key: "FILTER_BLOCKED_COUNTRIES_ENABLED", Label: "DNS 黑名单", Group: "flow", Kind: KindBool, Def: false,
		Help: "测完并探到真实机房位置之后，按「DNS 黑名单的国家」再剔一次。" +
			"默认关。IPv4 和 IPv6 都照这份名单剔，剔的是真实位置；查不到位置的留着不动" +
			"（不能因为查不到就假定它违规）。",
	},
	{
		Key: "BLOCKED_COUNTRIES", Label: "DNS 黑名单的国家", Group: "flow", Kind: KindCountries,
		Def: []string{"BD", "BI", "BY", "CD", "CF", "CN", "CU", "DE", "ET", "HK", "IR", "KP", "LY", "MO", "NG", "NL", "PK", "RU", "SD", "SO", "SY", "TH", "TW", "UA", "VE", "VN", "YE", "ZW"},
		Help: "这个名单很长，而且里面包含 CN 和 HK——上游项目按「内容合规」挑的。" +
			"下拉里可以逐条勾掉或勾上，不用手填代码。除非你明确知道要屏蔽哪些地区，否则别动。只有「DNS 黑名单」打开时才生效。",
	},
	{
		Key: "OUTPUT_ALLOWED_COUNTRIES", Label: "输出白名单的国家", Group: "flow", Kind: KindCountries, Def: []string{"HK"},
		Help: "写结果文件时只保留名单里的国家。默认只有 HK，所以打开「输出白名单」之前先在下拉里把国家勾对。",
	},
	{
		Key: "OUTPUT_FILTER_COUNTRIES_ENABLED", Label: "输出白名单", Group: "flow", Kind: KindBool, Def: false,
		Help: "最后一步再按国家筛一次。默认关，而且名单默认是 HK——打开前先把上面的名单改对，" +
			"否则结果会只剩香港节点，看起来像「优选坏了」。",
	},
	{
		Key: "FILTER_IPV6_AVAILABILITY", Label: "DNS 阶段过滤 IPv6", Group: "flow", Kind: KindBool, Def: true,
		Help: "写结果之前，再确认一次这个节点是不是真的支持 IPv6 访问。开着能避免「挑了个 v6 地址，你的网络却连不上」。" +
			"如果你的宽带没有 IPv6，保持开着反而更省事。",
	},
	{
		Key: "DNS_IP_RISK_FILTER_ENABLED", Label: "IP 风险过滤", Group: "flow", Kind: KindBool, Def: false,
		Help: "去查每个 IP 的「风险等级」（有没有被滥用、是不是机房 IP 之类），把太脏的剔掉。" +
			"注意这和 1034 不是一回事：1034 是 Cloudflare 不认这个边缘 IP，风险过滤查的是 IP 本身的名声。" +
			"开了会多几十次外部请求，也会让候选变少。",
	},
	{
		Key: "DNS_IP_RISK_MAX_LEVEL", Label: "风险过滤放宽到", Group: "flow", Kind: KindLevel, Def: "高风险", Options: riskLevels,
		Help: "风险不高于这个等级的才保留。选「纯净」最严（只留最干净的），选「极度危险」等于不过滤。" +
			"只有上面那个开关打开时才生效。",
	},
	{
		Key: "IP_CALIBRATION_ENABLED", Label: "IP 地区校准", Group: "flow", Kind: KindBool, Def: false,
		Help: "向第三方服务查每个 IP 的真实归属地，用来修正 #US 那种不准的国家标签。" +
			"需要额外的令牌，没配令牌时会直接跳过。我们已经在用机房代码（NRT / LAX 这些）显示位置，一般用不上它。",
	},

	// ---------- quality：排序与质量 ----------
	{
		Key: "USE_GLOBAL_MODE", Label: "全局最优模式", Group: "quality", Kind: KindBool, Def: true,
		Help: "打开 = 所有节点一起排名，取前 N 个（这是你要的效果）。关掉 = 按国家分组，每个国家各取几个，" +
			"适合「我要美国一个、日本一个」这种用法。关掉后「保留候选 IP 数」会按国家分。",
	},
	{
		Key: "PER_COUNTRY_TOP_N", Label: "每个国家保留几个", Group: "quality", Kind: KindInt, Def: 1, Min: 1, Max: 10,
		Help: "只有关掉「全局最优模式」时才生效。",
	},
	{
		Key: "HTTP_LATENCY_ENABLED", Label: "延迟/抖动排序", Group: "quality", Kind: KindBool, Def: false,
		Help: "额外量一次「完整 HTTP 请求」的耗时和抖动，排序时把这两个也算进去。开了更贴近浏览器里的真实体感" +
			"（TCP 握手快不等于网页快），代价是多一轮请求、整轮更慢。默认关。",
	},
	{
		Key: "SPEED_WEIGHT", Label: "速度权重", Group: "quality", Kind: KindFloat, Def: 3.0, Min: 0, Max: 10,
		Help: "综合评分里「下载速度」占多少。调高 = 更偏向快的；调到 0 = 完全不看速度。一般不用动。",
	},
	{
		Key: "TCP_LATENCY_WEIGHT", Label: "TCP 延迟权重", Group: "quality", Kind: KindFloat, Def: 0.0, Min: 0, Max: 10,
		Help: "综合评分里「TCP 握手延迟」占多少。默认 0（不看）。想让「点一下就有反应」的节点排前面，可以调到 1~3。",
	},
	{
		Key: "HTTP_LATENCY_WEIGHT", Label: "HTTP 延迟权重", Group: "quality", Kind: KindFloat, Def: 3.0, Min: 0, Max: 10,
		Help: "只有打开「延迟/抖动排序」时才有数据。权重越高越偏向响应快的节点。",
	},
	{
		Key: "JITTER_WEIGHT", Label: "抖动权重", Group: "quality", Kind: KindFloat, Def: 3.0, Min: 0, Max: 10,
		Help: "只有打开「延迟/抖动排序」时才有数据。权重越高越惩罚「忽快忽慢」的节点。" +
			"看视频、打游戏卡不卡，主要看这个。",
	},
	{
		Key: "MIN_SUCCESS_RATE", Label: "TCP 成功率下限", Group: "quality", Kind: KindFloat, Def: 1.0, Min: 0, Max: 1,
		Help: "探测几次里至少成功几次才算合格，填 0~1 之间的小数。1 = 必须全中（默认，最严）；" +
			"0.5 = 一半成功就留。网络差的线路可以适当放宽，否则可能一个都选不出来。",
	},
	{
		Key: "TCP_PROBES", Label: "TCP 探测次数", Group: "quality", Kind: KindInt, Def: 1, Min: 1, Max: 10,
		Help: "每个 IP 做几次 TCP 握手。次数多延迟测得准，但耗时成倍增加。默认 1 次。",
	},

	// ---------- perf：性能与超时 ----------
	{
		Key: "MAX_WORKERS", Label: "总并发数", Group: "perf", Kind: KindInt, Def: 300, Min: 1, Max: 1000,
		Help: "同时处理多少个节点。调低会让整轮慢好几倍；调高对结果没好处，还可能被运营商当成异常流量。" +
			"除非 NAS 明显卡住，否则别动。",
	},
	{
		Key: "AVAILABILITY_WORKERS", Label: "反代验证并发数", Group: "perf", Kind: KindInt, Def: 300, Min: 1, Max: 1000,
		Help: "同时验证多少个节点。同上：只影响快慢。",
	},
	{
		Key: "BANDWIDTH_WORKERS", Label: "带宽测速并发数", Group: "perf", Kind: KindInt, Def: 3, Min: 1, Max: 20,
		Help: "同时下载测几个节点。这个**不能调高**：一条宽带的总带宽是固定的，同时测 10 个等于每个都只分到十分之一，" +
			"测出来的速度全部失真。默认 3 已经偏激进。",
	},
	{
		Key: "BANDWIDTH_SIZE_MB", Label: "测速文件大小（MB）", Group: "perf", Kind: KindFloat, Def: 1.0, Min: 0.1, Max: 50,
		Help: "每个节点下载多少数据来算速度。文件越大越准，但越慢、越费流量。小带宽线路（比如 10M 以下）" +
			"把文件调小反而更准——不然测一次要等很久，中途波动全被平均掉了。",
	},
	{
		Key: "BANDWIDTH_TIMEOUT", Label: "带宽测速超时（秒）", Group: "perf", Kind: KindFloat, Def: 3.0, Min: 1, Max: 60,
		Help: "单个节点下载最多等多久。调大能在慢线路上测出结果，代价是坏节点会拖住整轮。",
	},
	{
		Key: "BANDWIDTH_RETRY_MAX", Label: "带宽测速重试次数", Group: "perf", Kind: KindInt, Def: 3, Min: 1, Max: 10,
		Help: "一个都没测出速度时最多重来几轮。日志里那句「带宽测速 第 1/3 轮」就是它。",
	},
	{
		Key: "TIMEOUT", Label: "通用超时（秒）", Group: "perf", Kind: KindFloat, Def: 3.0, Min: 1, Max: 60,
		Help: "网络请求的兜底超时。一般不用动，具体阶段都有各自更细的超时。",
	},
	{
		Key: "ENABLE_LOGGING", Label: "引擎自己写日志文件", Group: "perf", Kind: KindBool, Def: false,
		Help: "让测速引擎额外把日志写成一个文件。我们的后台已经完整显示它的输出了，一般不需要再开。" +
			"开了会多占一点磁盘。",
	},

	// ---------- output：输出与探测 ----------
	{
		Key: "IP_TXT_SHOW_BANDWIDTH", Label: "结果里带速度", Group: "output", Kind: KindBool, Def: true,
		Help: "结果文件的每一行后面写上实测速度。**界面上的「速度」那一列就来自这里**，关掉之后页面会变成一排「—」。",
	},
	{
		Key: "IP_TXT_SHOW_LATENCY", Label: "结果里带延迟", Group: "output", Kind: KindBool, Def: true,
		Help: "结果文件的每一行后面写上 TCP 延迟。同上：关掉之后页面「延迟」那一列全是「—」。",
	},
	{
		Key: "IP_TXT_SHOW_HTTP_LATENCY", Label: "结果里带 HTTP 延迟", Group: "output", Kind: KindBool, Def: false,
		Help: "额外写上完整 HTTP 请求的耗时。只有打开「延迟/抖动排序」才有数据。一般不用开。",
	},
	{
		Key: "IP_TXT_SHOW_HTTP_JITTER", Label: "结果里带抖动", Group: "output", Kind: KindBool, Def: false,
		Help: "额外写上抖动值。同上，依赖「延迟/抖动排序」。",
	},
	{
		Key: "PROBE_HOST", Label: "拿哪个域名做验证", Group: "output", Kind: KindText, Def: "cloudflare-ech.com",
		Help: "反代验证时假装要访问哪个网站。默认是一个 Cloudflare 自己的域名。" +
			"**改成你自己的域名有意义**：这样验证时就带上「这个边缘 IP 认不认你的站」这层判断，能提前发现 1034。" +
			"但注意它只验证、不筛选，真正的 1034 剔除由程序自己那一步做。",
	},
	{
		Key: "PROBE_PATH", Label: "验证访问的路径", Group: "output", Kind: KindText, Def: "/cdn-cgi/trace",
		Help: "配合上一项使用。Cloudflare 的域名都有这个路径，返回一小段纯文本，最省流量。" +
			"改成别的路径会让验证变慢、也更容易被目标站限流。",
	},
}

// specByKey 是 Schema 的索引，查起来 O(1)。
var specByKey = func() map[string]OptSpec {
	m := make(map[string]OptSpec, len(Schema))
	for _, s := range Schema {
		m[s.Key] = s
	}
	return m
}()

// Lookup 按参数名取说明，找不到返回 false。
func Lookup(key string) (OptSpec, bool) {
	s, ok := specByKey[key]
	return s, ok
}

// NormalizeOverrides 把用户存的覆盖值整理成 cfnb 认识的样子。
//
// 为什么要这一步：值是从 JSON 来的，数字一律是 float64，而 cfnb 那边
// `TCP_PROBES` 拿到 1.5 会在 `range()` 里直接抛异常；列表从界面上来是
// 字符串 "443,8443"，得拆成 []int。这些转换放在一处，写配置的地方就
// 不用再操心类型。
//
// 未知参数名**直接丢弃**而不是报错：老版本存下的键在升级后可能已经不在
// 表里了，为这个让整次保存失败，用户会莫名其妙地存不上配置。
func NormalizeOverrides(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		spec, ok := specByKey[k]
		if !ok {
			continue
		}
		v, ok := normalizeValue(spec, in[k])
		if !ok {
			continue
		}
		// 和默认值一样就不必存：存下来只会在 config.json 里堆一串
		// 「看起来是用户设的、其实是默认值」的键，以后改默认值也不生效。
		if isSameValue(v, spec.Def) {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeValue(spec OptSpec, raw any) (any, bool) {
	switch spec.Kind {
	case KindBool:
		switch v := raw.(type) {
		case bool:
			return v, true
		case string:
			b, err := strconv.ParseBool(strings.TrimSpace(v))
			return b, err == nil
		}
		return nil, false
	case KindInt:
		f, ok := toFloat(raw)
		if !ok {
			return nil, false
		}
		return int(clamp(f, spec.Min, spec.Max)), true
	case KindFloat:
		f, ok := toFloat(raw)
		if !ok {
			return nil, false
		}
		return clamp(f, spec.Min, spec.Max), true
	case KindText:
		s, ok := raw.(string)
		if !ok {
			return nil, false
		}
		s = strings.TrimSpace(s)
		if s == "" {
			return nil, false
		}
		return s, true
	case KindLevel:
		s, ok := raw.(string)
		if !ok {
			return nil, false
		}
		s = strings.TrimSpace(s)
		for _, lv := range spec.Options {
			if s == lv {
				return s, true
			}
		}
		return nil, false
	case KindPorts:
		return normalizePorts(raw), true
	case KindCountries:
		return normalizeCountries(raw), true
	}
	return nil, false
}

func toFloat(raw any) (float64, bool) {
	switch v := raw.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return f, err == nil
	}
	return 0, false
}

func clamp(v, min, max float64) float64 {
	if min > 0 && v < min {
		v = min
	}
	if max > 0 && v > max {
		v = max
	}
	return v
}

// normalizePorts 接受 "443,8443" 或 []any{443,8443} 或 []int{443}。
// 端口范围外的值直接丢掉，填 0 或 99999 只会让验证全失败。
func normalizePorts(raw any) []int {
	nums := collectInts(raw)
	out := make([]int, 0, len(nums))
	for _, n := range nums {
		if n > 0 && n < 65536 {
			out = append(out, n)
		}
	}
	return out
}

// normalizeCountries 接受 "HK,JP" 或 ["HK","JP"]，统一成大写两字母。
// 认不出的片段丢掉，而不是整条失败：用户写 "香港" 不该让保存按钮报错。
func normalizeCountries(raw any) []string {
	var parts []string
	switch v := raw.(type) {
	case string:
		parts = strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '，' || r == ' ' || r == '\n' || r == '\t' })
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				parts = append(parts, s)
			}
		}
	case []string:
		parts = v
	}
	out := make([]string, 0, len(parts))
	seen := make(map[string]bool, len(parts))
	for _, p := range parts {
		p = strings.ToUpper(strings.TrimSpace(p))
		if len(p) != 2 || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func collectInts(raw any) []int {
	switch v := raw.(type) {
	case string:
		var out []int
		for _, p := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '，' || r == ' ' }) {
			if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
				out = append(out, n)
			}
		}
		return out
	case []any:
		var out []int
		for _, x := range v {
			if f, ok := toFloat(x); ok {
				out = append(out, int(f))
			}
		}
		return out
	case []int:
		return v
	}
	return nil
}

// isSameValue 只用于「和默认值相同就不存」这一件事，所以只处理表里出现的类型。
func isSameValue(a, b any) bool {
	switch av := a.(type) {
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case int:
		bv, ok := b.(int)
		return ok && av == bv
	case float64:
		switch bv := b.(type) {
		case float64:
			return av == bv
		case int:
			return av == float64(bv)
		}
		return false
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case []int:
		bv, ok := b.([]int)
		return ok && equalInts(av, bv)
	case []string:
		bv, ok := b.([]string)
		return ok && equalStrings(av, bv)
	}
	return false
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ApplyOverrides 把整理过的覆盖值盖到已经拼好的引擎配置上。
//
// 只认 Schema 里的键：这是唯一一道「用户手改 config.json 塞进奇怪参数」
// 的闸门。丢弃而不是报错，理由同上。
func ApplyOverrides(cfg map[string]any, ov map[string]any) {
	for k, v := range ov {
		spec, ok := specByKey[k]
		if !ok {
			continue
		}
		nv, ok := normalizeValue(spec, v)
		if !ok {
			continue
		}
		cfg[k] = nv
	}
}

// DescribeOverrides 把一组覆盖值翻成人话，供日志使用。
//
// 为什么要打日志：用户改过一个开关、过几天忘了，结果行为和预期不符时，
// 唯一的线索就是「这一轮到底按什么参数跑的」。参数有四十个，不能全打，
// 只打改过的。
func DescribeOverrides(ov map[string]any) string {
	if len(ov) == 0 {
		return ""
	}
	keys := make([]string, 0, len(ov))
	for k := range ov {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		spec, ok := specByKey[k]
		label := k
		if ok {
			label = spec.Label
		}
		parts = append(parts, fmt.Sprintf("%s=%v", label, ov[k]))
	}
	return strings.Join(parts, "、")
}
