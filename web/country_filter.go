package web

// 「按真实机房位置筛节点」——IPv4 和 IPv6 共用的一套。
//
// 为什么要有这么一层：候选地址里的 `#US` 是**占位标签**（web/candidates.go 为了
// 满足引擎的解析格式补的，引擎遇到没有国家标签的裸 IP 会逐条去探测），真实位置
// 要测完再去问 Cloudflare 的 `/cdn-cgi/trace`。所以「只留香港」这类设置在引擎
// 内部按标签筛，筛的是假数据：轻则空转（`#US` 不在黑名单里），重则把候选全杀光
// （白名单只勾 HK 时）。
//
// 做法：引擎侧一律不按国家筛（见 countryFilterKeys），测完拿到真实机房位置之后
// 再在这里筛。代价是被筛掉的节点也白测了一遍——日志里如实写出来，不装作没发生。
//
// 2026-11-18 先在 v6 上做了这件事，同一天按用户要求把 v4 也改成同一套，
// 两条路径共用这里的判断，免得「v4 筛得对 v6 筛得错」这种分叉。

import (
	"fmt"
	"sort"
	"strings"

	"github.com/303528084/cf-ddns-sidecar/config"
	"github.com/303528084/cf-ddns-sidecar/engine"
)

// countryFilterKeys 是「按国家筛」的四组开关与名单。
//
// 这 8 个键**必须**从交给引擎的覆盖表里剔除：引擎拿它们按占位标签筛，
// 结果只会是错的。加新键时记得同步 v6NotPassed 和这里的测试。
var countryFilterKeys = []string{
	"FILTER_COUNTRIES_ENABLED", "ALLOWED_COUNTRIES", // 前置白名单（键名和用途是反的，见项目卡片）
	"FILTER_BLOCKED_COUNTRIES_ENABLED", "BLOCKED_COUNTRIES", // DNS 黑名单
	"PRE_FILTER_BLOCKED_ENABLED", "PRE_FILTER_BLOCKED_COUNTRIES", // 前置黑名单
	"OUTPUT_FILTER_COUNTRIES_ENABLED", "OUTPUT_ALLOWED_COUNTRIES", // 输出白名单
}

// isCountryFilterKey 判断某个高级设置键是不是「按国家筛」的。
func isCountryFilterKey(k string) bool {
	for _, c := range countryFilterKeys {
		if c == k {
			return true
		}
	}
	return false
}

// v4Overrides 拼出 v4 主测速要交给引擎的覆盖表：用户改过的值，去掉按国家筛的那 8 个。
//
// 为什么删而不是覆盖成 false：删掉之后引擎用基础配置里的默认值（全是关），
// 而「覆盖成 false」在日志里会显示成「用户改过」，把人引到错的方向。
func v4Overrides(cfg config.Config) map[string]any {
	src := cfg.Speed.EngineOverrides
	out := make(map[string]any, len(src))
	for k, v := range src {
		if isCountryFilterKey(k) {
			continue
		}
		out[k] = v
	}
	return out
}

// countryFilter 是「这一轮结果按真实机房位置怎么筛」的一次决定。
//
// Allow 与 Deny 同时为空时表示「什么都不筛」，此时一条都不动（老行为）。
type countryFilter struct {
	Allow map[string]bool // 非空 = 只留这些国家
	Deny  map[string]bool // 剔掉这些国家
	Why   []string        // 这次按哪几条规则筛的，给日志用
}

// Active 表示这一轮是否真的要筛。
func (f countryFilter) Active() bool { return len(f.Allow) > 0 || len(f.Deny) > 0 }

// countryFilterFrom 把「高级设置」里四组国家开关与名单翻译成一个筛法。
//
// 为什么白名单取交集、黑名单取并集：两份白名单都是「只留」，两个「只留」
// 同时成立就是同时满足；两份黑名单都是「不要」，任一成立就成立。
// 注意名单要走 effectiveValue：名单没被改过时配置里没有这个键，但它有一个
// 非空的默认值（前置白名单默认 HK），直接读覆盖表会读成空名单 = 不筛。
func countryFilterFrom(cfg config.Config) countryFilter {
	var f countryFilter
	ov := cfg.Speed.EngineOverrides

	// 白名单：前置白名单 → 输出白名单（后者在前者的基础上再收窄）
	if switchOn(ov, "FILTER_COUNTRIES_ENABLED") {
		if l := countryList(effectiveValue(ov, "ALLOWED_COUNTRIES")); len(l) > 0 {
			f.Allow = allowMerge(f.Allow, l)
			f.Why = append(f.Why, "前置白名单「"+strings.Join(l, "/")+"」")
		}
	}
	if switchOn(ov, "OUTPUT_FILTER_COUNTRIES_ENABLED") {
		if l := countryList(effectiveValue(ov, "OUTPUT_ALLOWED_COUNTRIES")); len(l) > 0 {
			f.Allow = allowMerge(f.Allow, l)
			f.Why = append(f.Why, "输出白名单「"+strings.Join(l, "/")+"」")
		}
	}

	// 黑名单：前置黑名单 + DNS 黑名单，合并成一份「不要」
	if switchOn(ov, "FILTER_BLOCKED_COUNTRIES_ENABLED") {
		if l := countryList(effectiveValue(ov, "BLOCKED_COUNTRIES")); len(l) > 0 {
			f.Deny = denyMerge(f.Deny, l)
			f.Why = append(f.Why, "DNS 黑名单「"+strings.Join(l, "/")+"」")
		}
	}
	if switchOn(ov, "PRE_FILTER_BLOCKED_ENABLED") {
		if l := countryList(effectiveValue(ov, "PRE_FILTER_BLOCKED_COUNTRIES")); len(l) > 0 {
			f.Deny = denyMerge(f.Deny, l)
			f.Why = append(f.Why, "前置黑名单「"+strings.Join(l, "/")+"」")
		}
	}
	return f
}

// allowMerge 把一份白名单并进来：第一份就是它本身，之后取交集。
func allowMerge(cur map[string]bool, list []string) map[string]bool {
	next := make(map[string]bool, len(list))
	for _, c := range list {
		next[c] = true
	}
	if cur == nil {
		return next
	}
	for c := range cur {
		if !next[c] {
			delete(cur, c)
		}
	}
	return cur
}

// denyMerge 把一份黑名单并进来。
func denyMerge(cur map[string]bool, list []string) map[string]bool {
	if cur == nil {
		cur = make(map[string]bool, len(list))
	}
	for _, c := range list {
		cur[c] = true
	}
	return cur
}

// effectiveValue 取「这一轮实际生效的值」：用户改过就用用户的，没改过用默认值。
//
// 为什么非得回落到默认值：NormalizeOverrides 只保存**和默认值不同**的项。
// 所以「打开前置白名单、名单就用默认的 HK」在配置里只剩一个 true，
// ALLOWED_COUNTRIES 这个键压根不存在。只看覆盖表会读成「名单是空的」，
// 于是筛了等于没筛——用户以为在只留香港，其实一个都没筛（2026-11-18 在容器里
// 真跑一轮才发现：日志里那句「按 前置白名单「SG」」在默认名单下会整句消失）。
func effectiveValue(ov map[string]any, key string) any {
	if v, ok := ov[key]; ok {
		return v
	}
	if spec, ok := engine.Lookup(key); ok {
		return spec.Def
	}
	return nil
}

// switchOn 读一个布尔开关。缺省取默认值（这几个开关的默认值全是 false）。
func switchOn(ov map[string]any, key string) bool {
	b, _ := effectiveValue(ov, key).(bool)
	return b
}

// countryList 读一份国家名单。
//
// 三种来源都要认：`[]string`（刚在界面上改过）、`[]any`（从 config.json 读回来，
// JSON 里数组元素没有具体类型）、`"HK,JP"`（手改配置文件写成一行）。
// 统一转成大写两位代码——界面上存的就是大写，但手改的不一定。
func countryList(v any) []string {
	var raw []string
	switch t := v.(type) {
	case []string:
		raw = t
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok {
				raw = append(raw, s)
			}
		}
	case string:
		raw = strings.Split(t, ",")
	}
	out := make([]string, 0, len(raw))
	for _, c := range raw {
		if c = strings.ToUpper(strings.TrimSpace(c)); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// countryFilterStat 是一次筛选的结果账，用来写日志和判断「是否全被筛掉」。
type countryFilterStat struct {
	Before         int            // 筛之前几条
	After          int            // 筛之后几条
	Dropped        map[string]int // 国家代码 → 被剔条数
	UnknownDropped int            // 位置查不到、因此被白名单剔掉的条数
	UnknownKept    int            // 位置查不到、但留下了的条数（只开黑名单时）
}

// filterResultByCountry 按真实机房位置筛一遍结果，返回新结果与统计。
//
// 三条规则，对「位置查不到」的处理各不相同，这是刻意的：
//   - 只开白名单：查不到位置的一律剔掉。「只留香港」的意思是没证据是香港的
//     不算数；留着才是最坏的错——用户以为在筛选，其实没筛。
//   - 只开黑名单：查不到位置的留着。不能因为查不到就假定它违规。
//   - 什么都不开：原样返回同一个指针，一条都不动（绝大多数用户的路径）。
func filterResultByCountry(res *engine.Result, colos map[string]string, f countryFilter) (*engine.Result, countryFilterStat) {
	st := countryFilterStat{Dropped: map[string]int{}}
	if res == nil {
		return res, st
	}
	st.Before = len(res.IPs)
	if !f.Active() {
		st.After = st.Before
		return res, st
	}

	byIP := make(map[string]engine.Node, len(res.Nodes))
	for _, n := range res.Nodes {
		byIP[n.IP] = n
	}

	out := &engine.Result{Logs: res.Logs}
	for _, ip := range res.IPs {
		code := countryCode(colos[ip])
		switch {
		case code == "":
			if len(f.Allow) > 0 {
				st.UnknownDropped++
				continue
			}
			st.UnknownKept++
		case len(f.Allow) > 0 && !f.Allow[code]:
			st.Dropped[code]++
			continue
		case f.Deny[code]:
			st.Dropped[code]++
			continue
		}
		out.IPs = append(out.IPs, ip)
		if n, ok := byIP[ip]; ok {
			out.Nodes = append(out.Nodes, n)
		}
	}
	st.After = len(out.IPs)
	return out, st
}

// detail 是「剔掉了哪些」的一句话，供日志和失败提示共用。
func (s countryFilterStat) detail() string {
	if len(s.Dropped) == 0 && s.UnknownDropped == 0 && s.UnknownKept == 0 {
		return "没有剔掉任何一条"
	}
	keys := make([]string, 0, len(s.Dropped))
	for k := range s.Dropped {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d 条", k, s.Dropped[k]))
	}
	if s.UnknownDropped > 0 {
		parts = append(parts, fmt.Sprintf("位置查不到 %d 条", s.UnknownDropped))
	}
	text := strings.Join(parts, "、")
	if s.UnknownKept > 0 {
		// 只开黑名单、又一条都没剔掉时，parts 是空的，这里不能直接接一个
		// 「；」——日志会变成「按 DNS 黑名单「US」；；另有 10 条…」那种双分号。
		tail := fmt.Sprintf("另有 %d 条位置查不到，黑名单不管它们，留着", s.UnknownKept)
		if text == "" {
			text = tail
		} else {
			text += "；" + tail
		}
	}
	return text
}

// note 是成功筛完那一行日志。who 是「IPv4」/「v6」，一次测速里两条日志要能分开。
func (s countryFilterStat) note(f countryFilter, who string) string {
	return fmt.Sprintf("%s 按真实机房位置筛：%d → %d 条（按 %s；%s）",
		who, s.Before, s.After, strings.Join(f.Why, " + "), s.detail())
}

// emptyMsg 是「筛完一条不剩」时给用户看的话。
//
// 单独写一句而不是复用引擎的错误：引擎只会说「0 节点」，用户完全不知道
// 是自己哪个设置造成的。这里把「按哪条规则、剔掉了什么、下一步能动哪个」
// 一次讲完，省一轮来回。
func (s countryFilterStat) emptyMsg(f countryFilter, who string) string {
	return fmt.Sprintf("%s 按你的国家设置筛完一条不剩（%d 条里 %s）。规则是 %s——"+
		"要么把要留的国家勾上，要么把这个开关关掉。这一轮没有写入任何 %s 结果。",
		who, s.Before, s.detail(), strings.Join(f.Why, " + "), who)
}

// refineResultByCountry 是「测完之后按真实机房位置筛」那一步，两族共用。
//
// 单独提出来只为一件事：**能测**。真正跑一轮要 1~2 分钟、还要能连上
// Cloudflare 问 trace，测试里做不到；而这一步的三条分支（不筛 / 筛完还有 /
// 筛完一条不剩）恰恰是最容易写错的地方。
//
// 没有配置任何国家规则时原样返回，一条都不动——这是绝大多数用户的路径，
// 不能因为加了筛选就让他们的结果有任何变化。
func (s *Server) refineResultByCountry(cfg config.Config, res *engine.Result, colos map[string]string, who string) (*engine.Result, error) {
	cf := countryFilterFrom(cfg)
	if !cf.Active() {
		return res, nil
	}
	out, st := filterResultByCountry(res, colos, cf)
	s.appendLog(st.note(cf, who))
	if len(out.IPs) == 0 {
		return out, fmt.Errorf("%s", st.emptyMsg(cf, who))
	}
	return out, nil
}
