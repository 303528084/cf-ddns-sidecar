package web

// v6 与 v4 的「设置口径」在哪里不一样，以及为什么。
//
// v4 主测速把用户在「高级设置」里改过的参数整包交给引擎，v6 探测起先只传了一条
// （关掉 ipv6_only 过滤），于是界面上的改动对 v6 全不生效。照着 v4 传也不全对，
// 所以这个文件只留「哪些不传、为什么」，筛选本身在 country_filter.go（两族共用）。
//
// 差别只有一处：按国家分组排序的两项（USE_GLOBAL_MODE / PER_COUNTRY_TOP_N）。
// v6 候选的国家标签全是同一个占位值 #US，非全局模式会按「每个国家保留几个」分组，
// 结果只剩 1 条。v4 那边这两项保持原样，不动主链路上与本议题无关的行为。

import "github.com/303528084/cf-ddns-sidecar/config"

// v6NotPassed 是「高级设置里这些项不交给 v6 引擎」的清单，值写的是理由。两类：
// 按国家筛的四组开关与名单（countryFilterKeys 那 8 个）、按国家分组排序的两项。
// 用 map 而不是切片：加新键时能顺手写理由，测试也能直接断言「这些键一个都没混进
// v6 的覆盖表」，漏掉一个的表现是 v6 悄悄归零，很难查。
var v6NotPassed = map[string]string{
	"FILTER_COUNTRIES_ENABLED":         "前置白名单开关，改由测完按真实机房位置筛",
	"ALLOWED_COUNTRIES":                "前置白名单的国家，同上",
	"FILTER_BLOCKED_COUNTRIES_ENABLED": "DNS 黑名单开关，改由测完按真实机房位置筛",
	"BLOCKED_COUNTRIES":                "DNS 黑名单的国家，同上",
	"PRE_FILTER_BLOCKED_ENABLED":       "前置黑名单开关，改由测完按真实机房位置筛",
	"PRE_FILTER_BLOCKED_COUNTRIES":     "前置黑名单的国家，同上",
	"OUTPUT_FILTER_COUNTRIES_ENABLED":  "输出白名单开关，改由测完按真实机房位置筛",
	"OUTPUT_ALLOWED_COUNTRIES":         "输出白名单的国家，同上",
	"USE_GLOBAL_MODE":                  "v6 候选的国家标签都是同一个占位值，按国家分组没有意义",
	"PER_COUNTRY_TOP_N":                "同上",
}

// v6Overrides 拼出 v6 探测这一轮要交给引擎的覆盖表。
// 先铺用户改过的值，最后强制压掉「过滤 ipv6_only 出口」：v6 候选全是 ipv6_only
// 落地的地址，这个开关一开它们会在写结果前被全部剔除，探测永远看不到它们。
func v6Overrides(cfg config.Config) map[string]any {
	src := cfg.Speed.EngineOverrides
	out := make(map[string]any, len(src)+1)
	for k, v := range src {
		if _, skip := v6NotPassed[k]; skip {
			continue
		}
		out[k] = v
	}
	out["FILTER_IPV6_AVAILABILITY"] = false
	return out
}
