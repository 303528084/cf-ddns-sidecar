package web

// 「v6 吃不吃用户设置」这一层的测试——只管 v6 与 v4 的口径差异。
//
// 筛选本身的用例在 country_filter_test.go（两族共用）；这个文件守的是另一件事：
// 哪些键**不该**交给 v6 引擎。这类错误方向特别不对称——设置没传下去不会报错，
// v6 照样跑完、照样出结果，只是结果里混着用户明确不要的机房，用户只能靠
// 「怎么还是日本节点」自己发现。

import (
	"testing"

	"github.com/303528084/cf-ddns-sidecar/config"
)

// TestV6OverridesForwardsNonCountrySettings 守「用户改的那些设置真的到了 v6」。
func TestV6OverridesForwardsNonCountrySettings(t *testing.T) {
	cfg := config.Config{}
	cfg.Speed.EngineOverrides = map[string]any{
		"PRE_FILTER_PORTS":           []string{"443", "8443"},
		"BANDWIDTH_WORKERS":          5,
		"TCP_PROBES":                 3,
		"HTTP_LATENCY_ENABLED":       true,
		"MIN_SUCCESS_RATE":           0.5,
		"AVAILABILITY_TEST_ROUNDS":   5,
		"FETCH_TIMEOUT":              15,
		"DNS_IP_RISK_FILTER_ENABLED": true,
	}

	got := v6Overrides(cfg)
	for _, k := range []string{
		"PRE_FILTER_PORTS", "BANDWIDTH_WORKERS", "TCP_PROBES", "HTTP_LATENCY_ENABLED",
		"MIN_SUCCESS_RATE", "AVAILABILITY_TEST_ROUNDS", "FETCH_TIMEOUT",
		"DNS_IP_RISK_FILTER_ENABLED",
	} {
		if v, ok := got[k]; !ok {
			t.Errorf("%s 没传给 v6（用户改了却不生效）", k)
			continue
		} else if k == "BANDWIDTH_WORKERS" && v != 5 {
			t.Errorf("BANDWIDTH_WORKERS 传成了 %v，应为 5", v)
		}
	}
}

// TestV6OverridesSkipsCountrySettings 守「按国家筛的那几项不许偷偷传给 v6」。
//
// 传下去的后果不是「筛错了」而是「v6 一条不剩」：v6 候选全带占位 `#US`，
// 白名单默认只勾 HK，引擎会在写结果前把它们全剔掉。
func TestV6OverridesSkipsCountrySettings(t *testing.T) {
	cfg := config.Config{}
	cfg.Speed.EngineOverrides = map[string]any{
		"FILTER_COUNTRIES_ENABLED":         true,
		"ALLOWED_COUNTRIES":                []string{"HK"},
		"FILTER_BLOCKED_COUNTRIES_ENABLED": true,
		"BLOCKED_COUNTRIES":                []string{"US"},
		"PRE_FILTER_BLOCKED_ENABLED":       true,
		"PRE_FILTER_BLOCKED_COUNTRIES":     []string{"CN"},
		"OUTPUT_FILTER_COUNTRIES_ENABLED":  true,
		"OUTPUT_ALLOWED_COUNTRIES":         []string{"HK"},
		"USE_GLOBAL_MODE":                  false,
		"PER_COUNTRY_TOP_N":                3,
	}
	got := v6Overrides(cfg)
	for k := range v6NotPassed {
		if _, ok := got[k]; ok {
			t.Errorf("%s 不该传给 v6——候选的国家标签是占位值，按它筛会把候选杀光", k)
		}
	}
	// 只剩那一条强制的，别的都不该凭空出现
	if len(got) != 1 {
		t.Errorf("覆盖表里应只剩强制关 ipv6_only 的一条，实际 %v", got)
	}
}

// TestV6OverridesForcesIPv6FilterOff 守用户定稿的决定②。
//
// 用户就算在界面上打开了「DNS 阶段过滤 IPv6」，v6 探测这一轮也必须关着：
// v6 候选全是 ipv6_only 落地的地址，开着等于把候选全部剔除。
func TestV6OverridesForcesIPv6FilterOff(t *testing.T) {
	cfg := config.Config{}
	cfg.Speed.EngineOverrides = map[string]any{
		"FILTER_IPV6_AVAILABILITY": true,
		"TCP_PROBES":               2,
	}
	got := v6Overrides(cfg)
	if got["FILTER_IPV6_AVAILABILITY"] != false {
		t.Errorf("v6 探测必须强制关掉 ipv6_only 过滤，实际 %v", got["FILTER_IPV6_AVAILABILITY"])
	}
	if got["TCP_PROBES"] != 2 {
		t.Error("强制项不该把别的设置挤掉")
	}
	// 空覆盖表也要至少带这一条
	if got := v6Overrides(config.Config{}); got["FILTER_IPV6_AVAILABILITY"] != false {
		t.Error("没有任何设置时也要带上强制项")
	}
}
