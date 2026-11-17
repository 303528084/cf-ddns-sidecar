package engine

// 「高级设置」参数表与覆盖值的测试。
//
// 这一层的错误方向同样不对称：一个参数写错了，用户在界面上改了、保存成功、
// 日志里也写了「已生效」，但引擎其实没收到——这种「看起来生效了」的假象
// 比直接报错难查得多。所以下面重点守三件事：
//  1. 表里的键必须真的被写进引擎配置（不是只存进 config.json）；
//  2. 危险参数（会和我们自己的 DDNS 抢写）**不能**出现在表里；
//  3. 类型转换不能把用户的值悄悄改成别的（"443,8443" 不能变成 443）。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readConfig 写出引擎配置再读回来，用于断言「最终交给引擎的是什么」。
func readConfig(t *testing.T, opt Options) map[string]any {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := writeCfnbConfig(p, opt); err != nil {
		t.Fatalf("写配置失败: %v", err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("读配置失败: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("配置不是合法 JSON: %v", err)
	}
	return m
}

func TestSchemaWellFormed(t *testing.T) {
	groups := map[string]bool{}
	for _, g := range Groups {
		groups[g.Key] = true
	}
	seen := map[string]bool{}
	for _, s := range Schema {
		if seen[s.Key] {
			t.Errorf("参数 %s 重复出现", s.Key)
		}
		seen[s.Key] = true
		if s.Label == "" {
			t.Errorf("%s 没有中文标签，界面上会显示成参数名", s.Key)
		}
		if s.Help == "" {
			t.Errorf("%s 没有说明文字，问号点开是空的", s.Key)
		}
		// 说明文字是写给不懂编程的人看的，出现大写参数名说明写错了地方。
		if strings.Contains(s.Help, s.Key) {
			t.Errorf("%s 的说明里出现了参数名，应该用中文讲清是什么", s.Key)
		}
		if !groups[s.Group] {
			t.Errorf("%s 的分组 %q 不在 Groups 里，界面上会整组消失", s.Key, s.Group)
		}
		if s.Def == nil {
			t.Errorf("%s 没有默认值，「恢复默认」会把它变成空", s.Key)
		}
		if s.Kind == KindLevel && len(s.Options) == 0 {
			t.Errorf("%s 是枚举但没有可选值", s.Key)
		}
	}
}

// TestDangerousKeysNotExposed 守住「不给开关」的那几个。
//
// CF_* 是最要紧的一条：引擎自带一套「更新 Cloudflare 解析记录」的逻辑，
// 而本程序自己也在写同一条记录。两边同时写会互相覆盖，解析结果来回跳，
// 表现为「域名一会儿能开一会儿不能」。所以它必须永远不出现在表里。
func TestDangerousKeysNotExposed(t *testing.T) {
	for _, k := range []string{
		"CF_ENABLED", "CF_API_TOKEN", "CF_ZONE_ID", "CF_DNS_RECORD_NAME",
		"ENABLE_WXPUSHER", "WXPUSHER_APP_TOKEN", "GITHUB_SYNC_ENABLED",
		"AD_HEADER_ENABLED", "AD_FOOTER_ENABLED", "AD_PERLINE_ENABLED",
		"OUTPUT_FILE", "LOG_FILE",
	} {
		if _, ok := Lookup(k); ok {
			t.Errorf("%s 不该出现在可覆盖参数表里——它会让现有功能出错", k)
		}
	}
}

func TestNormalizeOverrides(t *testing.T) {
	got := NormalizeOverrides(map[string]any{
		// 布尔：原样
		"HTTP_LATENCY_ENABLED": true,
		// 端口：界面上是一行文字，必须拆成 []int，否则引擎会拿到一个字符串
		"PRE_FILTER_PORTS": "443, 8443",
		// 国家：小写、带空格，要统一成大写两字母
		"OUTPUT_ALLOWED_COUNTRIES": "hk, jp",
		// 数值：JSON 里都是 float64，必须转成 int
		"AVAILABILITY_TEST_ROUNDS": float64(5),
		// 越界：钳到上限而不是报错
		"BANDWIDTH_WORKERS": float64(999),
		// 未知参数：丢掉
		"NOT_A_REAL_KEY": "x",
		// 和默认值一样：不必存
		"TEST_AVAILABILITY": true,
		// 枚举里没有的值：丢掉
		"DNS_IP_RISK_MAX_LEVEL": "随便写的",
	})

	if got["HTTP_LATENCY_ENABLED"] != true {
		t.Errorf("布尔没保留: %v", got["HTTP_LATENCY_ENABLED"])
	}
	ports, ok := got["PRE_FILTER_PORTS"].([]int)
	if !ok || len(ports) != 2 || ports[0] != 443 || ports[1] != 8443 {
		t.Errorf("端口应拆成 [443 8443]，实际 %#v", got["PRE_FILTER_PORTS"])
	}
	cs, ok := got["OUTPUT_ALLOWED_COUNTRIES"].([]string)
	if !ok || len(cs) != 2 || cs[0] != "HK" || cs[1] != "JP" {
		t.Errorf("国家应统一成 [HK JP]，实际 %#v", got["OUTPUT_ALLOWED_COUNTRIES"])
	}
	if v, ok := got["AVAILABILITY_TEST_ROUNDS"].(int); !ok || v != 5 {
		t.Errorf("轮数应是 int 5，实际 %#v", got["AVAILABILITY_TEST_ROUNDS"])
	}
	if v, ok := got["BANDWIDTH_WORKERS"].(int); !ok || v != 20 {
		t.Errorf("并发应被钳到上限 20，实际 %#v", got["BANDWIDTH_WORKERS"])
	}
	for _, k := range []string{"NOT_A_REAL_KEY", "TEST_AVAILABILITY", "DNS_IP_RISK_MAX_LEVEL"} {
		if _, ok := got[k]; ok {
			t.Errorf("%s 不该被保留，实际 %v", k, got[k])
		}
	}
}

// TestNormalizeOverridesEmptyIsNil 全默认时必须是 nil。
//
// 不是 nil 的话 config.json 里会多一个空对象，导出备份、界面「已改」标记、
// 日志里那行「高级设置已生效」全都会跟着误报。
func TestNormalizeOverridesEmptyIsNil(t *testing.T) {
	if got := NormalizeOverrides(nil); got != nil {
		t.Errorf("nil 输入应返回 nil，实际 %v", got)
	}
	if got := NormalizeOverrides(map[string]any{"TEST_AVAILABILITY": true}); got != nil {
		t.Errorf("全是默认值时应返回 nil，实际 %v", got)
	}
	if got := NormalizeOverrides(map[string]any{"BOGUS": 1}); got != nil {
		t.Errorf("全是未知键时应返回 nil，实际 %v", got)
	}
}

func TestApplyOverrides(t *testing.T) {
	base := map[string]any{"HTTP_LATENCY_ENABLED": false, "PRE_FILTER_PORTS": []int{443}}
	ApplyOverrides(base, map[string]any{
		"HTTP_LATENCY_ENABLED": true,
		"PRE_FILTER_PORTS":     "443,2053",
		"NOT_A_REAL_KEY":       "x",
	})
	if base["HTTP_LATENCY_ENABLED"] != true {
		t.Errorf("覆盖没生效: %v", base["HTTP_LATENCY_ENABLED"])
	}
	if ports, _ := base["PRE_FILTER_PORTS"].([]int); len(ports) != 2 {
		t.Errorf("端口覆盖没生效: %#v", base["PRE_FILTER_PORTS"])
	}
	if _, ok := base["NOT_A_REAL_KEY"]; ok {
		t.Error("未知键不该被写进引擎配置")
	}
}

// TestWriteCfnbConfigAppliesOverrides 是这一层最重要的一条：
// 证明「界面上改的值」真的走完 config → Options → 引擎配置文件这条链路。
func TestWriteCfnbConfigAppliesOverrides(t *testing.T) {
	m := readConfig(t, Options{
		TopN:                5,
		BandwidthCandidates: 100,
		UseBuiltinSources:   true,
		Overrides: map[string]any{
			"HTTP_LATENCY_ENABLED":       true,
			"AVAILABILITY_TEST_ROUNDS":   5,
			"DNS_IP_RISK_FILTER_ENABLED": true,
			"DNS_IP_RISK_MAX_LEVEL":      "轻微风险",
			"PRE_FILTER_PORTS":           "443,2053",
			"BANDWIDTH_WORKERS":          5,
		},
	})

	if m["HTTP_LATENCY_ENABLED"] != true {
		t.Errorf("延迟/抖动排序没写进去: %v", m["HTTP_LATENCY_ENABLED"])
	}
	if v, ok := m["AVAILABILITY_TEST_ROUNDS"].(float64); !ok || v != 5 {
		t.Errorf("反代验证轮数应为 5，实际 %#v", m["AVAILABILITY_TEST_ROUNDS"])
	}
	if m["DNS_IP_RISK_FILTER_ENABLED"] != true {
		t.Errorf("IP 风险过滤没写进去: %v", m["DNS_IP_RISK_FILTER_ENABLED"])
	}
	if m["DNS_IP_RISK_MAX_LEVEL"] != "轻微风险" {
		t.Errorf("风险等级没写进去: %v", m["DNS_IP_RISK_MAX_LEVEL"])
	}
	ports, _ := m["PRE_FILTER_PORTS"].([]any)
	if len(ports) != 2 {
		t.Errorf("端口列表应为 2 项，实际 %#v", m["PRE_FILTER_PORTS"])
	}
	if v, ok := m["BANDWIDTH_WORKERS"].(float64); !ok || v != 5 {
		t.Errorf("带宽并发应为 5，实际 %#v", m["BANDWIDTH_WORKERS"])
	}
}

// TestOverridesDoNotBreakOutput 守「高级设置别把结果解析搞坏」。
//
// IP_TXT_SHOW_* 一旦被关掉，界面上的速度和延迟会全变成「—」，
// 而用户会以为是测速坏了。这几个可以关，但关了以后解析不能崩。
func TestOverridesDoNotBreakOutput(t *testing.T) {
	m := readConfig(t, Options{
		UseBuiltinSources: true,
		Overrides: map[string]any{
			"IP_TXT_SHOW_BANDWIDTH": false,
			"IP_TXT_SHOW_LATENCY":   false,
		},
	})
	if m["IP_TXT_SHOW_BANDWIDTH"] != false || m["IP_TXT_SHOW_LATENCY"] != false {
		t.Errorf("这两个开关没生效: %v / %v", m["IP_TXT_SHOW_BANDWIDTH"], m["IP_TXT_SHOW_LATENCY"])
	}
	// 关掉之后 ip.txt 只剩裸 IP，解析要能认。
	p := filepath.Join(t.TempDir(), "ip.txt")
	if err := os.WriteFile(p, []byte("104.16.0.87:443#US\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ips, nodes, err := parseOutput(p)
	if err != nil {
		t.Fatalf("裸 IP 行不该解析失败: %v", err)
	}
	// 端口和 #国家 会被剥掉：这两样只对测速有意义，写进 AdGuard / DNS 的
	// 必须是裸 IP，否则解析记录直接非法。
	if len(ips) != 1 || ips[0] != "104.16.0.87" || len(nodes) != 1 {
		t.Errorf("解析结果不对: %v / %+v", ips, nodes)
	}
}

func TestDescribeOverrides(t *testing.T) {
	if got := DescribeOverrides(nil); got != "" {
		t.Errorf("没有改动时应返回空串，实际 %q", got)
	}
	got := DescribeOverrides(map[string]any{
		"HTTP_LATENCY_ENABLED": true,
		"BANDWIDTH_WORKERS":    5,
	})
	// 日志里要出现中文标签，而不是参数名——用户看不懂参数名。
	if !strings.Contains(got, "延迟/抖动排序") || !strings.Contains(got, "带宽测速并发数") {
		t.Errorf("应使用中文标签，实际 %q", got)
	}
	if strings.Contains(got, "HTTP_LATENCY_ENABLED") {
		t.Errorf("不该把参数名打给用户看: %q", got)
	}
}

// TestEveryBooleanSwitchAccountedFor 守的是「日志里有、界面没有」这个具体投诉。
//
// cfnb 一共 24 个布尔开关。18 个在 Schema 里给了开关，剩下 6 个必须能在
// ExcludedReasons() 里找到名字和理由——否则用户又会在日志里看到一个
// 「启用/禁用」，翻遍后台却找不到，只能再来问一遍。
//
// 这里把 6 个键写死：它们是「确定不给」的，不该因为某次重构被悄悄忘掉。
func TestEveryBooleanSwitchAccountedFor(t *testing.T) {
	exposed := map[string]bool{}
	for _, s := range Schema {
		if s.Kind == KindBool {
			exposed[s.Key] = true
		}
	}

	deliberatelyOff := []string{
		"CF_ENABLED",         // 会和本程序自己的 DDNS 抢写同一条记录
		"CF_PROXIED",         // 同上
		"ENABLE_WXPUSHER",    // 需要另外申请凭证，本程序没接
		"AD_HEADER_ENABLED",  // 往结果里插广告行
		"AD_FOOTER_ENABLED",  // 同上
		"AD_PERLINE_ENABLED", // 同上
	}

	var all strings.Builder
	for _, e := range ExcludedReasons() {
		all.WriteString(e.Key)
		all.WriteString("\n")
	}
	text := all.String()

	for _, k := range deliberatelyOff {
		if exposed[k] {
			t.Errorf("%s 不该出现在 Schema 里（它会让本程序的功能互相打架）", k)
		}
		if !strings.Contains(text, k) {
			t.Errorf("%s 没有出现在「不给开关」的说明里——用户会以为界面漏了", k)
		}
	}

	// 反过来：每个不给的键都得有非空理由，界面上不允许出现只有名字没有原因的行。
	for _, e := range ExcludedReasons() {
		if strings.TrimSpace(e.Why) == "" {
			t.Errorf("%q 没有写原因", e.Key)
		}
	}
}
