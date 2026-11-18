package web

// 「按真实机房位置筛节点」这一层的测试——IPv4 / IPv6 共用。
//
// 这一层的错误方向特别不对称：筛错了不会报错，结果照样出来，只是混着用户
// 明确不要的机房，或者干脆一条不剩。用户只能靠「怎么还是日本节点」自己发现。
// 所以重点守四件事：
//  1. 那 8 个按国家筛的键**不能**漏进引擎的覆盖表（漏进去 = 按假标签筛）；
//  2. 四组开关与名单怎么合成一个筛法（交集 / 并集 / 关着不算）；
//  3. 位置查不到的三种处理（白名单剔 / 黑名单留 / 都不开不动）；
//  4. 筛完一条不剩必须报错，不能返回空列表。
//
// 2026-11-18 之前这套只在 v6 上，v4 是引擎内部按占位 `#US` 筛的；改成共用之后
// 两族的判断只有 who 这个字面量不同，所以用例也只写一套。

import (
	"strings"
	"testing"

	"github.com/303528084/cf-ddns-sidecar/config"
	"github.com/303528084/cf-ddns-sidecar/engine"
)

// TestCountryFilterKeysCoverV6NotPassed 守两张清单别走散。
//
// v4 用 countryFilterKeys 剔键、v6 用 v6NotPassed 剔键，两处各自维护。少写
// 一边的表现是「v4 筛得对、v6 全灭」或者反过来，而且都不报错——所以直接断言
// 「按国家筛的那 8 个键在 v6 那边也必须被剔掉」。
func TestCountryFilterKeysCoverV6NotPassed(t *testing.T) {
	if len(countryFilterKeys) != 8 {
		t.Errorf("按国家筛的键应为 8 个，实际 %d 个：%v", len(countryFilterKeys), countryFilterKeys)
	}
	for _, k := range countryFilterKeys {
		if _, ok := v6NotPassed[k]; !ok {
			t.Errorf("%s 在 countryFilterKeys 里但不在 v6NotPassed 里——v6 会把它传给引擎", k)
		}
	}
}

// TestV4OverridesDropsCountryFilterKeys 守 v4 主测速不再让引擎按假标签筛国家。
//
// v4 以前是整包 cfg.Speed.EngineOverrides 交给引擎，于是「只留香港」筛的是
// 候选自带的占位 `#US`。现在那 8 个键必须被摘掉，其余的一个不许少。
func TestV4OverridesDropsCountryFilterKeys(t *testing.T) {
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
		// 下面这些跟国家无关，必须原样留着
		"PRE_FILTER_PORTS":  []string{"443"},
		"TCP_PROBES":        3,
		"USE_GLOBAL_MODE":   false,
		"PER_COUNTRY_TOP_N": 5,
	}

	got := v4Overrides(cfg)
	for _, k := range countryFilterKeys {
		if _, ok := got[k]; ok {
			t.Errorf("%s 不该交给 v4 引擎——候选带的是占位标签，按它筛等于没筛", k)
		}
	}
	for _, k := range []string{"PRE_FILTER_PORTS", "TCP_PROBES", "USE_GLOBAL_MODE", "PER_COUNTRY_TOP_N"} {
		if _, ok := got[k]; !ok {
			t.Errorf("%s 跟国家无关，不该被顺手删掉", k)
		}
	}
	if len(got) != 4 {
		t.Errorf("只该剩 4 项，实际 %d 项：%v", len(got), got)
	}

	// 空配置不能凭空造出键来
	if got := v4Overrides(config.Config{}); len(got) != 0 {
		t.Errorf("没有任何覆盖时不该有任何键，实际 %v", got)
	}
}

// TestCountryFilterFrom 守「四组开关和名单怎么合成一个筛法」。
func TestCountryFilterFrom(t *testing.T) {
	mk := func(ov map[string]any) countryFilter {
		var c config.Config
		c.Speed.EngineOverrides = ov
		return countryFilterFrom(c)
	}

	if f := mk(nil); f.Active() {
		t.Error("什么都没开时应完全不筛")
	}

	f := mk(map[string]any{
		"FILTER_COUNTRIES_ENABLED": true,
		"ALLOWED_COUNTRIES":        []string{"HK", "JP"},
	})
	if !f.Active() || !f.Allow["HK"] || !f.Allow["JP"] || len(f.Allow) != 2 {
		t.Errorf("前置白名单没被读出来: %+v", f)
	}

	// 两份白名单取交集：输出白名单只留 HK，结果就只剩 HK
	f = mk(map[string]any{
		"FILTER_COUNTRIES_ENABLED":        true,
		"ALLOWED_COUNTRIES":               []string{"HK", "JP"},
		"OUTPUT_FILTER_COUNTRIES_ENABLED": true,
		"OUTPUT_ALLOWED_COUNTRIES":        []string{"HK"},
	})
	if len(f.Allow) != 1 || !f.Allow["HK"] {
		t.Errorf("两份白名单应取交集（只剩 HK），实际 %v", f.Allow)
	}

	// 两份黑名单取并集：前置 CN + DNS 黑名单 US
	f = mk(map[string]any{
		"PRE_FILTER_BLOCKED_ENABLED":       true,
		"PRE_FILTER_BLOCKED_COUNTRIES":     []string{"CN"},
		"FILTER_BLOCKED_COUNTRIES_ENABLED": true,
		"BLOCKED_COUNTRIES":                []string{"US"},
	})
	if !f.Deny["CN"] || !f.Deny["US"] || len(f.Deny) != 2 {
		t.Errorf("两份黑名单应取并集（CN + US），实际 %v", f.Deny)
	}

	// 开关关着时，名单里留着什么都不算数
	f = mk(map[string]any{
		"FILTER_COUNTRIES_ENABLED": false,
		"ALLOWED_COUNTRIES":        []string{"HK"},
	})
	if f.Active() {
		t.Error("开关没开时名单不该生效")
	}

	// 开关开着手改成了空名单 → 也不筛（否则等于「剔掉所有国家」）
	f = mk(map[string]any{
		"FILTER_COUNTRIES_ENABLED": true,
		"ALLOWED_COUNTRIES":        []string{},
	})
	if f.Active() {
		t.Error("空名单不该当成「什么都不留」")
	}

	// 「打开前置白名单、名单全用默认」——NormalizeOverrides 会把等于默认值的
	// 项丢掉，所以配置里只剩一个 true，ALLOWED_COUNTRIES 这个键不存在。
	// 这里必须回落到默认的 HK，否则就是「开了等于没开」的静默失败：
	// 用户在界面上打开了只留香港，程序一个都没筛，日志里还什么都不写。
	// 2026-11-18 在容器里真跑一轮才发现，覆盖表里确实只有 {"FILTER_COUNTRIES_ENABLED": true}。
	f = mk(map[string]any{"FILTER_COUNTRIES_ENABLED": true})
	if len(f.Allow) != 1 || !f.Allow["HK"] {
		t.Errorf("名单没改过时应回落到默认的 HK，实际 %v", f.Allow)
	}

	// 同理，打开 DNS 黑名单、名单用默认时，回落到的是默认那份 28 国清单
	// （含 HK、CN、RU 等）。这与引擎原本的行为一致：开关一开，它用的就是
	// 这份自带名单，不是空名单。
	f = mk(map[string]any{"FILTER_BLOCKED_COUNTRIES_ENABLED": true})
	if !f.Deny["HK"] || len(f.Deny) < 20 {
		t.Errorf("DNS 黑名单应回落到默认那份 28 国清单，实际 %v", f.Deny)
	}
}

// TestCountryListVariants 守三种存法都能读出来（界面改的 / 从文件读回的 / 手改的）。
func TestCountryListVariants(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{[]string{"HK", "JP"}, "HK/JP"},
		{[]any{"hk", " jp "}, "HK/JP"}, // 从 config.json 读回来是 []any
		{"hk,jp", "HK/JP"},             // 手改配置文件写一行
		{nil, ""},
		{[]any{1, "JP", nil}, "JP"}, // 混进脏值只丢脏的，不整份丢弃
	}
	for _, c := range cases {
		if got := strings.Join(countryList(c.in), "/"); got != c.want {
			t.Errorf("countryList(%#v) = %q，期望 %q", c.in, got, c.want)
		}
	}
}

// TestFilterResultByCountry 守三种筛法，尤其是「位置查不到怎么办」。
func TestFilterResultByCountry(t *testing.T) {
	res := &engine.Result{
		IPs: []string{"hk1", "jp1", "us1", "unknown1"},
		Nodes: []engine.Node{
			{IP: "hk1", Speed: 10}, {IP: "jp1", Speed: 8},
			{IP: "us1", Speed: 6}, {IP: "unknown1", Speed: 4},
		},
	}
	colos := map[string]string{"hk1": "HKG", "jp1": "NRT", "us1": "LAX"} // unknown1 探不到

	t.Run("什么都不开时一条都不动", func(t *testing.T) {
		got, st := filterResultByCountry(res, colos, countryFilter{})
		if len(got.IPs) != 4 || st.Before != 4 || st.After != 4 {
			t.Errorf("不该动任何一条: %v", got.IPs)
		}
		if got != res {
			t.Error("没有规则时应原样返回同一个结果，不要白拷一份")
		}
	})

	t.Run("白名单只留香港", func(t *testing.T) {
		got, st := filterResultByCountry(res, colos, countryFilter{Allow: map[string]bool{"HK": true}})
		if len(got.IPs) != 1 || got.IPs[0] != "hk1" {
			t.Errorf("应只剩香港那条，实际 %v", got.IPs)
		}
		if len(got.Nodes) != 1 || got.Nodes[0].IP != "hk1" || got.Nodes[0].Speed != 10 {
			t.Errorf("节点数据要跟着一起筛，且速度不能丢: %+v", got.Nodes)
		}
		if st.Dropped["JP"] != 1 || st.Dropped["US"] != 1 {
			t.Errorf("剔掉的国家要记账: %v", st.Dropped)
		}
		// 白名单下「查不到位置」必须算不通过，否则「只留香港」就名不副实
		if st.UnknownDropped != 1 {
			t.Errorf("位置查不到的应被白名单剔掉 1 条，实际 %d", st.UnknownDropped)
		}
	})

	t.Run("黑名单剔掉美国时位置查不到的留着", func(t *testing.T) {
		got, st := filterResultByCountry(res, colos, countryFilter{Deny: map[string]bool{"US": true}})
		if len(got.IPs) != 3 {
			t.Errorf("只该少掉美国那条，实际 %v", got.IPs)
		}
		for _, ip := range got.IPs {
			if ip == "us1" {
				t.Error("美国那条应该被剔掉")
			}
		}
		if st.UnknownKept != 1 || st.UnknownDropped != 0 {
			t.Errorf("查不到位置的应留着（不能假定违规），实际 kept=%d dropped=%d",
				st.UnknownKept, st.UnknownDropped)
		}
	})

	t.Run("筛完一条不剩也要如实返回", func(t *testing.T) {
		got, st := filterResultByCountry(res, colos, countryFilter{Allow: map[string]bool{"SG": true}})
		if len(got.IPs) != 0 || st.After != 0 {
			t.Errorf("新加坡一条都没有，结果应为空，实际 %v", got.IPs)
		}
	})
}

// TestCountryFilterMessages 守「筛掉之后用户看得懂发生了什么」。
//
// 这几句话存在的唯一目的就是解释「为什么没结果 / 为什么少了」。少一句
// 用户就只能猜，而猜的结果通常是「程序坏了」。
func TestCountryFilterMessages(t *testing.T) {
	f := countryFilter{
		Allow: map[string]bool{"HK": true},
		Why:   []string{"前置白名单「HK」"},
	}
	st := countryFilterStat{Before: 9, After: 2, Dropped: map[string]int{"JP": 4, "US": 2}, UnknownDropped: 1}

	note := st.note(f, "IPv4")
	for _, want := range []string{"IPv4 按真实机房位置筛", "9 → 2", "前置白名单", "JP 4 条", "US 2 条", "位置查不到 1 条"} {
		if !strings.Contains(note, want) {
			t.Errorf("日志里少了 %q：%s", want, note)
		}
	}
	// 日志是给人看的，不能出现参数名
	if strings.Contains(note, "ALLOWED_COUNTRIES") {
		t.Errorf("日志里不该出现参数名: %s", note)
	}
	// 两条路径的日志要能分开：一次测速里 v4 和 v6 都可能筛
	if v6 := st.note(f, "v6"); !strings.HasPrefix(v6, "v6 按真实机房位置筛") {
		t.Errorf("v6 那条日志的开头不对: %s", v6)
	}

	empty := st.emptyMsg(f, "v6")
	for _, want := range []string{"一条不剩", "要么把要留的国家勾上", "没有写入任何 v6 结果"} {
		if !strings.Contains(empty, want) {
			t.Errorf("失败提示里少了 %q：%s", want, empty)
		}
	}
	if v4 := st.emptyMsg(f, "IPv4"); !strings.Contains(v4, "没有写入任何 IPv4 结果") {
		t.Errorf("IPv4 那版提示里没写清是哪一族: %s", v4)
	}

	// 只开黑名单、而且一条都没剔掉时（真机上最常见：只写了个 DNS 黑名单，
	// 结果全是查不到位置的节点），不能出现「；；」这种双分号。
	// 这是 2026-11-18 在容器里跑真轮测速时抓到的真实输出。
	onlyKept := countryFilterStat{Before: 27, After: 27, Dropped: map[string]int{}, UnknownKept: 10}
	if got := onlyKept.note(countryFilter{Deny: map[string]bool{"US": true}, Why: []string{"DNS 黑名单「US」"}}, "IPv4"); strings.Contains(got, "；；") || strings.Contains(got, "；）") {
		t.Errorf("日志里出现了空的分号: %s", got)
	} else if !strings.Contains(got, "27 → 27 条") || !strings.Contains(got, "另有 10 条位置查不到") {
		t.Errorf("该留的账没记全: %s", got)
	}
}

// TestRefineResultByCountry 守「这一步真的接上了」。
//
// 上面几组测的都是零件（筛法、账、文案），但零件对不代表装配对：这一步要是
// 忘了打日志，用户就只知道结果少了、不知道为什么；要是把「筛完为空」当成
// 正常结果返回，会写进去一个空列表——比报错更难查。
func TestRefineResultByCountry(t *testing.T) {
	res := &engine.Result{
		IPs:   []string{"hk1", "jp1"},
		Nodes: []engine.Node{{IP: "hk1", Speed: 10}, {IP: "jp1", Speed: 8}},
	}
	colos := map[string]string{"hk1": "HKG", "jp1": "NRT"}

	mk := func(ov map[string]any) config.Config {
		var c config.Config
		c.Speed.EngineOverrides = ov
		return c
	}

	t.Run("没开国家规则时一条都不动、也不刷日志", func(t *testing.T) {
		s := &Server{}
		got, err := s.refineResultByCountry(mk(nil), res, colos, "IPv4")
		if err != nil {
			t.Fatalf("没开规则不该报错: %v", err)
		}
		if got != res {
			t.Error("没开规则时应原样返回，连拷贝都不该做")
		}
		if len(s.logs) != 0 {
			t.Errorf("没开规则时不该往日志里写东西，实际 %v", s.logs)
		}
	})

	t.Run("筛完还有结果：不报错，日志说清筛掉了什么", func(t *testing.T) {
		s := &Server{}
		got, err := s.refineResultByCountry(mk(map[string]any{
			"FILTER_COUNTRIES_ENABLED": true,
			"ALLOWED_COUNTRIES":        []string{"HK"},
		}), res, colos, "IPv4")
		if err != nil {
			t.Fatalf("还有结果时不该报错: %v", err)
		}
		if len(got.IPs) != 1 || got.IPs[0] != "hk1" {
			t.Errorf("应只剩香港那条，实际 %v", got.IPs)
		}
		line := strings.Join(s.logs, "\n")
		for _, want := range []string{"IPv4 按真实机房位置筛", "2 → 1", "JP 1 条"} {
			if !strings.Contains(line, want) {
				t.Errorf("日志里少了 %q：%s", want, line)
			}
		}
	})

	t.Run("筛完一条不剩：必须报错，并把能改的开关点名", func(t *testing.T) {
		s := &Server{}
		got, err := s.refineResultByCountry(mk(map[string]any{
			"FILTER_COUNTRIES_ENABLED": true,
			"ALLOWED_COUNTRIES":        []string{"SG"},
		}), res, colos, "v6")
		if err == nil {
			t.Fatal("一条不剩时必须报错——返回空结果会让调用方以为测完了")
		}
		if len(got.IPs) != 0 {
			t.Errorf("结果应为空，实际 %v", got.IPs)
		}
		for _, want := range []string{"一条不剩", "前置白名单", "没有写入任何 v6 结果"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("错误里少了 %q：%s", want, err.Error())
			}
		}
		// 这一步只打「筛了几条到几条」；那句给用户看的完整建议由调用方
		// 连同错误一起写进日志，所以下面断言的是账，不是建议原文。
		if !strings.Contains(strings.Join(s.logs, "\n"), "2 → 0") {
			t.Errorf("日志里该留下筛选账（2 → 0），实际 %v", s.logs)
		}
	})
}
