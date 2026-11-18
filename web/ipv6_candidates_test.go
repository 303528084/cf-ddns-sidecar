package web

import (
	"net/netip"
	"strings"
	"testing"
)

// TestSampleFromIPv6CIDRs 验证 v6 采样的四件事：格式带方括号、地址落在段内、
// 不重复、数量够。这四点任何一点错了，真机都会测出一堆假节点或静默错误。
func TestSampleFromIPv6CIDRs(t *testing.T) {
	got := sampleFromIPv6CIDRs(cloudflareIPv6, 20)
	if len(got) == 0 {
		t.Fatal("没有采样出任何 v6 地址")
	}
	cfNet, err := netip.ParsePrefix("2606:4700::/32")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool, len(got))
	for _, node := range got {
		// 格式必须是 [ipv6]:443#US —— 裸 v6 会让 Go 端 SplitHostPort 拆不开。
		if !strings.HasPrefix(node, "[") || !strings.Contains(node, "]:443#US") {
			t.Fatalf("节点串格式不对（缺方括号）: %s", node)
		}
		host := strings.TrimSuffix(strings.TrimPrefix(node, "["), "]:443#US")
		addr, err := netip.ParseAddr(host)
		if err != nil {
			t.Fatalf("地址不是合法 v6: %s (%v)", host, err)
		}
		if !addr.Is6() {
			t.Fatalf("不是 IPv6: %s", host)
		}
		if !cfNet.Contains(addr) {
			t.Fatalf("地址落在 CF v6 段外: %s", host)
		}
		if seen[host] {
			t.Fatalf("重复地址: %s", host)
		}
		seen[host] = true
	}
	// cloudflareIPv6 只有一段，所以「每段 20 个」= 总共正好 20 个。
	if len(got) != 20 {
		t.Fatalf("1 段 × 每段 20 个应产出 20 条，实际 %d", len(got))
	}
	t.Logf("采样 %d 个 v6 地址，全部落在 %s 内、格式正确、无重复", len(got), cfNet)
}

// TestSampleFromIPv6CIDRsPerPrefix 回归：采样按「每段 N 个」算，不按总数平分。
//
// 这个是 2026-11-18 真机问题的根因回归：以前是「总数 600 按段数平分」，
// 用户填 97 段时每段只剩 6 个，命中率被稀释到 585 个候选只通 30 个。
// 现在每段固定 ipv6PerPrefix 个，段越多总量越大，每段都保证有足够采样点。
func TestSampleFromIPv6CIDRsPerPrefix(t *testing.T) {
	// 五段必须互不包含，否则 Contains 归属统计会把子段算到大段头上。
	cidrs := []string{
		"2400:cb00:2049::/48",
		"2606:4700:3000::/48",
		"2606:4700:3100::/48",
		"2606:4700:130::/48",
		"2a06:98c1:3100::/48",
	}
	const per = 12
	got := sampleFromIPv6CIDRs(cidrs, per)
	if len(got) != len(cidrs)*per {
		t.Fatalf("5 段 × 每段 %d 个应为 %d 条，实际 %d", per, len(cidrs)*per, len(got))
	}
	// 每个段都必须被抽满 per 条——这是「按段固定」和「总数平分」的区别所在。
	counts := make(map[string]int, len(cidrs))
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, s := range cidrs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("测试数据里的段不合法: %s (%v)", s, err)
		}
		prefixes = append(prefixes, p)
	}
	for _, node := range got {
		host := strings.TrimSuffix(strings.TrimPrefix(node, "["), "]:443#US")
		addr, err := netip.ParseAddr(host)
		if err != nil {
			t.Fatalf("采样格式不对: %s (%v)", node, err)
		}
		for _, p := range prefixes {
			if p.Contains(addr) {
				counts[p.String()]++
				break
			}
		}
	}
	for _, p := range prefixes {
		if counts[p.String()] != per {
			t.Errorf("段 %s 只抽到 %d 条，应为 %d 条", p, counts[p.String()], per)
		}
	}
}

// TestSampleFromIPv6CIDRsCap 总条数不能突破 maxIPv6Candidates，
// 否则用户填几百个段会把一次探测拖成十几分钟。
func TestSampleFromIPv6CIDRsCap(t *testing.T) {
	// 两段各要 maxIPv6Candidates 条 → 总量 2×上限，应被截到上限。
	got := sampleFromIPv6CIDRs([]string{"2606:4700::/32", "2a06:98c1:3100::/48"}, maxIPv6Candidates)
	if len(got) != maxIPv6Candidates {
		t.Fatalf("应截断到 %d 条，实际 %d", maxIPv6Candidates, len(got))
	}
}

// TestSampleFromIPv6CIDRsNoV4 确保 v4 段不会被误当成 v6 采样（To4 的坑）。
func TestSampleFromIPv6CIDRsNoV4(t *testing.T) {
	got := sampleFromIPv6CIDRs([]string{"104.16.0.0/13"}, 10)
	if len(got) != 0 {
		t.Fatalf("v4 段不应产出 v6 地址，实际: %v", got)
	}
}

// TestSampleFromIPv6CIDRsTinyPrefix /127、/128 没有采样空间，应跳过。
func TestSampleFromIPv6CIDRsTinyPrefix(t *testing.T) {
	got := sampleFromIPv6CIDRs([]string{"2606:4700::1/128"}, 10)
	if len(got) != 0 {
		t.Fatalf("/128 不应产出地址，实际: %v", got)
	}
}

// TestParseIPv6CIDRsFromLink 用用户实际给的那种 CF v6 段列表验证解析：
// 一行一段、# 注释、全都要认出来；随后采样必须落在这些段里。
func TestParseIPv6CIDRsFromLink(t *testing.T) {
	text := `# Cloudflare IPv6 ranges
2400:cb00:2049::/48
2400:cb00:f00e::/48
2606:4700::/32
2606:4700:10::/48
2606:4700:130::/48
2606:4700:3000::/48
2606:4700:3001::/48
2606:4700:3002::/48
2606:4700:3003::/48
2606:4700:3004::/48
2606:4700:3005::/48
2606:4700:3006::/48
2606:4700:3007::/48`
	cidrs, skipped := parseIPv6CIDRs(text)
	if len(cidrs) != 13 {
		t.Fatalf("应认出 13 段，实际 %d 段: %v（skip %v）", len(cidrs), cidrs, skipped)
	}
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, s := range cidrs {
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is6() {
			t.Fatalf("解析出非法 v6 段: %s (%v)", s, err)
		}
		prefixes = append(prefixes, p)
	}
	for _, node := range sampleFromIPv6CIDRs(cidrs, 40) {
		host := strings.TrimSuffix(strings.TrimPrefix(node, "["), "]:443#US")
		addr, err := netip.ParseAddr(host)
		if err != nil {
			t.Fatalf("采样格式不对: %s (%v)", node, err)
		}
		in := false
		for _, p := range prefixes {
			if p.Contains(addr) {
				in = true
				break
			}
		}
		if !in {
			t.Fatalf("采样地址不在用户给的段里: %s", host)
		}
	}
}

// TestParseIPv6CIDRsFilters 验证三件会误导人的事：v4 段不能被当 v6 收下、
// RFC 3849 文档段不能浪费测速时间、重复段只留一条。
func TestParseIPv6CIDRsFilters(t *testing.T) {
	text := `104.16.0.0/13, 2001:db8::/32; 2606:4700::/32 | 2606:4700::/32
这是说明文字`
	cidrs, skipped := parseIPv6CIDRs(text)
	if len(cidrs) != 1 || cidrs[0] != "2606:4700::/32" {
		t.Fatalf("应只留下 2606:4700::/32 一次，实际: %v", cidrs)
	}
	if len(skipped) == 0 {
		t.Fatal("认不出的 token 应留作日志样例，实际一条都没有")
	}
}
