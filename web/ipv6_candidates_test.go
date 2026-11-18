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
	if len(got) > 20 {
		t.Fatalf("采样超出请求数量: %d > 20", len(got))
	}
	t.Logf("采样 %d 个 v6 地址，全部落在 %s 内、格式正确、无重复", len(got), cfNet)
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
