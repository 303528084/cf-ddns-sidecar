package ipv6

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// parseForTest 用标准库解析测试里的简写地址。
func parseForTest(s string) (netip.Addr, error) {
	return netip.ParseAddr(s)
}

// procLine 造一行 /proc/net/if_inet6，方便测试按语义拼数据。
//
// addr 是带冒号的 IPv6；prefix/scope/flags 给十进制，函数转成 /proc 里的十六进制。
func procLine(addr, ifname string, prefix, scope, flags int) string {
	a := normalizeAddr(addr)
	return fmt.Sprintf("%s 02 %02X %02X %02X %s", a, prefix, scope, flags, ifname)
}

// normalizeAddr 把简写地址展开成 32 位无冒号十六进制（/proc 的格式）。
func normalizeAddr(addr string) string {
	// 用 netip 解析再展开，测试里就不必手数 32 个字符。
	parsed, err := parseForTest(addr)
	if err != nil {
		panic(err)
	}
	b := parsed.As16()
	var sb strings.Builder
	for _, x := range b {
		fmt.Fprintf(&sb, "%02x", x)
	}
	return sb.String()
}

func writeProc(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "if_inet6")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

// 场景：只有 link-local / ULA / 回环 / 临时 / 废弃 / 未检测完——都不合格。
func TestAllFiltered(t *testing.T) {
	cases := []struct {
		name string
		addr string
		flags int
		want filterReason
	}{
		{"回环", "::1", 0x80, reasonLoopback},
		{"链路本地", "fe80::1", 0x80, reasonLinkLocal},
		{"ULA-fc", "fc00::1", 0x80, reasonULA},
		{"ULA-fd", "fd12:3456::1", 0x80, reasonULA},
		{"临时地址", "2001:db8::99", 0x01, reasonTemporary},
		{"废弃", "2001:db8::1", 0x20, reasonDeprecated},
		{"DAD未完成", "2001:db8::1", 0x40, reasonTentative},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line := procLine(tc.addr, "eth0", 64, 0x10, tc.flags)
			_, got := classify(line)
			if got != tc.want {
				t.Fatalf("过滤原因 = %v，期望 %v（行: %s）", got, tc.want, line)
			}
		})
	}
}

// 场景：全是无效地址时，Report 显示"没有可用"，且统计能加总到总数。
func TestNoAvailableAddress(t *testing.T) {
	p := writeProc(t,
		procLine("::1", "lo", 128, 0x01, 0x80),
		procLine("fe80::1", "eth0", 64, 0x02, 0x80),
		procLine("fd00::1", "eth0", 64, 0x10, 0x80),
		procLine("2001:db8::9", "eth0", 64, 0x10, 0x01), // 临时
	)
	rep, err := ReadFrom(p)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Available || rep.Selected != nil || len(rep.Candidates) != 0 {
		t.Fatalf("不应有可用地址: %+v", rep)
	}
	if rep.Total != 4 {
		t.Fatalf("总数 = %d，期望 4", rep.Total)
	}
	sum := rep.Filtered.Loopback + rep.Filtered.LinkLocal + rep.Filtered.ULA +
		rep.Filtered.Temporary + rep.Filtered.Tentative + rep.Filtered.Deprecated +
		rep.Filtered.Other + rep.Filtered.BadLine
	if sum != rep.Total {
		t.Fatalf("过滤计数合计 %d != 总数 %d（%+v）", sum, rep.Total, rep.Filtered)
	}
	if rep.Filtered.Temporary != 1 || rep.Filtered.LinkLocal != 1 || rep.Filtered.ULA != 1 || rep.Filtered.Loopback != 1 {
		t.Fatalf("各类过滤计数不对: %+v", rep.Filtered)
	}
}

// 场景：多条合格地址，挑"前缀 64 + 网卡名最短"的那条。
func TestPickBestPrefixAndShortestName(t *testing.T) {
	p := writeProc(t,
		procLine("2001:db8::1", "br-docker0", 64, 0x10, 0x80), // 前缀对，但名字长
		procLine("2001:db8::2", "enp1s0", 128, 0x10, 0x80),    // 名字短，但前缀不是 64
		procLine("2001:db8::3", "eth0", 64, 0x10, 0x80),        // 前缀 64 + 名字最短 → 应挑它
		procLine("2001:db8::4", "veth9", 64, 0x10, 0x80),       // 前缀对，名字比 eth0 长
	)
	rep, err := ReadFrom(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Candidates) != 4 {
		t.Fatalf("合格地址数 = %d，期望 4", len(rep.Candidates))
	}
	if rep.Selected == nil || rep.Selected.Interface != "eth0" || !strings.HasSuffix(rep.Selected.Address, "::3") {
		t.Fatalf("挑错了: %+v", rep.Selected)
	}
	// 选中标记只出现一次。
	selCount := 0
	for _, c := range rep.Candidates {
		if c.Selected {
			selCount++
		}
	}
	if selCount != 1 {
		t.Fatalf("选中标记出现 %d 次，期望 1", selCount)
	}
	if !strings.Contains(rep.Selected.Why, "前缀 64") || !strings.Contains(rep.Selected.Why, "eth0") {
		t.Fatalf("挑选理由没写清: %q", rep.Selected.Why)
	}
}

// 场景：前缀一样、网卡名一样长时，按地址排序，结果稳定不抖动。
func TestPickIsDeterministic(t *testing.T) {
	lines := []string{
		procLine("2001:db8::20", "eth1", 64, 0x10, 0x80),
		procLine("2001:db8::10", "eth0", 64, 0x10, 0x80),
	}
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		rep, err := ReadFrom(writeProc(t, lines...))
		if err != nil {
			t.Fatal(err)
		}
		if rep.Selected == nil {
			t.Fatal("应有选中地址")
		}
		seen[rep.Selected.Address] = true
	}
	if len(seen) != 1 {
		t.Fatalf("挑选结果不稳定: %v", seen)
	}
}

// 场景：flags 原文被保留，permanent 位被正确识别——这是真机核对 flags 判据的依据。
func TestFlagsPreserved(t *testing.T) {
	p := writeProc(t,
		procLine("2001:db8::1", "eth0", 64, 0x10, 0x80), // permanent
	)
	rep, err := ReadFrom(p)
	if err != nil {
		t.Fatal(err)
	}
	c := rep.Candidates[0]
	if c.FlagsRaw != "0x80" || !c.Permanent {
		t.Fatalf("flags 没保留好: %+v", c)
	}
}

// 场景：坏行（字段数不对 / 地址非法）计入 BadLine，不让整个检测失败。
func TestBadLinesCounted(t *testing.T) {
	p := writeProc(t,
		"garbage line",
		procLine("2001:db8::1", "eth0", 64, 0x10, 0x80),
	)
	rep, err := ReadFrom(p)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Filtered.BadLine != 1 || len(rep.Candidates) != 1 || rep.Total != 2 {
		t.Fatalf("坏行处理不对: %+v", rep)
	}
}

// 场景：文件读不到时明确报错，不静默返回空结果。
func TestReadError(t *testing.T) {
	if _, err := ReadFrom(filepath.Join(t.TempDir(), "nonexistent")); err == nil {
		t.Fatal("读不到文件应报错")
	}
}

// 场景：六列解析本身正确（ifindex 也确实是十六进制）。
func TestClassifyParsesFields(t *testing.T) {
	line := procLine("2001:db8::1", "eth0", 64, 0x10, 0x80)
	got, reason := classify(line)
	if reason != reasonNone {
		t.Fatalf("不该被过滤: %v", reason)
	}
	if got.addr.String() != "2001:db8::1" || got.prefix != 64 || got.scope != 0x10 || got.flags != 0x80 || got.ifname != "eth0" {
		t.Fatalf("解析错了: %+v", got)
	}
}
