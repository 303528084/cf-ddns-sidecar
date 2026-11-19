package web

// 「按记录类型分流」的两个纯函数测试（2026-11-18，阶段②）。
//
// 这两处一旦搞错都是**安静的错**：把 v4 地址写进 AAAA、或者把 v6 答案从
// AdGuard 里删掉，都不会有任何报错，只有"怎么没变快"或者"网页打不开"。

import (
	"testing"

	"github.com/303528084/cf-ddns-sidecar/config"
	"github.com/303528084/cf-ddns-sidecar/ddns"
)

// AdGuard 的答案集合必须同时包含 v4 和 v6。
func TestRewriteAnswersKeepsBothFamilies(t *testing.T) {
	got := rewriteAnswers("162.159.39.41", []string{"2606:4700::1", "2606:4700::2"})
	if len(got) != 2 {
		t.Fatalf("应同时写 v4 和 v6 两条答案，实际 %d 条：%v", len(got), got)
	}
	if !got["162.159.39.41"] {
		t.Error("缺了 v4 最优")
	}
	// 只写 v6 的最优一条（和 v4 那边"只写 best"对称），不是全部。
	if !got["2606:4700::1"] || got["2606:4700::2"] {
		t.Errorf("v6 应只取最优那一条，实际 %v", got)
	}
}

// 这一轮没测出 v6 时只给 v4——旧的 v6 答案会被 ReplaceRewrites 清掉，这是有意的
// （删了 v6 客户端回落 v4，比留着一条没人验证过的 AAAA 安全）。
func TestRewriteAnswersV4OnlyWhenNoV6(t *testing.T) {
	for _, v6 := range [][]string{nil, {}, {""}} {
		got := rewriteAnswers("162.159.39.41", v6)
		if len(got) != 1 || !got["162.159.39.41"] {
			t.Errorf("v6 为空时只该有 v4 一条，实际 %v", got)
		}
	}
}

// 空的 v4 也不该塞一个空字符串答案进去（AdGuard 会当成坏规则）。
func TestRewriteAnswersSkipEmptyStrings(t *testing.T) {
	if got := rewriteAnswers("", nil); len(got) != 0 {
		t.Fatalf("全空时应给出空集合，实际 %v", got)
	}
	if got := rewriteAnswers("", []string{""}); len(got) != 0 {
		t.Fatalf("空答案不该被写进去，实际 %v", got)
	}
}

// 手动推送 / 测试密钥时，按类型取对应的上一次排名，连速度明细一起取。
// 速度明细是「最低下载速度」门槛唯一的依据，取错了族就等于拿 v4 的速度
// 去判 v6 的地址。
func TestLastRankForType(t *testing.T) {
	c := config.Default()
	c.LastIP = "1.1.1.1"
	c.LastIPs = []string{"1.1.1.1", "1.1.1.2"}
	c.LastNodes = []config.NodeStat{{IP: "1.1.1.1", Speed: 20}, {IP: "1.1.1.2", Speed: 15}}
	c.LastIPv6 = "2606:4700::1"
	c.LastIPv6IPs = []string{"2606:4700::1", "2606:4700::2"}
	c.LastIPv6Nodes = []config.NodeStat{{IP: "2606:4700::1", Speed: 30}}

	best, rank, nodes := lastRankForType(c, ddns.TypeA)
	if best != "1.1.1.1" || len(rank) != 2 || rank[1] != "1.1.1.2" {
		t.Errorf("A 应取 v4 那组，实际 best=%q rank=%v", best, rank)
	}
	if len(nodes) != 2 || nodes[1].Speed != 15 {
		t.Errorf("A 应带 v4 的速度明细，实际 %v", nodes)
	}

	best, rank, nodes = lastRankForType(c, ddns.TypeAAAA)
	if best != "2606:4700::1" || len(rank) != 2 || rank[1] != "2606:4700::2" {
		t.Errorf("AAAA 应取 v6 那组，实际 best=%q rank=%v", best, rank)
	}
	if len(nodes) != 1 || nodes[0].Speed != 30 {
		t.Errorf("AAAA 应带 v6 的速度明细，实际 %v", nodes)
	}

	// 返回的是拷贝：调用方改它不能影响配置。
	rank[0] = "mutated"
	nodes[0].Speed = 999
	if c.LastIPv6IPs[0] != "2606:4700::1" || c.LastIPv6Nodes[0].Speed != 30 {
		t.Error("rank / nodes 必须是拷贝，不能被调用方改到配置里")
	}

	if best, rank, nodes := lastRankForType(nil, ddns.TypeAAAA); best != "" || rank != nil || nodes != nil {
		t.Errorf("空配置应返回空值，实际 %q %v %v", best, rank, nodes)
	}
}
