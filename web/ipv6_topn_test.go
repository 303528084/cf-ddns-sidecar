package web

// 「IPv6 显示几条」必须和 IPv4 用同一个开关（2026-11-18）。
//
// 用户的原话：「IPv6 展示多少个，也同 IPv4 展示那个设置一样，放到一个开关上面。
// 设置时显示 10 个，就是显示 10 个；设置 5 个，就是显示 5 个」
//
// 改动前 v6 那边写死 TopN: 10，和「保留候选 IP 数」完全无关——用户在设置页
// 把它改成 5，概览页 IPv4 那张表变 5 行、v6 那张还是 10 行，看起来像设置没生效。
// 这两条测试钉住的就是「同一个值」，以后谁再想给 v6 单独配一个数，先看这里。

import (
	"testing"

	"github.com/303528084/cf-ddns-sidecar/config"
)

// v6 那一轮保留几条，必须跟着 Speed.TopN 走。
func TestV6TopNFollowsSpeedTopN(t *testing.T) {
	cases := []struct {
		cfgTopN int
		want    int
	}{
		{0, 5}, // 没配过（老配置、零值）→ 和 config 的默认值一致
		{1, 1},
		{5, 5},
		{10, 10},
		{20, 20},
	}
	for _, c := range cases {
		cfg := &config.Config{}
		cfg.Speed.TopN = c.cfgTopN
		s := &Server{cfg: cfg}
		if got := s.v6TopN(); got != c.want {
			t.Fatalf("Speed.TopN=%d 时 v6TopN()=%d，应为 %d——两族必须共用同一个数",
				c.cfgTopN, got, c.want)
		}
	}
}

// 配置还没读进来（Server{}）也不能崩、不能返回 0。
//
// 返回 0 的后果很隐蔽：engine 那边会自己兜底成 5，但界面提示和日志会说是 0 条，
// 排查时完全对不上。
func TestV6TopNNilConfig(t *testing.T) {
	s := &Server{}
	if got := s.v6TopN(); got != 5 {
		t.Fatalf("没有配置时 v6TopN()=%d，应为默认值 5", got)
	}
}

// 带宽测速的候选数不能把结果表卡在 30 条以下。
//
// TopN 调到 40 却只让 30 条进带宽测速的话，最多只能返回 30 条结果，
// 用户设的 40 永远达不到，表现和「设置没生效」一模一样。
func TestV6BandwidthCandidatesCoversTopN(t *testing.T) {
	cases := []struct {
		topN int
		want int
	}{
		{0, 30},  // 默认 TopN=5，候选数仍是原来那个 30，不额外变慢
		{5, 30},  // 同上
		{30, 30}, // 刚好够
		{40, 40}, // 必须跟着放大，否则出不了 40 条
		{100, 100},
	}
	for _, c := range cases {
		cfg := &config.Config{}
		cfg.Speed.TopN = c.topN
		s := &Server{cfg: cfg}
		if got := s.v6BandwidthCandidates(); got != c.want {
			t.Fatalf("Speed.TopN=%d 时 v6BandwidthCandidates()=%d，应为 %d",
				c.topN, got, c.want)
		}
	}
}
