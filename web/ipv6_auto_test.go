package web

// v6 优选接入主流程后的两条约定测试（2026-11-18）：
//
//  1. 「v6 探测」是一个独占坑：手动探测和定时那一轮都会跑 v6，两边共用同一个
//     候选暂存区和工作目录。撞上了必须有一方安静跳过，不能两个一起跑。
//  2. v6 结果要能从配置里读回来：一次优选要 1~2 分钟，重启之后界面上
//     「上一次结果」不能变成空白。

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/303528084/cf-ddns-sidecar/config"
)

// 同一个坑只能被一个人占住，释放之后才能再占。
func TestClaimIPv6ProbeIsExclusive(t *testing.T) {
	s := &Server{}

	if !s.claimIPv6Probe() {
		t.Fatal("第一次应该能占到")
	}
	if s.claimIPv6Probe() {
		t.Fatal("同一个坑不该被占两次——两个 v6 探测一起跑会互相清掉对方的候选")
	}

	// 模拟探测结束（runIPv6Probe 的 defer 干的就是这件事）。
	s.mu.Lock()
	s.v6ProbeRunning = false
	s.mu.Unlock()

	if !s.claimIPv6Probe() {
		t.Fatal("释放之后应该能重新占到")
	}
}

// 占到坑时必须把上一轮的错误清掉，否则界面会一直挂着上次的报错。
func TestClaimIPv6ProbeClearsOldError(t *testing.T) {
	s := &Server{}
	s.v6ProbeErr = "上一轮的失败原因"

	if !s.claimIPv6Probe() {
		t.Fatal("首次应该能占到")
	}
	s.mu.Lock()
	left := s.v6ProbeErr
	s.mu.Unlock()
	if left != "" {
		t.Fatalf("新一次探测开始时旧的错误要清掉，实际还是 %q", left)
	}
}

// 内存里没有结果时，接口要回落到配置里存的那份。
func TestHandleIPv6ProbeResultFallsBackToConfig(t *testing.T) {
	cfg := config.Default()
	cfg.LastIPv6 = "2606:4700::1"
	cfg.LastIPv6IPs = []string{"2606:4700::1"}
	cfg.LastIPv6Nodes = []config.NodeStat{{IP: "2606:4700::1", Speed: 12.3, Delay: 88,
		Colo: "NRT", Place: "日本·东京(NRT)"}}
	cfg.LastIPv6Time = "2026-11-18 13:36:00"

	s := &Server{cfg: cfg}

	rec := httptest.NewRecorder()
	s.handleIPv6ProbeResult(rec, httptest.NewRequest("GET", "/api/ipv6/probe/result", nil))
	if rec.Code != 200 {
		t.Fatalf("应返回 200，实际 %d: %s", rec.Code, rec.Body.String())
	}

	var out struct {
		Nodes []config.NodeStat `json:"nodes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("响应解析失败: %v（原文 %s）", err, rec.Body.String())
	}
	if len(out.Nodes) != 1 {
		t.Fatalf("应回落到配置里的 1 条，实际 %d 条", len(out.Nodes))
	}
	got := out.Nodes[0]
	if got.IP != "2606:4700::1" || got.Speed != 12.3 || got.Delay != 88 {
		t.Errorf("回落的节点数据不对: %+v", got)
	}
	// 机房位置也必须在：回落这条路以前是把 NodeStat 拆回 engine.Node 再交出去，
	// Colo/Place 就在那一步丢掉了，界面上整列「位置未知」。
	if got.Colo != "NRT" || got.Place == "" {
		t.Errorf("回落时机房位置被丢了：%+v", got)
	}
}

// 内存里有结果时优先用内存的（它更新），不被配置覆盖。
func TestHandleIPv6ProbeResultPrefersMemory(t *testing.T) {
	cfg := config.Default()
	cfg.LastIPv6Nodes = []config.NodeStat{{IP: "2606:4700::9"}}

	s := &Server{
		cfg:          cfg,
		v6ProbeNodes: []config.NodeStat{{IP: "2606:4700::2", Speed: 20, Colo: "HKG", Place: "中国香港·香港(HKG)"}},
	}

	rec := httptest.NewRecorder()
	s.handleIPv6ProbeResult(rec, httptest.NewRequest("GET", "/api/ipv6/probe/result", nil))

	var out struct {
		Nodes []config.NodeStat `json:"nodes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if len(out.Nodes) != 1 || out.Nodes[0].IP != "2606:4700::2" {
		t.Fatalf("应优先用内存里的新结果，实际 %+v", out.Nodes)
	}
	if out.Nodes[0].Colo != "HKG" || out.Nodes[0].Place == "" {
		t.Errorf("内存里那份也要带机房位置：%+v", out.Nodes[0])
	}
}
