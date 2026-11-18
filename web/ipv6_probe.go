package web

// Cloudflare IPv6 节点探测（阶段①：只测不写）。
//
// 这一整套和主测速是完全隔离的两条路：
//   - 主测速：采样 CF 的 IPv4 段 → engine.Run → res.IPs → 写 AdGuard + DDNS；
//   - 本探测：采样 CF 的 IPv6 段 → engine.Run → 只存到 s.v6ProbeNodes 供界面显示。
//
// 探测结果**绝不**进 res.IPs，所以无论探测跑多少次、选出什么 v6 地址，
// 都不会被写进 AdGuard 重写或 DDNS 解析——这正是阶段①"只测不写"的硬保证。
// 目的只是回答一个问题：从这台机器连 Cloudflare 的 v6 节点，到底快不快、值不值得
// 在阶段②把它写进 AAAA。

import (
	"context"
	"net/http"
	"path/filepath"
	"time"

	"github.com/303528084/cf-ddns-sidecar/engine"
)

// handleIPv6Candidates 给探测用的测速引擎喂 CF v6 候选。
// 固定采样 cloudflareIPv6（2606:4700::/32），不读用户配置、不依赖暂存，
// 因此和主测速的 /api/candidates 互不干扰。
func (s *Server) handleIPv6Candidates(w http.ResponseWriter, r *http.Request) {
	count := atoiDefault(r.URL.Query().Get("n"), candidateCount)
	if count > 3000 {
		count = 3000
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(candidatesTextFromIPv6(count)))
}

// candidatesTextFromIPv6 把 v6 采样结果渲染成每行 `[ipv6]:443#US` 的文本。
func candidatesTextFromIPv6(count int) string {
	out := sampleFromIPv6CIDRs(cloudflareIPv6, count)
	s := ""
	for _, node := range out {
		s += node + "\n"
	}
	return s
}

// handleIPv6Probe 触发一次 v6 探测，立即返回；探测在后台协程里跑。
// 前端随后轮询 /api/ipv6/probe/result 拿结果。异步是为了不让 HTTP 请求
// 等上几十秒（一次完整测速可能要 1 分钟以上）。
func (s *Server) handleIPv6Probe(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.v6ProbeRunning {
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "started": false, "note": "探测正在进行中"})
		return
	}
	s.v6ProbeRunning = true
	s.v6ProbeErr = ""
	s.mu.Unlock()

	go s.runIPv6Probe()

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "started": true})
}

// runIPv6Probe 真正跑 v6 探测。用独立的 workDir，避免覆盖主测速的 config.json/ip.txt。
func (s *Server) runIPv6Probe() {
	defer func() {
		s.mu.Lock()
		s.v6ProbeRunning = false
		s.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	probeDir := filepath.Join(s.workDir, "ipv6-probe")
	res, err := engine.Run(ctx, s.enginePath, probeDir, engine.Options{
		TopN:                10,
		BandwidthCandidates: 30,
		CandidatesURL:       s.selfURL + "/api/ipv6/candidates",
		UseBuiltinSources:   false, // 只用我们喂的 v6 候选，不叠加 v4 聚合源
		// 按用户定稿的决定②：探测阶段就关掉"过滤 ipv6_only 出口"的开关，
		// 否则 v6 节点会在写结果前被全部剔除，探测永远看不到它们。
		Overrides: map[string]any{"FILTER_IPV6_AVAILABILITY": false},
	}, s.appendLog)

	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.v6ProbeErr = friendlyErr(err)
		s.v6ProbeNodes = nil
		return
	}
	s.v6ProbeErr = ""
	s.v6ProbeNodes = res.Nodes // 只存节点，绝不动 res.IPs / res.Best() 的写入路径
	s.v6ProbeAt = time.Now()
}

// handleIPv6ProbeResult 返回最近一次 v6 探测的结果。
func (s *Server) handleIPv6ProbeResult(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	running := s.v6ProbeRunning
	nodes := append([]engine.Node(nil), s.v6ProbeNodes...)
	at := s.v6ProbeAt
	errMsg := s.v6ProbeErr
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"running": running,
		"nodes":   nodes,
		"at":      at,
		"error":   errMsg,
	})
}
