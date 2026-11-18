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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/303528084/cf-ddns-sidecar/engine"
)

// handleIPv6Source 读写「v6 段链接」这个独立设置。
//
// 为什么不做成 /api/config 的一个字段：那个接口是全量保存，前端每次保存
// 都要提交十几个字段；而这里是探测卡片里的一个独立输入框，点一下只改这一项。
// 两者共用同一个 config.json，但写入路径分开，互不覆盖。
func (s *Server) handleIPv6Source(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		u := s.cfg.IPv6ProbeURL
		s.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "url": u})
	case http.MethodPost:
		var body struct {
			URL string `json:"url"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求格式错误"})
			return
		}
		u := strings.TrimSpace(body.URL)
		if u != "" {
			parsed, err := url.Parse(u)
			if err != nil || parsed.Host == "" ||
				(parsed.Scheme != "http" && parsed.Scheme != "https") {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error": "链接要以 http:// 或 https:// 开头，并且带上域名",
				})
				return
			}
		}

		s.mu.Lock()
		cfg := s.cfg.Clone()
		s.mu.Unlock()
		cfg.IPv6ProbeURL = u
		// 先落盘再改内存：写失败时界面显示的还是旧值，不会"以为存上了"。
		if err := cfg.Save(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "保存失败: " + friendlyErr(err),
			})
			return
		}
		s.mu.Lock()
		s.cfg = &cfg
		s.mu.Unlock()
		if u == "" {
			s.appendLog("IPv6 探测来源链接已清空，恢复用内置 CF v6 段")
		} else {
			s.appendLog("IPv6 探测来源链接已保存：" + u)
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "url": u})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleIPv6Candidates 给探测用的测速引擎喂 v6 候选。
//
// 两种来源：用户填了段链接就返回开跑前解析好的暂存内容；没填才回退到
// 内置的 CF v6 段（v1.6.7 行为）。和主测速的 /api/candidates 完全隔离——
// 这里给的地址永远只用于探测，不会进 res.IPs，更不会写 AdGuard / DDNS。
func (s *Server) handleIPv6Candidates(w http.ResponseWriter, r *http.Request) {
	count := atoiDefault(r.URL.Query().Get("n"), candidateCount)
	if count > 3000 {
		count = 3000
	}
	s.mu.Lock()
	text, staged := s.v6CandText, s.v6CandStaged
	s.mu.Unlock()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if staged {
		_, _ = w.Write([]byte(text))
		return
	}
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

// stageIPv6Candidates 在探测开跑前把用户填的 v6 段链接下载解析一次。
//
// 为什么不在 handleIPv6Candidates 里现场下载：引擎会重试、也可能请求多次，
// 每来一次就下一遍外部站点，既慢又容易被对方限流（主测速的 candText 同样是
// 这个道理）。失败原因直接返回给 runIPv6Probe 写进 v6ProbeErr——用户看到的是
// "链接拉取失败（HTTP 404）"这种能动手修的话，而不是笼统的"没有产出可用 IP"。
func (s *Server) stageIPv6Candidates(ctx context.Context) error {
	s.mu.Lock()
	u := strings.TrimSpace(s.cfg.IPv6ProbeURL)
	s.mu.Unlock()
	if u == "" {
		s.unstageIPv6Candidates() // 清掉上一次的暂存，避免"删了链接还在用旧段"
		return nil
	}

	text, err := fetchSourceText(ctx, u)
	if err != nil {
		return fmt.Errorf("v6 段链接拉取失败（%s）：%w", u, err)
	}
	cidrs, skipped := parseIPv6CIDRs(text)
	if len(cidrs) == 0 {
		return fmt.Errorf("v6 段链接里没认出 IPv6 段（%s）：%s%s",
			u,
			"内容里一个合法的 CIDR 都没有",
			sampleHint(skipped))
	}
	nodes := sampleFromIPv6CIDRs(cidrs, candidateCount)
	s.mu.Lock()
	s.v6CandText = strings.Join(nodes, "\n") + "\n"
	s.v6CandStaged = true
	s.mu.Unlock()
	s.appendLog(fmt.Sprintf(
		"v6 探测来源链接解析完成（%s）：认出 %d 个 IPv6 段、生成 %d 个候选地址%s",
		u, len(cidrs), len(nodes), sampleHint(skipped)))
	return nil
}

func (s *Server) unstageIPv6Candidates() {
	s.mu.Lock()
	s.v6CandText, s.v6CandStaged = "", false
	s.mu.Unlock()
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
	// 用户填了链接就在这里下载解析一次；失败要马上说清原因，不进测速环节
	// ——否则用户只会看到"测速没有产出可用 IP"，根本不知道是链接填错了。
	if err := s.stageIPv6Candidates(ctx); err != nil {
		s.mu.Lock()
		s.v6ProbeErr = err.Error()
		s.v6ProbeNodes = nil
		s.mu.Unlock()
		return
	}
	defer s.unstageIPv6Candidates()

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
