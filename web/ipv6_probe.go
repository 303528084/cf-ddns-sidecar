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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/303528084/cf-ddns-sidecar/engine"
)

// ipv6ProbeTimeout 是一次 v6 探测的总时限。
//
// 原来是 3 分钟，按「总数 600 个候选」定的。改成每段固定 30 个之后，用户填 97 个段
// 就是 2910 个候选（本机实测确认），TCP 阶段从约 2 秒变成约 20 秒，后面选出的
// 30 个节点还要各下载一次测带宽（并发只有 3）。3 分钟卡在这种规模上很容易跑到
// 一半被 ctx 掐断，界面显示"探测失败"、连已有结果也不给——比不放大采样更糟。
// 放到 6 分钟：足够 2910 个候选跑完，又比主测速的 10 分钟短，探测卡死时不会长期占着。
const ipv6ProbeTimeout = 6 * time.Minute

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

// candidatesTextFromIPv6 把内置段（只有 2606:4700::/32 一段，走不到用户链接时
// 才用）的采样结果渲染成每行 `[ipv6]:443#US` 的文本。
// n 在这里是「这一段采多少个」，内置段只有一段，所以 n 就是总条数。
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
	nodes := sampleFromIPv6CIDRs(cidrs, ipv6PerPrefix)
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

// claimIPv6Probe 占住「v6 探测」这个坑，返回 false 表示别人正在跑。
//
// 为什么需要：手动探测（点卡片上的按钮）和定时那一轮现在都会跑 v6，
// 两边共用同一个暂存区 s.v6CandText、同一个工作目录 ipv6-probe。真撞上了
// 会互相把对方的候选列表清掉，测出来的东西谁也说不清是哪个的。
// 所以谁先占到谁跑，另一个安静跳过并在日志里说明。
func (s *Server) claimIPv6Probe() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.v6ProbeRunning {
		return false
	}
	s.v6ProbeRunning = true
	s.v6ProbeErr = ""
	return true
}

// handleIPv6Probe 触发一次 v6 探测，立即返回；探测在后台协程里跑。
// 前端随后轮询 /api/ipv6/probe/result 拿结果。异步是为了不让 HTTP 请求
// 等上几十秒（一次完整测速可能要 1 分钟以上）。
func (s *Server) handleIPv6Probe(w http.ResponseWriter, r *http.Request) {
	if !s.claimIPv6Probe() {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "started": false, "note": "探测正在进行中"})
		return
	}

	go func() { _, _ = s.runIPv6Probe() }()

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "started": true})
}

// runIPv6Probe 真正跑 v6 探测，**返回这一轮的 v6 IP 列表**（按质量排序）。
//
// 调用前必须已经 claimIPv6Probe 占到坑，结束时由它自己释放。
//
// 为什么要把结果返回给调用方、而不是让它们去读 cfg.LastIPv6：LastIPv6 存的
// 是「上一次成功的结果」，可能是上一个小时的。自动流程要把 v6 写进 AAAA /
// AdGuard 时必须用**这一轮刚测出来的**，否则会把一个早就不可用的地址写进解析。
//
// 用独立的 workDir，避免覆盖主测速的 config.json/ip.txt。超时也是自己的：
// 主测速那边 ctx 只剩几分钟时不能把 v6 一起拖进去，反之亦然。
func (s *Server) runIPv6Probe() ([]string, error) {
	defer func() {
		s.mu.Lock()
		s.v6ProbeRunning = false
		s.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), ipv6ProbeTimeout)
	defer cancel()

	probeDir := filepath.Join(s.workDir, "ipv6-probe")
	// 用户填了链接就在这里下载解析一次；失败要马上说清原因，不进测速环节
	// ——否则用户只会看到"测速没有产出可用 IP"，根本不知道是链接填错了。
	if err := s.stageIPv6Candidates(ctx); err != nil {
		s.mu.Lock()
		s.v6ProbeErr = err.Error()
		s.v6ProbeNodes = nil
		s.mu.Unlock()
		return nil, err
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

	if err != nil {
		msg := friendlyErr(err)
		s.mu.Lock()
		s.v6ProbeErr = msg
		s.v6ProbeNodes = nil // 失败就清空内存里的旧结果，免得界面显示上一轮的数字
		s.mu.Unlock()
		return nil, errors.New(msg)
	}

	// 成功：内存 + 配置一起更新。
	//
	// 落盘这一步是为了「重启之后还看得到」——一次 v6 优选要 1~2 分钟，
	// 只在内存里的话，升级一次应用就没了，界面显示「还没有结果」像功能坏了。
	// 注意**只写 LastIPv6***，绝不动 v4 那组：两套结果互相独立，v6 跑空
	// 不该把 v4 的结果一起抹掉。
	s.mu.Lock()
	s.v6ProbeErr = ""
	s.v6ProbeNodes = res.Nodes
	s.v6ProbeAt = time.Now()
	s.cfg.LastIPv6 = res.Best()
	s.cfg.LastIPv6IPs = append(make([]string, 0, len(res.IPs)), res.IPs...)
	s.cfg.LastIPv6Nodes = buildNodeStats(res, nil) // v6 暂不做出口机房探测，只留速度/延迟
	s.cfg.LastIPv6Time = s.v6ProbeAt.Format("2006-01-02 15:04:05")
	toSave := s.cfg.Clone()
	s.mu.Unlock()

	if err := toSave.Save(); err != nil {
		s.appendLog("v6 优选结果保存失败（重启后看不到这次结果）: " + friendlyErr(err))
	}
	s.appendLog(fmt.Sprintf("v6 优选完成：最优 %s（共 %d 条可用）", res.Best(), len(res.IPs)))
	// 返回一份独立的切片：调用方会拿它去构造重写/解析集合，别和配置里那份
	// 共享底层数组。
	return append([]string(nil), res.IPs...), nil
}

// handleIPv6ProbeResult 返回最近一次 v6 探测的结果。
//
// 内存里没有时回落到配置里的那份（重启、或者上一轮是定时跑的）：界面上
// 「上一次 v6 结果」这一栏要能一直显示，而不是每次重启就变成空白。
func (s *Server) handleIPv6ProbeResult(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	running := s.v6ProbeRunning
	nodes := append([]engine.Node(nil), s.v6ProbeNodes...)
	at := s.v6ProbeAt
	errMsg := s.v6ProbeErr
	if len(nodes) == 0 && s.cfg != nil && len(s.cfg.LastIPv6Nodes) > 0 {
		nodes = make([]engine.Node, 0, len(s.cfg.LastIPv6Nodes))
		for _, n := range s.cfg.LastIPv6Nodes {
			nodes = append(nodes, engine.Node{IP: n.IP, Speed: n.Speed, Delay: n.Delay})
		}
		if at.IsZero() {
			if t, perr := time.ParseInLocation("2006-01-02 15:04:05", s.cfg.LastIPv6Time, time.Local); perr == nil {
				at = t
			}
		}
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"running": running,
		"nodes":   nodes,
		"at":      at,
		"error":   errMsg,
	})
}
