package web

// Cloudflare IPv6 节点优选。和主测速是两条独立的路：主测速采样 IPv4 段 → engine.Run →
// res.IPs → 写 AdGuard + DDNS；本探测采样 IPv6 段 → engine.Run → 结果回给调用方。
//
// 「只测不写」这条保证只对手动探测成立：runIPv6Probe 自己不碰 AdGuard 和 DDNS，只把结果
// 存进 s.v6ProbeNodes / cfg.LastIPv6* 供界面显示。真正写 AAAA 的是 server.go 的 runOnce，
// 它调 runIPv6Probe 拿到这一轮的地址，再和 v4 一起交给 EnsureRecords。也就是说点「开始
// 探测」永远不会改动你的解析，只有「立即测速」/ 定时那一轮才会。

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/303528084/cf-ddns-sidecar/config"
	"github.com/303528084/cf-ddns-sidecar/engine"
)

// ipv6ProbeTimeout 是一次 v6 探测的总时限。原来是 3 分钟，按「总数 600 个候选」定的；
// 改成每段固定 30 个之后，用户填 97 个段就是 2910 个候选（本机实测确认），TCP 阶段从约
// 2 秒变成约 20 秒，后面选出的 30 个节点还要各下载一次测带宽（并发只有 3），3 分钟很容易
// 跑到一半被 ctx 掐断，界面显示「探测失败」、连已有结果也不给。放到 6 分钟：够 2910 个
// 候选跑完，又比主测速的 10 分钟短，探测卡死时不会长期占着。
const ipv6ProbeTimeout = 6 * time.Minute

// handleIPv6Candidates 给探测用的测速引擎喂 v6 候选。用户填了段链接就返回开跑前解析好的
// 暂存内容，没填才回退到内置的 CF v6 段。和主测速的 /api/candidates 完全隔离，这里给的
// 地址永远只用于探测，不会进 res.IPs，更不会写 AdGuard / DDNS。
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

// stageIPv6Candidates 在探测开跑前把用户填的 v6 段链接下载解析一次。不在
// handleIPv6Candidates 里现场下载：引擎会重试、也可能请求多次，每来一次就下一遍外部站点，
// 既慢又容易被限流。失败原因直接返回给 runIPv6Probe 写进 v6ProbeErr，用户看到的是
// 「链接拉取失败（HTTP 404）」这种能动手修的话。支持一行一个链接：
//   - 段按字符串去重后再采样，两个链接里出现同一个段不会采出两倍地址；
//   - 某条链接挂了不算整体失败，只要还有别的链接给出段就照常往下测，挂掉的那几条写进
//     日志；全部挂掉才报错，并把每条的原因都列出来。
func (s *Server) stageIPv6Candidates(ctx context.Context) error {
	s.mu.Lock()
	urls := s.cfg.IPv6SourceURLs()
	s.mu.Unlock()
	if len(urls) == 0 {
		s.unstageIPv6Candidates() // 清掉上一次的暂存，避免"删了链接还在用旧段"
		return nil
	}

	allCIDRs := make([]string, 0, 64)
	seenCIDR := make(map[string]bool, 64)
	var failed []string
	for _, u := range urls {
		text, err := fetchSourceText(ctx, u)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s（拉取失败：%v）", u, err))
			continue
		}
		cidrs, skipped := parseIPv6CIDRs(text)
		if len(cidrs) == 0 {
			failed = append(failed, fmt.Sprintf("%s（内容里一个合法的 IPv6 段都没有%s）",
				u, sampleHint(skipped)))
			continue
		}
		for _, c := range cidrs {
			if seenCIDR[c] {
				continue
			}
			seenCIDR[c] = true
			allCIDRs = append(allCIDRs, c)
		}
	}
	if len(allCIDRs) == 0 {
		return fmt.Errorf("v6 段链接一个都没用上：%s", strings.Join(failed, "；"))
	}

	nodes := sampleFromIPv6CIDRs(allCIDRs, ipv6PerPrefix)
	s.mu.Lock()
	s.v6CandText = strings.Join(nodes, "\n") + "\n"
	s.v6CandStaged = true
	s.mu.Unlock()
	s.appendLog(fmt.Sprintf(
		"v6 测速来源解析完成：%d 个链接 → 认出 %d 个 IPv6 段 → 生成 %d 个候选地址",
		len(urls), len(allCIDRs), len(nodes)))
	// 有链接失败但不影响这一轮：单独说清楚是哪几条，别让用户以为全都生效了。
	if len(failed) > 0 {
		s.appendLog(fmt.Sprintf("v6 测速来源里有 %d 条没用上：%s",
			len(failed), strings.Join(failed, "；")))
	}
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

// v6TopN 返回 v6 那一轮要保留多少条结果，和 IPv4 共用「保留候选 IP 数」。
//
// 为什么要共用：那一栏的语义是「这批候选留几条给我选」，IPv4 和 IPv6 是
// 同一个问题的两个族，各留一个数只会让人困惑（用户原话：「设置时显示 10 个，
// 就是显示 10 个；设置 5 个，就是显示 5 个」）。概览页两张表的行数也因此一致。
func (s *Server) v6TopN() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg != nil && s.cfg.Speed.TopN > 0 {
		return s.cfg.Speed.TopN
	}
	return 5 // 和 config 的默认值一致；以前 v6 这边写死 10，那是另一个数
}

// v6BandwidthCandidates 是 v6 这一轮「先按延迟筛几条去真下载测速」。
//
// 以前写死 30。改成跟着 TopN 走（但不低于 30）：TopN 调到 30 以上时，如果
// 仍然只测 30 条，结果表就永远到不了用户要的条数，看起来像「设置没生效」。
// 不直接跟 Speed.BandwidthCandidates（默认 100）：v6 的候选池只有两千多条、
// 下载并发又只有 3，照搬 100 会让手动探测慢到没法用来试链接。
func (s *Server) v6BandwidthCandidates() int {
	n := s.v6TopN()
	if n < 30 {
		return 30
	}
	return n
}

// runIPv6Probe 真正跑 v6 探测，返回这一轮的 v6 IP 列表（按质量排序）。调用前必须已经
// claimIPv6Probe 占到坑，结束时由它自己释放。
//
// 结果返回给调用方而不是让它们读 cfg.LastIPv6：后者存的是「上一次成功的结果」，可能是
// 上一个小时的，自动流程要把 v6 写进 AAAA 时必须用这一轮刚测出来的。用独立 workDir，
// 避免覆盖主测速的 config.json/ip.txt；超时也是自己的，主测速 ctx 只剩几分钟时不能把
// v6 一起拖进去。
func (s *Server) runIPv6Probe() ([]string, error) {
	defer func() {
		s.mu.Lock()
		s.v6ProbeRunning = false
		s.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), ipv6ProbeTimeout)
	defer cancel()

	probeDir := filepath.Join(s.workDir, "ipv6-probe")
	// 「哪些设置交给引擎」和「按哪套国家规则筛」这两件事进来先定死。
	// 用快照而不是边跑边读配置：一次探测要 1~2 分钟，中途用户点「保存设置」
	// 会让「按 A 规则测出来的结果」和「按 B 规则筛」拼在一起，事后没人说得清。
	// （保留候选条数仍由 v6TopN/v6BandwidthCandidates 现取，那两个有默认值兜底。）
	s.mu.Lock()
	cfg := s.cfg.Clone()
	s.mu.Unlock()

	// 用户填了链接就在这里下载解析一次；失败要马上说清原因，不进测速环节
	//，否则用户只会看到"测速没有产出可用 IP"，根本不知道是链接填错了。
	if err := s.stageIPv6Candidates(ctx); err != nil {
		s.mu.Lock()
		s.v6ProbeErr = err.Error()
		s.v6ProbeNodes = nil
		s.mu.Unlock()
		return nil, err
	}
	defer s.unstageIPv6Candidates()

	res, err := engine.Run(ctx, s.enginePath, probeDir, engine.Options{
		TopN:                s.v6TopN(),
		BandwidthCandidates: s.v6BandwidthCandidates(),
		CandidatesURL:       s.selfURL + "/api/ipv6/candidates",
		UseBuiltinSources:   false, // 只用我们喂的 v6 候选，不叠加 v4 聚合源
		// 用户的高级设置照传，但国家那几项除外，v6 候选没有真实国家标签，
		// 交给引擎只会误杀或空转，改由测完按机房位置筛（见 v6_settings.go）。
		// 里面最后一条会强制压掉"过滤 ipv6_only 出口"（用户定稿的决定②）：
		// 那个开关一开，v6 节点会在写结果前被全部剔除，探测永远看不到它们。
		Overrides: v6Overrides(cfg),
	}, s.appendLog)

	if err != nil {
		msg := friendlyErr(err)
		s.mu.Lock()
		s.v6ProbeErr = msg
		s.v6ProbeNodes = nil // 失败就清空内存里的旧结果，免得界面显示上一轮的数字
		s.mu.Unlock()
		return nil, errors.New(msg)
	}

	// 成功：内存 + 配置一起更新。落盘是为了「重启之后还看得到」，一次 v6 优选要 1~2
	// 分钟，只在内存里的话升级一次应用就没了。只写 LastIPv6*，绝不动 v4 那组：两套结果
	// 互相独立，v6 跑空不该把 v4 一起抹掉。
	// 真实机房位置：和 v4 同一套办法，穿过这个 v6 地址问 /cdn-cgi/trace 读 colo。
	// 用独立于探测的 ctx：6 分钟的探测预算经常在测带宽那步就快用完，沿用它会一条都探不
	// 出去，界面整列变成「位置未知」，比不探更误导人。预算由 exitProbePlan 算。
	_, exitAllowance := exitProbePlan(len(res.IPs))
	exitCtx, exitCancel := context.WithTimeout(context.Background(), exitAllowance)
	colos := s.logExitColos(exitCtx, res.IPs, "IPv6 ")
	exitCancel()

	// 国家筛选必须放在这里：候选带的 `#US` 是占位标签，真实位置只有探完
	// 机房才知道。代价是被筛掉的节点也白测了一遍，日志里如实写出来。
	if res, err = s.refineResultByCountry(cfg, res, colos, "v6"); err != nil {
		s.mu.Lock()
		s.v6ProbeErr = err.Error()
		s.v6ProbeNodes = nil
		s.mu.Unlock()
		return nil, err
	}

	stats := buildNodeStats(res, colos)

	s.mu.Lock()
	s.v6ProbeErr = ""
	s.v6ProbeNodes = stats
	s.v6ProbeAt = time.Now()
	s.cfg.LastIPv6 = res.Best()
	s.cfg.LastIPv6IPs = append(make([]string, 0, len(res.IPs)), res.IPs...)
	// 复制一份给配置：内存那份和落盘那份别共享底层数组，否则以后谁在
	// 内存结果上原地改一格，配置里那份会跟着变、下次启动才暴露。
	s.cfg.LastIPv6Nodes = append(make([]config.NodeStat, 0, len(stats)), stats...)
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
	nodes := append([]config.NodeStat(nil), s.v6ProbeNodes...)
	at := s.v6ProbeAt
	errMsg := s.v6ProbeErr
	if len(nodes) == 0 && s.cfg != nil && len(s.cfg.LastIPv6Nodes) > 0 {
		// 直接给落盘那份的副本：它本来就带 colo/place，不用再从 engine.Node
		// 拼一遍，v1.7.2 之前这里是把 NodeStat 拆回 engine.Node，机房位置
		// 就在这一步被丢掉，界面永远是「位置未知」。
		nodes = append(make([]config.NodeStat, 0, len(s.cfg.LastIPv6Nodes)), s.cfg.LastIPv6Nodes...)
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
