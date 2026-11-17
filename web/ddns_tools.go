package web

// 后台里「配好了吗」这类小工具：测试域名解析的密钥、手动推送一次解析、
// 以及把 AdGuard 里现有的重写表读出来看看。
//
// 为什么值得单独做：用户填密钥的时候完全不知道自己填对没有——以前只能等
// 下一个测速周期（默认 60 分钟）看日志里有没有报错，或者干脆等到域名解析
// 失效才发现。2026-11-17 那天他就是卡在「密钥到底对不对」上。
// 现在按一下就能当场得到答案，而且「测试密钥」只读，不会动线上解析。

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/303528084/cf-ddns-sidecar/config"
	"github.com/303528084/cf-ddns-sidecar/ddns"
	"github.com/303528084/cf-ddns-sidecar/dns"
)

// currentDDNS 取出当前 DDNS 配置并造好服务商客户端。
// 不可用时 provider 为 nil，msg 是一句能直接显示给用户看的话。
func (s *Server) currentDDNS() (ddns.Provider, config.Config, string) {
	s.mu.Lock()
	cfg := s.cfg.Clone()
	s.mu.Unlock()

	if !cfg.DDNS.Enabled {
		return nil, cfg, "域名解析还没启用：先在上面的「启用」打勾并保存一次"
	}
	if cfg.DDNS.Provider == "" || cfg.DDNS.Domain == "" {
		return nil, cfg, "还没选服务商或没填优选域名"
	}
	if missing := config.MissingCredentials(cfg.DDNS.Provider); len(missing) > 0 {
		return nil, cfg, "缺少密钥：" + strings.Join(missing, "、")
	}
	p, err := ddns.New(cfg.DDNS.Provider, cfg.DDNS.Domain, config.DDNCredentials())
	if err != nil {
		return nil, cfg, err.Error()
	}
	return p, cfg, ""
}

// handleDDNSCheck 只读校验密钥：确认能用、能查到这条域名，并报出当前指向。
func (s *Server) handleDDNSCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p, cfg, msg := s.currentDDNS()
	if p == nil {
		writeJSON(w, 400, map[string]string{"error": msg})
		return
	}

	state, err := p.Verify(cfg.DDNS.Domain)
	if err != nil {
		s.appendLog("测试域名解析密钥失败: " + err.Error())
		writeJSON(w, 502, map[string]string{"error": ddnsHint(err)})
		return
	}

	s.mu.Lock()
	bestIP := s.cfg.LastIP
	s.mu.Unlock()

	if state.Found {
		s.appendLog(fmt.Sprintf("域名解析密钥可用：%s 现在指向 %s", cfg.DDNS.Domain, state.CurrentIP))
	} else {
		s.appendLog(fmt.Sprintf("域名解析密钥可用：%s 还没有 A 记录，下次成功后会创建", cfg.DDNS.Domain))
	}
	writeJSON(w, 200, map[string]any{
		"ok":         true,
		"provider":   cfg.DDNS.Provider,
		"domain":     cfg.DDNS.Domain,
		"found":      state.Found,
		"current_ip": state.CurrentIP,
		"best_ip":    bestIP,
	})
}

// handleDDNSUpdate 立刻把当前最优 IP 推一次，不用等下一个测速周期。
func (s *Server) handleDDNSUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p, cfg, msg := s.currentDDNS()
	if p == nil {
		writeJSON(w, 400, map[string]string{"error": msg})
		return
	}

	s.mu.Lock()
	ip := s.cfg.LastIP
	busy := s.running
	s.mu.Unlock()

	if ip == "" {
		writeJSON(w, 400, map[string]string{
			"error": "还没有测出最优 IP。先点「立即测速」；只想验证密钥对不对，用「测试密钥」就够了",
		})
		return
	}
	// 测速进行中不推：那一轮自己会推，两边同时写同一条记录只会打架。
	if busy {
		writeJSON(w, 409, map[string]string{"error": "测速正在进行中，它结束后会自己推送；请稍后再试"})
		return
	}

	if err := p.EnsureARecord(cfg.DDNS.Domain, ip); err != nil {
		s.appendLog("手动推送域名解析失败: " + err.Error())
		writeJSON(w, 502, map[string]string{"error": ddnsHint(err)})
		return
	}

	s.appendLog(fmt.Sprintf("域名解析已手动更新：%s → %s", cfg.DDNS.Domain, ip))
	writeJSON(w, 200, map[string]any{"ok": true, "domain": cfg.DDNS.Domain, "ip": ip})
}

// handleAdguardRewrites 把 AdGuard 里现在的重写表读出来，并标出「下次测速会被清掉」
// 的那些——ReplaceRewrites 会清空整张表再重建，用户有权先看一眼。
func (s *Server) handleAdguardRewrites(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.mu.Lock()
	cfg := s.cfg.Clone()
	s.mu.Unlock()

	if strings.TrimSpace(cfg.AdGuard.URL) == "" {
		writeJSON(w, 400, map[string]string{"error": "还没填 AdGuard 地址"})
		return
	}
	provider, err := dns.New(cfg.AdGuard.Instance())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": friendlyErr(err)})
		return
	}

	entries, err := provider.ListRewrites()
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": friendlyErr(err)})
		return
	}

	// 期望集合：每个要加速的域名 → 当前最优 IP。LastIP 为空时为空表，
	// 界面上就会把所有现存的都标成「下次测速会被清掉」，这恰好是实话。
	expected := make(map[string]string, len(cfg.Domains))
	if cfg.LastIP != "" {
		for _, d := range cfg.Domains {
			expected[d] = cfg.LastIP
		}
	}
	writeJSON(w, 200, map[string]any{
		"ok":       true,
		"entries":  entries,
		"expected": expected,
		"last_ip":  cfg.LastIP,
	})
}

// ddnsHint 在服务商返回的原始错误后面补一句「大概是什么问题」。
//
// 原始信息里有 HTTP 状态码和云厂商的错误码，对排查有价值，所以不替换掉，
// 只在后面加一句人话。
func ddnsHint(err error) string {
	msg := err.Error()
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(msg, "401"), strings.Contains(msg, "403"),
		strings.Contains(low, "unauthorized"), strings.Contains(low, "invalidaccesskey"),
		strings.Contains(low, "authfailure"), strings.Contains(low, "invalid api key"),
		strings.Contains(low, "signature"):
		return msg + "（看着像密钥不对或没有改解析的权限）"
	case strings.Contains(low, "timeout"), strings.Contains(low, "no such host"),
		strings.Contains(low, "connection refused"), strings.Contains(low, "eof"):
		return msg + "（连不上服务商，检查 NAS 的外网出口）"
	}
	return msg
}
