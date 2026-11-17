// Package web 提供统一的后台服务：状态、配置、测速触发，全部在一个界面里。
//
// 设计取舍：不引入任何 Web 框架，标准库 net/http + 单页原生 JS。
// 好处是镜像里不需要 Node、不需要前端构建链，改界面就是改一个 HTML 文件。
package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/303528084/cf-ddns-sidecar/config"
	"github.com/303528084/cf-ddns-sidecar/ddns"
	"github.com/303528084/cf-ddns-sidecar/dns"
	"github.com/303528084/cf-ddns-sidecar/engine"
)

//go:embed static
var staticFS embed.FS

// version 由 main 注入。
var version = "dev"

// SetVersion 设置版本号（供 /api/status 展示）。
func SetVersion(v string) { version = v }

// Server 是后台服务。
type Server struct {
	configPath string
	enginePath string
	workDir    string
	password   string
	selfURL    string // 本机地址，用于给测速引擎提供本地候选列表

	mu      sync.Mutex
	cfg     *config.Config
	running bool
	logs    []string
	lastErr string

	// 会话令牌签名密钥，由登录密码派生：改密码后旧令牌自动失效。
	secret []byte
}

// New 构造后台服务。selfURL 形如 http://127.0.0.1:8080，供测速引擎拉取候选列表。
//
// 不做来源 IP 限制：局域网、容器网段、甚至从公网反代进来都放行，
// 访问控制完全交给登录密码。
func New(cfg *config.Config, configPath, enginePath, workDir, password, selfURL string) *Server {
	// 密钥派生：不额外存文件，改密码即等于吊销所有旧令牌。
	sum := sha256.Sum256([]byte("cf-ddns-sidecar/session:" + password))
	return &Server{
		configPath: configPath,
		enginePath: enginePath,
		workDir:    workDir,
		password:   password,
		selfURL:    strings.TrimSuffix(selfURL, "/"),
		cfg:        cfg,
		secret:     sum[:],
	}
}

// Handler 返回 HTTP 处理链。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/logout", s.handleLogout)
	mux.HandleFunc("/api/status", s.auth(s.handleStatus))
	mux.HandleFunc("/api/config", s.auth(s.handleConfig))
	mux.HandleFunc("/api/credentials", s.auth(s.handleCredentials))
	mux.HandleFunc("/api/run", s.auth(s.handleRun))

	// 本机候选列表：测速引擎从这里拉「Cloudflare 官方段随机采样」的结果，
	// 所以即使所有外部数据源都不可达，测速依然能跑。
	// 只对本机和已登录用户开放，免得开放网段后被外部随意刷。
	mux.HandleFunc("/api/candidates", s.candidatesGuard)

	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))

	return mux
}

// candidatesGuard 只放行本机（测速引擎拉候选）和已登录用户。
func (s *Server) candidatesGuard(w http.ResponseWriter, r *http.Request) {
	if isLoopback(r.RemoteAddr) || s.hasValidSession(r) {
		s.handleCandidates(w, r)
		return
	}
	http.Error(w, "forbidden", http.StatusForbidden)
}

// isLoopback 判断请求是否来自本机（测速引擎走 127.0.0.1 回调）。
func isLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// handleCandidates 返回候选 IP 列表（每行 ip:port#国家）。
func (s *Server) handleCandidates(w http.ResponseWriter, r *http.Request) {
	count := atoiDefault(r.URL.Query().Get("n"), 600)
	if count > 3000 {
		count = 3000
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(candidateList(count)))
}

// ---------- 认证 ----------
//
// 令牌用 HMAC 签名，服务端不存会话表：
//   1) 容器重启后登录状态不丢（改完配置重启不用再登一次）；
//   2) 签名密钥由密码派生，改密码即等于吊销全部旧令牌。
//
// 令牌有两种携带方式，按顺序取：
//   1) Authorization: Bearer <token>  —— 前端首选
//   2) Cookie: cfddns_session         —— 直连浏览器时的兜底
// 必须支持第 1 种：飞牛把后台嵌在 iframe 里，跨站上下文下浏览器可能
// 根本不保存 Cookie，于是「登录成功 → 下一个请求又 401」，表现为
// 无论输什么密码都提示未登录。

const (
	sessionCookie = "cfddns_session"
	sessionTTL    = 30 * 24 * time.Hour
)

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 正常路径上密码一定非空（main 读不到会现生成一个）。
		// 真走到这里说明连生成都失败了，此时必须拒绝而不是放行——
		// 后台对所有来源 IP 开放，空密码等于谁都能改 DNS 记录。
		if s.password == "" {
			http.Error(w, "后台未设置密码，已锁定。请在「应用设置」里设置管理密码后重启应用", http.StatusServiceUnavailable)
			return
		}
		if !s.hasValidSession(r) {
			http.Error(w, "未登录或登录已过期", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// hasValidSession 判断请求携带的令牌是否有效（header 或 Cookie 二选一）。
func (s *Server) hasValidSession(r *http.Request) bool {
	tok := requestToken(r)
	return tok != "" && s.validToken(tok)
}

// signToken 生成 <过期时间戳>.<签名> 形式的令牌。
func (s *Server) signToken() string {
	exp := strconv.FormatInt(time.Now().Add(sessionTTL).Unix(), 10)
	return exp + "." + s.tokenSig(exp)
}

func (s *Server) tokenSig(payload string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) validToken(tok string) bool {
	exp, sig, ok := strings.Cut(tok, ".")
	if !ok {
		return false
	}
	n, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || time.Now().Unix() > n {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(s.tokenSig(exp)), []byte(sig)) == 1
}

// requestToken 先看 Authorization 头，再退回 Cookie。
func requestToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		return c.Value
	}
	return ""
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "请求格式错误"})
		return
	}
	if s.password == "" {
		writeJSON(w, 503, map[string]string{"error": "后台未设置密码，请先在「应用设置」里设置管理密码"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(body.Password), []byte(s.password)) != 1 {
		time.Sleep(500 * time.Millisecond) // 抬高暴力破解成本
		writeJSON(w, 401, map[string]string{"error": "密码错误，请核对「应用设置」里的登录密码"})
		return
	}
	token := s.signToken()

	// Cookie 仍然设一份，方便直接在浏览器地址栏访问时免登录。
	// 值里有点号，Cookie 允许，无需转义。
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL / time.Second),
	})
	writeJSON(w, 200, map[string]any{"ok": true, "token": token})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// 令牌是无状态的，服务端没法单独吊销；清掉 Cookie 由前端清本地令牌即可。
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// ---------- 状态 ----------

type statusResp struct {
	Version      string   `json:"version"`
	Running      bool     `json:"running"`
	LastIP       string   `json:"last_ip"`
	LastTime     string   `json:"last_time"`
	LastError    string   `json:"last_error"`
	Logs         []string `json:"logs"`
	Domains      []string `json:"domains"`
	DDNSEnabled  bool     `json:"ddns_enabled"`
	DDNSProvider string   `json:"ddns_provider"`
	DDNSDomain   string   `json:"ddns_domain"`
	DDNSMissing  []string `json:"ddns_missing"`
	IntervalMin  int      `json:"interval_minutes"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	cfg := s.cfg.Clone()
	resp := statusResp{
		Version:      version,
		Running:      s.running,
		LastIP:       cfg.LastIP,
		LastTime:     cfg.LastTime,
		LastError:    s.lastErr,
		Logs:         append([]string(nil), s.logs...),
		Domains:      append([]string(nil), cfg.Domains...),
		DDNSEnabled:  cfg.DDNS.Enabled,
		DDNSProvider: cfg.DDNS.Provider,
		DDNSDomain:   cfg.DDNS.Domain,
		IntervalMin:  cfg.Speed.IntervalMinutes,
	}
	s.mu.Unlock()

	if cfg.DDNS.Enabled && cfg.DDNS.Provider != "" {
		resp.DDNSMissing = config.MissingCredentials(cfg.DDNS.Provider)
	}
	writeJSON(w, 200, resp)
}

// ---------- 配置 ----------

type configResp struct {
	AdGuardURL      string   `json:"adguard_url"`
	AdGuardUser     string   `json:"adguard_user"`
	AdGuardPassword string   `json:"adguard_password"`
	HasAdGuardPass  bool     `json:"has_adguard_password"`
	Domains         []string `json:"domains"`
	TopN            int      `json:"top_n"`
	Candidates      int      `json:"bandwidth_candidates"`
	IntervalMinutes int      `json:"interval_minutes"`
	DDNSEnabled     bool     `json:"ddns_enabled"`
	DDNSProvider    string   `json:"ddns_provider"`
	DDNSDomain      string   `json:"ddns_domain"`
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		c := s.cfg.Clone()
		s.mu.Unlock()
		writeJSON(w, 200, configResp{
			AdGuardURL:      c.AdGuard.URL,
			AdGuardUser:     c.AdGuard.Username,
			HasAdGuardPass:  c.AdGuard.Password != "",
			Domains:         c.Domains,
			TopN:            c.Speed.TopN,
			Candidates:      c.Speed.BandwidthCandidates,
			IntervalMinutes: c.Speed.IntervalMinutes,
			DDNSEnabled:     c.DDNS.Enabled,
			DDNSProvider:    c.DDNS.Provider,
			DDNSDomain:      c.DDNS.Domain,
		})
	case http.MethodPost:
		s.saveConfig(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) saveConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AdGuardURL      string   `json:"adguard_url"`
		AdGuardUser     string   `json:"adguard_user"`
		AdGuardPassword string   `json:"adguard_password"`
		Domains         []string `json:"domains"`
		TopN            int      `json:"top_n"`
		Candidates      int      `json:"bandwidth_candidates"`
		IntervalMinutes int      `json:"interval_minutes"`
		DDNSEnabled     bool     `json:"ddns_enabled"`
		DDNSProvider    string   `json:"ddns_provider"`
		DDNSDomain      string   `json:"ddns_domain"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "请求格式错误"})
		return
	}

	s.mu.Lock()
	cfg := s.cfg.Clone()
	cfg.AdGuard.URL = strings.TrimSpace(body.AdGuardURL)
	cfg.AdGuard.Username = strings.TrimSpace(body.AdGuardUser)
	// 密码留空表示「不修改」，避免用户只改域名时把 AdGuard 密码清掉
	if body.AdGuardPassword != "" {
		cfg.AdGuard.Password = body.AdGuardPassword
	}
	cfg.Domains = normalizeDomains(body.Domains)
	if body.TopN > 0 {
		cfg.Speed.TopN = body.TopN
	}
	if body.Candidates > 0 {
		cfg.Speed.BandwidthCandidates = body.Candidates
	}
	cfg.Speed.IntervalMinutes = body.IntervalMinutes
	cfg.DDNS.Enabled = body.DDNSEnabled
	cfg.DDNS.Provider = strings.ToLower(strings.TrimSpace(body.DDNSProvider))
	cfg.DDNS.Domain = config.NormalizeDomain(body.DDNSDomain)

	s.cfg = &cfg
	s.mu.Unlock()

	if err := cfg.Save(); err != nil {
		writeJSON(w, 500, map[string]string{"error": "保存失败: " + friendlyErr(err)})
		return
	}

	// 把「服务商 / 域名 / 间隔」同步回 ddns.env。这个文件是安装向导的入口，
	// 也是用户排查问题时会用文本编辑器打开的地方，不能和后台显示的值打架。
	// 失败只记日志：config.json 已经存好了，功能不受影响。
	if err := config.UpdateEnvFile(config.EnvFilePath(), map[string]string{
		"CFDDNS_PROVIDER":         cfg.DDNS.Provider,
		"CFDDNS_DOMAIN":           cfg.DDNS.Domain,
		"CFDDNS_INTERVAL_MINUTES": strconv.Itoa(cfg.Speed.IntervalMinutes),
	}); err != nil {
		log.Printf("[警告] 回写 ddns.env 失败: %v", err)
	}

	writeJSON(w, 200, map[string]bool{"ok": true})
}

// ---------- DDNS 密钥 ----------

func (s *Server) handleCredentials(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		creds := config.DDNCredentials()
		status := make(map[string]bool)
		for _, group := range []map[string][]string{config.RequiredEnvByProvider, config.OptionalEnvByProvider} {
			for _, names := range group {
				for _, n := range names {
					status[n] = creds[n] != ""
				}
			}
		}
		writeJSON(w, 200, status)

	case http.MethodPost:
		var body map[string]string
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "请求格式错误"})
			return
		}
		existing := config.LoadEnvFile(config.EnvFilePath())
		for k, v := range body {
			v = strings.TrimSpace(v)
			if v == "" {
				continue // 留空表示不修改
			}
			existing[k] = v
		}
		if err := config.SaveEnvFile(config.EnvFilePath(), existing); err != nil {
			writeJSON(w, 500, map[string]string{"error": "保存密钥失败: " + friendlyErr(err)})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---------- 测速 ----------

func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		writeJSON(w, 409, map[string]string{"error": "测速正在进行中"})
		return
	}
	s.running = true
	s.lastErr = ""
	s.logs = nil
	cfg := s.cfg.Clone()
	s.mu.Unlock()

	go func() { _ = s.runOnce(cfg) }()

	writeJSON(w, 200, map[string]bool{"ok": true})
}

// RunOnce 同步执行一次完整流程（供 -once 模式使用）。
func (s *Server) RunOnce() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("测速正在进行中")
	}
	s.running = true
	cfg := s.cfg.Clone()
	s.mu.Unlock()
	return s.runOnce(cfg)
}

func (s *Server) runOnce(cfg config.Config) error {
	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), engine.DefaultTimeout())
	defer cancel()

	s.appendLog("开始测速…")
	res, err := engine.Run(ctx, s.enginePath, s.workDir, engine.Options{
		TopN:                cfg.Speed.TopN,
		BandwidthCandidates: cfg.Speed.BandwidthCandidates,
		CandidatesURL:       s.selfURL + "/api/candidates",
	}, s.appendLog)

	if err != nil {
		msg := friendlyErr(err)
		s.mu.Lock()
		s.lastErr = msg
		s.mu.Unlock()
		s.appendLog("测速失败: " + msg)
		return err
	}

	best := res.Best()
	s.appendLog("测速完成，最优 IP: " + best)
	now := time.Now().Format("2006-01-02 15:04:05")

	// 1) 写入 AdGuard Home 重写表
	if cfg.AdGuard.URL != "" && len(cfg.Domains) > 0 {
		provider, perr := dns.New(cfg.AdGuard.Instance())
		if perr != nil {
			s.appendLog("AdGuard 写入失败: " + perr.Error())
		} else {
			want := make(map[string]map[string]bool, len(cfg.Domains))
			for _, d := range cfg.Domains {
				want[d] = map[string]bool{best: true}
			}
			stats, werr := provider.ReplaceRewrites(want)
			if werr != nil {
				s.appendLog("写入 AdGuard 失败: " + werr.Error())
			} else {
				s.appendLog(fmt.Sprintf("已写入 AdGuard：%d 条重写（%d 个域名）", stats.Written, len(cfg.Domains)))
			}
		}
	} else if cfg.AdGuard.URL == "" {
		s.appendLog("未配置 AdGuard Home，跳过写入")
	}

	// 2) 推送域名解析（DDNS）
	if cfg.DDNS.Enabled && cfg.DDNS.Provider != "" && cfg.DDNS.Domain != "" {
		missing := config.MissingCredentials(cfg.DDNS.Provider)
		if len(missing) > 0 {
			s.appendLog("域名解析未推送：缺少密钥 " + strings.Join(missing, ", "))
		} else {
			creds := config.DDNCredentials()
			p, derr := ddns.New(cfg.DDNS.Provider, cfg.DDNS.Domain, creds)
			if derr != nil {
				s.appendLog("域名解析配置有误: " + derr.Error())
			} else if derr := p.EnsureARecord(cfg.DDNS.Domain, best); derr != nil {
				s.appendLog("域名解析推送失败: " + derr.Error())
			} else {
				s.appendLog(fmt.Sprintf("域名解析已更新：%s → %s", cfg.DDNS.Domain, best))
			}
		}
	}

	// 3) 记录结果
	s.mu.Lock()
	s.cfg.LastIP = best
	s.cfg.LastTime = now
	toSave := s.cfg.Clone()
	s.mu.Unlock()

	if err := toSave.Save(); err != nil {
		log.Printf("保存配置失败: %v", err)
	}
	return nil
}

// StartScheduler 启动定时测速。
func (s *Server) StartScheduler() {
	go func() {
		for {
			s.mu.Lock()
			interval := s.cfg.Speed.IntervalMinutes
			s.mu.Unlock()

			if interval <= 0 {
				time.Sleep(time.Minute)
				continue
			}
			time.Sleep(time.Duration(interval) * time.Minute)

			s.mu.Lock()
			busy := s.running
			cfg := s.cfg.Clone()
			if !busy {
				s.running = true
			}
			s.mu.Unlock()
			if busy {
				continue
			}
			_ = s.runOnce(cfg)
		}
	}()
}

func (s *Server) appendLog(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs = append(s.logs, line)
	if len(s.logs) > 300 {
		s.logs = s.logs[len(s.logs)-300:]
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "ok", "version": version})
}

// ---------- 工具 ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// normalizeDomains 去重、去协议前缀、小写、丢弃非法项。
func normalizeDomains(in []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(in))
	for _, d := range in {
		d = strings.TrimSpace(strings.ToLower(d))
		d = strings.TrimPrefix(d, "http://")
		d = strings.TrimPrefix(d, "https://")
		d = strings.TrimSuffix(d, "/")
		d = strings.TrimSuffix(d, ".")
		if d == "" || !strings.Contains(d, ".") || strings.ContainsAny(d, " /:") {
			continue
		}
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// friendlyErr 把底层 OS 错误翻译成用户能看懂、能动手处理的话。
// 界面是给不懂技术的人看的，直接抛 "permission denied" 等于没说。
func friendlyErr(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "permission denied"):
		return "数据目录不可写。请在「应用中心」把本应用重启一次；若仍然失败，" +
			"说明数据目录被挂载成了只读（检查 compose 里 volumes 是否带 :ro）"
	case strings.Contains(msg, "no space left"):
		return "NAS 磁盘空间不足，请清理后重试"
	case strings.Contains(msg, "read-only file system"):
		return "数据目录是只读的，请检查挂载配置"
	}
	return msg
}

// RandomPassword 生成随机登录密码。
func RandomPassword() (string, error) {
	b := make([]byte, 9)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
