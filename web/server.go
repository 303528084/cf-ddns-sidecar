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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/303528084/cf-ddns-sidecar/applog"
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

// Auth 描述后台登录密码从哪里取。
//
// 关键设计：密码是**每次请求现读**的，不是启动时读一次就定死。
// 原因：飞牛的安装/应用设置脚本（cmd/install_callback、cmd/config_callback）
// 会改写 dashboard-password，但那些脚本以 run-as: package 运行，没有权限
// 操作 docker，`docker restart` 常常失败。如果密码在启动时固化，
// 用户在安装向导里设的密码就永远不生效——现象正是「设了密码还是登不上，
// 只有日志里那个自动生成的密码能进」。
//
// 现读现比之后：脚本写文件即生效，不需要重启容器。
type Auth struct {
	// Env 是 DSA_PASSWORD 环境变量，优先级最高（手工部署时用）。
	Env string
	// File 是 dashboard-password 路径，每次校验都重读，让改密码即时生效。
	File string
	// Fallback 是启动时生成/读到的密码。文件被删或暂时不可读时仍能登录，
	// 避免「改密码改到一半时谁也进不去」。
	Fallback string
}

// Current 返回当前应当生效的密码。
func (a Auth) Current() string {
	if v := strings.TrimSpace(a.Env); v != "" {
		return v
	}
	if a.File != "" {
		if b, err := os.ReadFile(a.File); err == nil {
			if v := strings.TrimSpace(string(b)); v != "" {
				return v
			}
		}
	}
	return a.Fallback
}

// Server 是后台服务。
type Server struct {
	configPath string
	enginePath string
	workDir    string
	pass       Auth
	selfURL    string // 本机地址，用于给测速引擎提供本地候选列表
	throttle   *loginThrottle
	logFile    *applog.Log // 落盘的运行日志（可为 nil，表示只在内存里记）

	mu      sync.Mutex
	cfg     *config.Config
	running bool
	logs    []string
	lastErr string
	// 定时器状态：下一次什么时候跑、上一次成没成、连续失败几次。
	// 以前后台只能看到「上次测速时间」，看不出「它到底还活着吗、还是每小时
	// 都在失败」——这两样才是判断「要不要管它」的依据。
	nextRunAt time.Time
	lastOK    bool
	failCount int
	// restored 表示这次启动时 config.json 不见了、是从 .bak 恢复的。
	// 单独存一份而不是每次去读 cfg.RestoredFromBackup：cfg 会被 Clone 和
	// 覆盖，标志容易在某个保存路径上被顺手清掉，而这个提示一旦消失，
	// 用户就又回到「一切正常，只是全空了」的假象里。
	restored bool

	// restoredUpgrade / restoredSource 是「从升级前自动备份恢复」这一种的明细：
	// 那种情况连 config.json.bak 都没了（整个数据目录被删），红条要说清
	// 「是从哪儿捡回来的」，否则用户没法判断要不要去翻别的备份。
	restoredUpgrade bool
	restoredSource  string

	// schedWake 用来把「正睡着的定时器」叫醒。
	// 没有它的话，用户把间隔从 60 分钟改成 10 分钟，调度器还按旧的 60 分钟
	// 睡在那儿，界面上「下次测速」也要等它醒过来才更新——最长能差一小时。
	schedWake chan struct{}
}

// New 构造后台服务。selfURL 形如 http://127.0.0.1:8080，供测速引擎拉取候选列表。
// logFile 可为 nil（日志就只留在内存，重启即清空）。
//
// 不做来源 IP 限制：局域网、容器网段、甚至从公网反代进来都放行，
// 访问控制交给「登录密码 + 登录失败限流」（见 guard.go）。
func New(cfg *config.Config, configPath, enginePath, workDir string, auth Auth, selfURL string, logFile *applog.Log) *Server {
	s := &Server{
		configPath: configPath,
		enginePath: enginePath,
		workDir:    workDir,
		pass:       auth,
		selfURL:    strings.TrimSuffix(selfURL, "/"),
		throttle:   newLoginThrottle(),
		logFile:    logFile,
		cfg:        cfg,
		restored:   cfg.RestoredFromBackup,
		schedWake:  make(chan struct{}, 1),
	}
	if cfg.RestoredFromUpgradeBackup {
		s.restoredUpgrade = true
		s.restoredSource = config.RestoreMarkerSource()
	}
	// 把上次（重启前）的日志尾巴回填到界面。用户反映「重启后日志一片空白，
	// 出事那段根本看不到」，这就是那一段。
	if logFile != nil {
		if tail := logFile.Tail(100); len(tail) > 0 {
			s.logs = tail
		}
	}
	return s
}

// signingKey 由当前密码派生出令牌签名密钥。
//
// 每次都按当前密码现算，所以改密码等于立刻吊销所有旧令牌，
// 不需要额外存密钥、也不需要在内存里维护「当前密钥」。
func (s *Server) signingKey() []byte {
	sum := sha256.Sum256([]byte("cf-ddns-sidecar/session:" + s.pass.Current()))
	return sum[:]
}

// Handler 返回 HTTP 处理链。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/logout", s.handleLogout)
	mux.HandleFunc("/api/status", s.auth(s.handleStatus))
	mux.HandleFunc("/api/config", s.auth(s.handleConfig))
	mux.HandleFunc("/api/config/export", s.auth(s.handleExport))
	mux.HandleFunc("/api/config/import", s.auth(s.handleImport))
	mux.HandleFunc("/api/credentials", s.auth(s.handleCredentials))
	mux.HandleFunc("/api/password", s.auth(s.handlePassword))
	mux.HandleFunc("/api/ddns/check", s.auth(s.handleDDNSCheck))
	mux.HandleFunc("/api/ddns/update", s.auth(s.handleDDNSUpdate))
	mux.HandleFunc("/api/adguard/rewrites", s.auth(s.handleAdguardRewrites))
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

	// 安全头包在最外层：静态页、API、错误响应都要带上。
	return securityHeaders(mux)
}

// candidatesGuard 只放行真正的进程内调用（测速引擎拉候选）和已登录用户。
//
// 注意这里用的是 isLocalRequest 而不是「RemoteAddr 是不是 127.0.0.1」：
// 加了反代或 Cloudflare Tunnel 之后，所有公网请求的 RemoteAddr 也会是
// 127.0.0.1，只判 IP 等于把这个接口对全网敞开。见 guard.go 的说明。
func (s *Server) candidatesGuard(w http.ResponseWriter, r *http.Request) {
	if isLocalRequest(r) || s.hasValidSession(r) {
		s.handleCandidates(w, r)
		return
	}
	http.Error(w, "forbidden", http.StatusForbidden)
}

// handleCandidates 返回候选 IP 列表（每行 ip:port#国家）。
//
// 内容由用户配置决定：没设自定义来源 → 内置官方段；设了段/单 IP → 只从那里采样；
// 只设了链接 → 返回空（候选全交给引擎自己拉）。详见 candidateList 的注释。
func (s *Server) handleCandidates(w http.ResponseWriter, r *http.Request) {
	count := atoiDefault(r.URL.Query().Get("n"), 600)
	if count > 3000 {
		count = 3000
	}
	s.mu.Lock()
	c := s.cfg.Clone()
	s.mu.Unlock()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(candidateList(&c, count)))
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
		if s.pass.Current() == "" {
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
	mac := hmac.New(sha256.New, s.signingKey())
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

	// 先看这个来源是不是已经在「罚站」。放在解析 body 之前：被锁的人连尝试
	// 的机会都没有，也省得被灌数据。
	ip := clientIP(r)
	if ok, wait := s.throttle.allow(ip); !ok {
		writeTooManyAttempts(w, wait)
		return
	}

	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "请求格式错误"})
		return
	}
	if s.pass.Current() == "" {
		writeJSON(w, 503, map[string]string{"error": "后台未设置密码，请先在「应用设置」里设置管理密码"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(body.Password), []byte(s.pass.Current())) != 1 {
		s.throttle.fail(ip)
		time.Sleep(loginFailDelay) // 抬高单路爆破成本；并发的那些靠上面的限流兜住
		writeJSON(w, 401, map[string]string{"error": "密码错误，请核对「应用设置」里的登录密码"})
		return
	}
	s.throttle.reset(ip)
	token := s.signToken()
	s.setSessionCookie(w, r, token)
	writeJSON(w, 200, map[string]any{"ok": true, "token": token})
}

// setSessionCookie 下发会话 Cookie，方便直接在浏览器地址栏访问时免登录。
// 值里有点号，Cookie 允许，无需转义。
//
// Secure 只在 HTTPS 下加：HTTP 下打了这个标记浏览器会直接丢弃 Cookie，
// 表现为「登录成功但下一个请求又 401」——这正是最早那版「怎么输密码都进不去」的原因。
func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL / time.Second),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// 令牌是无状态的，服务端没法单独吊销；清掉 Cookie 由前端清本地令牌即可。
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// handlePassword 修改后台登录密码。
//
// 为什么要在后台自己做一个改密码入口，而不是只靠飞牛的「应用设置」：
//   - 应用设置里那个密码框没有任何校验，填 123456 也能保存成功；
//   - 改完要回桌面重开页面，用户没法当场确认「到底生效没有」。
//
// 这里当场校验强度、当场原子写入文件、当场换发登录令牌，改完立刻可验证。
func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// 密码来自环境变量时文件不起作用，写进去只会让人以为改成功了。
	if strings.TrimSpace(s.pass.Env) != "" {
		writeJSON(w, 400, map[string]string{
			"error": "登录密码由环境变量 DSA_PASSWORD 指定，这里改不了；请改环境变量后重启应用",
		})
		return
	}
	if s.pass.File == "" {
		writeJSON(w, 500, map[string]string{"error": "密码文件路径未知，无法保存"})
		return
	}

	var body struct {
		Old string `json:"old_password"`
		New string `json:"new_password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "请求格式错误"})
		return
	}

	// 改密码也要走同一套限流：否则这里就成了一个不需要本机位置、
	// 可以慢慢试当前密码的入口。
	ip := clientIP(r)
	if ok, wait := s.throttle.allow(ip); !ok {
		writeTooManyAttempts(w, wait)
		return
	}
	if subtle.ConstantTimeCompare([]byte(body.Old), []byte(s.pass.Current())) != 1 {
		s.throttle.fail(ip)
		time.Sleep(loginFailDelay)
		writeJSON(w, 401, map[string]string{"error": "当前密码不对"})
		return
	}
	s.throttle.reset(ip)

	if reason := WeakPasswordReason(body.New); reason != "" {
		writeJSON(w, 400, map[string]string{"error": "新密码" + reason})
		return
	}
	if subtle.ConstantTimeCompare([]byte(body.New), []byte(s.pass.Current())) == 1 {
		writeJSON(w, 400, map[string]string{"error": "新密码和当前密码一样，没有改动"})
		return
	}
	if err := writePasswordFile(s.pass.File, body.New); err != nil {
		writeJSON(w, 500, map[string]string{"error": "保存密码失败: " + friendlyErr(err)})
		return
	}

	// 令牌签名密钥由密码派生，改完密码旧令牌全部失效。这里直接换发一个新的，
	// 免得用户改完密码把自己踢下线、还要再登一次。
	token := s.signToken()
	s.setSessionCookie(w, r, token)
	log.Printf("[信息] 后台登录密码已修改")
	writeJSON(w, 200, map[string]any{"ok": true, "token": token})
}

// writePasswordFile 原子写入密码文件：先写同目录临时文件再改名。
//
// 必须原子：程序每次登录都现读这个文件，直接覆盖会出现「读到写了一半的
// 密码」的瞬间，那一瞬的登录必然失败，用户会以为密码设错了。
func writePasswordFile(path, pw string) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".dashboard-password-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)

	if _, err := tmp.WriteString(pw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// 0644 与生命周期脚本写出的权限保持一致：程序以另一个用户身份也可能要读它。
	if err := os.Chmod(name, 0o644); err != nil {
		return err
	}
	return os.Rename(name, path)
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

	// 下面两个是「必须让用户看见」的状态：配置是从备份恢复的。
	// 以前这只进运行日志，而运行日志在卡片最下面、还要往下滚，等于没提示。
	//
	// 注意：这里曾经还有一个 password_weak / password_reason，用来在页面顶上挂
	// 「登录密码太短了」的黄条。2026-11-17 按用户要求删掉了——他从安装向导里设的
	// 就是 6 位，不想每次开页面都被提醒一次。弱密码校验现在只在「主动改密码」
	// 那一刻做（见 handleSetPassword），不再有常驻提示。
	RestoredConfig bool `json:"restored_config"`
	// 恢复的两种来路，界面据此决定说哪句话（见 index.html 的 renderBanners）：
	//   restored_upgrade=false → 只是 config.json 丢了，config.json.bak 顶上；
	//   restored_upgrade=true  → 整个数据目录被删过，连 .bak 都没了，
	//                            靠升级前搬到外面的那份救回来，来源在 restored_source。
	RestoredUpgrade bool   `json:"restored_upgrade"`
	RestoredSource  string `json:"restored_source"`
	LogFile         string `json:"log_file"`

	// 定时器状态：下次几点跑、上次成没成、连续失败几次。
	NextRunAt string `json:"next_run_at"`
	LastOK    bool   `json:"last_ok"`
	FailCount int    `json:"fail_count"`

	// 上次测速排好序的完整 IP 列表。界面用它显示「已写入前 N 条」，
	// 也让用户在改条数之前就能看到有哪些备选。
	LastIPs []string `json:"last_ips"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	cfg := s.cfg.Clone()
	resp := statusResp{
		Version:         version,
		Running:         s.running,
		LastIP:          cfg.LastIP,
		LastTime:        cfg.LastTime,
		LastError:       s.lastErr,
		Logs:            append([]string(nil), s.logs...),
		Domains:         append([]string(nil), cfg.Domains...),
		DDNSEnabled:     cfg.DDNS.Enabled,
		DDNSProvider:    cfg.DDNS.Provider,
		DDNSDomain:      cfg.DDNS.Domain,
		IntervalMin:     cfg.Speed.IntervalMinutes,
		RestoredConfig:  s.restored,
		RestoredUpgrade: s.restoredUpgrade,
		RestoredSource:  s.restoredSource,
		NextRunAt:       formatRunTime(s.nextRunAt),
		LastOK:          s.lastOK,
		FailCount:       s.failCount,
		LastIPs:         append([]string{}, cfg.LastIPs...),
	}
	s.mu.Unlock()

	if cfg.DDNS.Enabled && cfg.DDNS.Provider != "" {
		resp.DDNSMissing = config.MissingCredentials(cfg.DDNS.Provider)
	}
	if s.logFile != nil {
		resp.LogFile = "app.log"
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
	ExtraSources    []string `json:"extra_sources"`
	DDNSEnabled     bool     `json:"ddns_enabled"`
	DDNSProvider    string   `json:"ddns_provider"`
	DDNSDomain      string   `json:"ddns_domain"`
	DDNSTTL         int      `json:"ddns_ttl"`
	DDNSProxied     bool     `json:"ddns_proxied"`
	DDNSIPCount     int      `json:"ddns_ip_count"`
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
			ExtraSources:    c.Speed.ExtraSources,
			DDNSEnabled:     c.DDNS.Enabled,
			DDNSProvider:    c.DDNS.Provider,
			DDNSDomain:      c.DDNS.Domain,
			DDNSTTL:         c.DDNS.TTL,
			DDNSProxied:     c.DDNS.Proxied,
			DDNSIPCount:     c.DDNS.EffectiveIPCount(),
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
		// 用指针是为了区分「没传这个字段」和「传了空数组」：
		//   没传（nil）  → 保持原值，不动用户已设的段（老的导入文件、旧客户端）；
		//   传了 []      → 用户主动清空，恢复用内置官方段。
		// 若用普通切片，这两种情况都是长度 0，清空就永远生效不了。
		ExtraSources    *[]string `json:"extra_sources"`
		DDNSEnabled     bool      `json:"ddns_enabled"`
		DDNSProvider    string    `json:"ddns_provider"`
		DDNSDomain      string    `json:"ddns_domain"`
		DDNSTTL         int       `json:"ddns_ttl"`
		DDNSProxied     bool      `json:"ddns_proxied"`
		DDNSIPCount     int       `json:"ddns_ip_count"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "请求格式错误"})
		return
	}
	// TTL 只挡明显填错的：各家上限并不一样（阿里云最大 86400，DNSPod 免费版
	// 最小 600），更细的边界让服务商自己报错更准确，别在这儿瞎猜。
	if body.DDNSTTL != 0 && (body.DDNSTTL < 60 || body.DDNSTTL > 86400) {
		writeJSON(w, 400, map[string]string{
			"error": "TTL 请填 0（用各服务商默认）或 60 到 86400 之间的秒数，常见的是 600 或 3600",
		})
		return
	}
	// 条数上限给 20：再多 DNS 响应就太长了，而且每条都会摊薄「优选」的效果。
	// 0 表示「没填/用默认」，按 1 条处理——老界面和老的备份文件里没有这个字段，
	// 一上来就要求 1..20 会把它们全部判成非法。
	if body.DDNSIPCount < 0 || body.DDNSIPCount > 20 {
		writeJSON(w, 400, map[string]string{
			"error": "「同步几条 IP」请填 1 到 20 之间的整数",
		})
		return
	}

	// 「优选 IP 段」逐行校验，错一行就整单退回并指明第几行。
	// 校验放在锁外面：它只依赖请求体，没必要占着 s.mu。
	var extraLines []string
	if body.ExtraSources != nil {
		extraLines = make([]string, 0, len(*body.ExtraSources))
		for _, l := range *body.ExtraSources {
			if t := strings.TrimSpace(l); t != "" {
				extraLines = append(extraLines, t)
			}
		}
		if _, err := parseExtraSources(extraLines); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
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
	// body.ExtraSources 为 nil 表示请求里没带这个字段（旧客户端/老导入文件），
	// 此时保留原值，不能顺手清空——那会把用户辛苦填的段默默删掉。
	if body.ExtraSources != nil {
		cfg.Speed.ExtraSources = extraLines
	}
	cfg.DDNS.Enabled = body.DDNSEnabled
	cfg.DDNS.Provider = strings.ToLower(strings.TrimSpace(body.DDNSProvider))
	cfg.DDNS.Domain = config.NormalizeDomain(body.DDNSDomain)
	cfg.DDNS.TTL = body.DDNSTTL
	cfg.DDNS.Proxied = body.DDNSProxied
	cfg.DDNS.IPCount = body.DDNSIPCount

	s.cfg = &cfg
	s.mu.Unlock()

	if err := cfg.Save(); err != nil {
		writeJSON(w, 500, map[string]string{"error": "保存失败: " + friendlyErr(err)})
		return
	}

	// 用户主动保存过一次 = 已经看过并确认了恢复出来的内容，那条红条可以撤了。
	// 只在这里清，不在定时测速顺手保存时清——那种保存不是「人看过了」。
	s.mu.Lock()
	s.restored = false
	s.restoredUpgrade = false
	s.restoredSource = ""
	s.mu.Unlock()
	// 落盘的标记也要一起清。否则下次重启改从 .bak 那条路走，红条又冒出来一次，
	// 用户会以为自己刚才那次保存没生效（这一条只有真的从备份恢复过才有文件）。
	config.ClearRestoreMarker()

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

	// 间隔可能变了，把睡着的定时器叫醒重算，否则「下次测速」要等旧的
	// 周期走完才更新（最长能差一小时）。
	s.wakeScheduler()

	// 开了云朵这件事必须留在日志里。以后用户看到「域名解析的 IP 不是最优 IP」
	// 时，日志里这一行能直接解释原因——是 Cloudflare 接手了，不是推送错了。
	if cfg.DDNS.Proxied && cfg.DDNS.Provider == "cloudflare" {
		s.appendLog("注意：Cloudflare 云朵（代理）已开启，域名会解析到 Cloudflare 的边缘节点，不再直接指向优选 IP")
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
	cfg := s.cfg.Clone()
	s.mu.Unlock()

	// 以前这里是 s.logs = nil，每点一次「立即测速」就把之前的记录全抹掉，
	// 出事时想回看上一轮发生了什么已经没有了。改成插一行分隔。
	s.appendLog("—— 手动触发的测速 ——")

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

// retryDelay 是测速失败后自动重试的等待时间。抽成变量是为了测试能改成 0。
var retryDelay = 10 * time.Second

// waitFor 等一段时间；ctx 提前结束就返回 false。
func waitFor(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// formatRunTime 把「下次测速时间」变成界面上好看的样子：
// 今天只显示时分，跨天带上月日，没有定时就留空（前端显示「未开启」）。
func formatRunTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	if t.Format("2006-01-02") == time.Now().Format("2006-01-02") {
		return t.Format("15:04")
	}
	return t.Format("01-02 15:04")
}

// delayText 把等待时长说成人话，直接拼进日志句子（「10 秒后自动重试一次」）。
// 超过一分钟就不用秒了，因为没人愿意读「90 秒后」。
func delayText(d time.Duration) string {
	switch {
	case d <= 0:
		return "马上"
	case d < time.Minute:
		return fmt.Sprintf("%d 秒后", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟后", int(d.Minutes()))
	default:
		return fmt.Sprintf("%d 小时后", int(d.Hours()))
	}
}

func (s *Server) runOnce(cfg config.Config) error {
	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), engine.DefaultTimeout())
	defer cancel()

	// 「优选 IP 段」：把用户填的来源分成两类走不同路径 ——
	//   · IP 段 / 单 IP 由本机的 /api/candidates 提供（见 candidateList）；
	//   · 链接直接交给引擎自己去拉，我们不管它的格式。
	// custom 为 false 表示用户没设置，完全走升级前的老行为。
	extra, _ := parseExtraSources(cfg.Speed.ExtraSources)
	custom := len(cfg.Speed.ExtraSources) > 0

	// 本地候选列表的地址。用户只填了链接时本地一条候选都不出，这时就
	// **不要**把这个地址交给引擎——否则它会去拉一个空列表，日志里留一行
	// 「数据源解析完成（0 节点）」。用户看到「0 节点」会以为地址又失效了，
	// 而这一次是他自己没填段，属于「日志把人带沟里」。
	localCandidates := s.selfURL + "/api/candidates"
	if custom && len(extra.cidrs) == 0 && len(extra.ips) == 0 {
		localCandidates = ""
	}

	run := func() (*engine.Result, error) {
		return engine.Run(ctx, s.enginePath, s.workDir, engine.Options{
			TopN:                cfg.Speed.TopN,
			BandwidthCandidates: cfg.Speed.BandwidthCandidates,
			CandidatesURL:       localCandidates,
			ExtraURLs:           extra.urls,
			UseBuiltinSources:   !custom,
		}, s.appendLog)
	}

	s.appendLog("开始测速…")
	// 这一行是给用户看的「为什么会测出这些 IP」：以前候选来源是写死的，
	// 现在能改，就必须说清楚这一轮到底用了谁的来源，否则出了问题无从判断。
	if custom {
		msg := fmt.Sprintf(
			"候选来源：按后台设置的自定义来源（IP 段 %d 个、单个 IP %d 个、链接 %d 个），不叠加内置聚合源",
			len(extra.cidrs), len(extra.ips), len(extra.urls))
		if len(extra.cidrs) == 0 && len(extra.ips) == 0 {
			msg += "；本地不出候选，全部由引擎从你填的链接里拉"
		}
		s.appendLog(msg)
	}
	res, err := run()

	// 失败自动重试一次。cfnb 的失败大多是「某个数据源或节点刚好超时」这类
	// 偶发问题，重试一次往往就过了。以前碰到只能干等下一个周期（默认 60
	// 分钟），等于白丢一轮。ctx 已经耗尽时不重试——那说明是真跑满了超时。
	if err != nil && ctx.Err() == nil {
		s.appendLog("测速失败: " + friendlyErr(err) + "；" + delayText(retryDelay) + "后自动重试一次")
		if waitFor(ctx, retryDelay) {
			s.appendLog("开始重试…")
			res, err = run()
		}
	}

	if err != nil {
		msg := friendlyErr(err)
		s.mu.Lock()
		s.lastErr = msg
		s.lastOK = false
		s.failCount++
		s.mu.Unlock()
		s.appendLog("测速失败: " + msg)
		return err
	}

	s.mu.Lock()
	s.lastErr = ""
	s.lastOK = true
	s.failCount = 0
	s.mu.Unlock()

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
	//
	// 写几条由用户设定（默认 1 条）。注意 pushIPs 是「按排名截前 N」，
	// 而 cfg.LastIPs 存的是**完整排名**——这样用户之后把条数从 1 改成 5，
	// 点一下「立即更新一次」就能补齐，不用重新跑一次测速。
	pushIPs := pickIPs(res.IPs, cfg.DDNS.EffectiveIPCount())
	if len(pushIPs) == 0 {
		// 走到这里说明这一轮没留下任何可用 IP。绝不能拿空列表去「对齐」——
		// ddns 包会把它当成「这次没结果，别动」，但日志里得如实说一句。
		s.appendLog("域名解析未推送：本次没有可用的 IP")
	} else if cfg.DDNS.Enabled && cfg.DDNS.Provider != "" && cfg.DDNS.Domain != "" {
		missing := config.MissingCredentials(cfg.DDNS.Provider)
		if len(missing) > 0 {
			s.appendLog("域名解析未推送：缺少密钥 " + strings.Join(missing, ", "))
		} else {
			creds := config.DDNCredentials()
			p, derr := ddns.New(cfg.DDNS.Provider, cfg.DDNS.Domain, creds)
			if derr != nil {
				s.appendLog("域名解析配置有误: " + derr.Error())
			} else if derr := p.EnsureARecords(cfg.DDNS.Domain, pushIPs, recordOptions(cfg.DDNS)); derr != nil {
				s.appendLog("域名解析推送失败: " + derr.Error())
			} else {
				s.appendLog(fmt.Sprintf("域名解析已更新：%s → %s（共 %d 条）",
					cfg.DDNS.Domain, strings.Join(pushIPs, "、"), len(pushIPs)))
			}
		}
	}

	// 3) 记录结果
	s.mu.Lock()
	s.cfg.LastIP = best
	s.cfg.LastIPs = append(make([]string, 0, len(res.IPs)), res.IPs...)
	s.cfg.LastTime = now
	toSave := s.cfg.Clone()
	s.mu.Unlock()

	if err := toSave.Save(); err != nil {
		log.Printf("保存配置失败: %v", err)
	}
	return nil
}

// StartScheduler 启动定时测速。
//
// nextRunAt 在这里算并暴露给界面。算的是「真的要跑的时刻」，不是「间隔」——
// 用户看到「下次 16:35」就是他该等的那个点，不会因为改过间隔而说一套做一套。
func (s *Server) StartScheduler() {
	go func() {
		for {
			s.mu.Lock()
			interval := s.cfg.Speed.IntervalMinutes
			if interval <= 0 {
				s.nextRunAt = time.Time{}
			} else {
				s.nextRunAt = time.Now().Add(time.Duration(interval) * time.Minute)
			}
			next := s.nextRunAt
			s.mu.Unlock()

			if interval <= 0 {
				// 没开定时：等配置被改（wakeScheduler）或者干等一分钟兜底。
				// 不用两分钟的 sleep 是因为「改成 0 之后界面上要说未开启」，
				// 这一分钟只是防呆，不承担主要更新责任。
				select {
				case <-s.schedWake:
				case <-time.After(time.Minute):
				}
				continue
			}

			// 睡到下次该跑的时刻；中途配置被改了就先醒，重新算时间，不跑。
			timer := time.NewTimer(time.Until(next))
			select {
			case <-timer.C:
			case <-s.schedWake:
				timer.Stop()
				continue
			}

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

// wakeScheduler 让调度循环重新算一次「下次什么时候跑」。
//
// 保存配置后必须叫一声：否则间隔从 60 分钟改成 10 分钟，它还要按旧的
// 60 分钟睡足，界面上「下次测速」会一直显示一小时之后。
// 非阻塞发送：已经有一次待处理的唤醒就够了，多余的丢掉。
func (s *Server) wakeScheduler() {
	if s.schedWake == nil {
		return
	}
	select {
	case s.schedWake <- struct{}{}:
	default:
	}
}

// maxLogLines 是界面上保留的日志行数上限。文件里另有一份更长的完整日志
// （见 applog 包），界面只显示最近的这些，避免一次返回几十万字节。
const maxLogLines = 300

// appendLog 记一条运行日志：一份进内存给人的界面看，一份进 app.log 落盘。
//
// 时间戳由这里统一加上。以前日志不带时间，用户贴出来的那几行「已把安装向导里
// 填的端口写入 ddns.env」根本看不出是几点发生的，也没法跟其他记录对时序。
func (s *Server) appendLog(line string) {
	stamped := time.Now().Format("01-02 15:04:05") + " " + line

	s.mu.Lock()
	s.logs = append(s.logs, stamped)
	if len(s.logs) > maxLogLines {
		s.logs = s.logs[len(s.logs)-maxLogLines:]
	}
	s.mu.Unlock()

	// 走标准 log 输出：main 里已经把它接到了 stderr 和 app.log 上，
	// 这样这一行会同时出现在 docker logs 和文件里。用 Print 而不是 Printf，
	// 因为 line 里可能带 %（比如 Python 报错的格式串）。
	log.Print(line)
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
		// 别把 IP 当域名：有人会把「服务器 IP」直接填进来，写进 AdGuard
		// 的重写表就是一条垃圾记录；导入别人改过的备份时也会碰到。
		if net.ParseIP(d) != nil {
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
