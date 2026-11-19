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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
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
// 密码是每次请求现读的，不是启动时读一次定死：飞牛的安装/应用设置脚本会改写
// dashboard-password，但那些脚本没有权限操作 docker，`docker restart` 常常失败。
// 启动时固化的话用户在向导里设的密码永远不生效，现象正是「设了密码还是登不上，
// 只有日志里那个自动生成的能进」。现读现比之后，脚本写文件即生效。
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
	// history 是最近几轮测速的摘要（见 history.go）。只留在内存 + 数据目录的
	// history.json 里，不进配置、不进备份、不进导出包。
	history []roundRecord
	lastErr string
	// 定时器状态：下一次什么时候跑、上一次成没成、连续失败几次。
	// 以前后台只能看到「上次测速时间」，看不出「它到底还活着吗、还是每小时
	// 都在失败」，这两样才是判断「要不要管它」的依据。
	nextRunAt time.Time
	lastOK    bool
	failCount int
	// lastDurSec 是上一次测速实际花了几秒。
	// 界面用它回答「跑一轮要多久」，用户点完「立即测速」最想知道的就是
	// 「还要等多久」，而这是唯一能给他一个具体数字的依据（同一台机器、
	// 同一个网络，上次多久这次大致就多久）。
	// 不落盘：它是「这一进程跑的那一次」，重启后说「不知道」才对。
	lastDurSec int
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
	// 睡在那儿，界面上「下次测速」也要等它醒过来才更新，最长能差一小时。
	schedWake chan struct{}

	// candText 非空时，/api/candidates 直接返回这一段。用于「来源里有链接」的情形：
	// 链接必须在开跑前下载解析一次，不能等引擎来请求时再下，引擎会重试、也可能请求
	// 多次，每来一次就重下一遍外部站点，既慢又容易被限流。candStaged 是配对的「已暂存」
	// 标志：空文本也是合法结果（用户填的来源一个地址都没有），不能靠长度判断。
	candText   string
	candStaged bool

	// IPv6 探测（阶段①：只测不写）。与主测速完全隔离：结果不进 res.IPs，永远不会被
	// 写进 AdGuard 或 DDNS。存 config.NodeStat 而不是 engine.Node：v6 也要显示真实
	// 机房位置，而 engine.Node 是测速引擎的输出，只该有速度/延迟。
	v6ProbeRunning bool
	v6ProbeNodes   []config.NodeStat
	v6ProbeAt      time.Time
	v6ProbeErr     string
	// lastV6IPs 是最近一次 v6 探测出来的那批地址（排好序），概览页「当前最优 IP」
	// 下面那一行读它。它必须和 v6ProbeNodes 同源，所以只在 runIPv6Probe 里赋值
	// 一处：以前整轮测速那边也赋一次，而手动点「开始探测」只更新 v6ProbeNodes，
	// 于是卡片停在旧地址、下面表格却是新测的，两个 v6 不一样，用户只能猜哪个是真的。
	// 取「最近测出来的」而不是「写进 AAAA 的」：v4 那格显示的是 cfg.LastIP，
	// 同样只是最近一次测出的最优，并不保证已经写进域名。两格要对得上。
	lastV6IPs []string
	// v6CandText / v6CandStaged 和主测速的 candText 是同一个套路：
	// 用户在探测卡片里填的链接必须在**开跑前**下载解析一次，不能等引擎
	// 来拉候选时再下，引擎会重试、可能请求多次，每来一次就重新下载
	// 一遍外部站点，既慢又容易被对方限流。标志位是为了区分「没暂存」
	// 和「暂存了一段空文本」（链接里一个 v6 段都没有）。
	v6CandText   string
	v6CandStaged bool
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
	// 历史也是同理：重启一次就清空的话，「昨天凌晨那轮为什么失败」永远查不到。
	s.loadHistory()
	// 概览页那行 v6 从盘上那份接着来，不然重启之后卡片上的 v6 消失、而下面的
	// 表格还在（那张表有空就回落配置）。v6 关掉时不接：那时 cfg 里这份是关掉
	// 之前的旧地址，接着显示等于说「你还有 v6」，与开关状态对着干。
	if len(cfg.IPv6Sources()) > 0 {
		s.lastV6IPs = append(make([]string, 0, len(cfg.LastIPv6IPs)), cfg.LastIPv6IPs...)
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
	mux.HandleFunc("/api/switch", s.auth(s.handleSwitch))
	mux.HandleFunc("/api/config/export", s.auth(s.handleExport))
	mux.HandleFunc("/api/config/import", s.auth(s.handleImport))
	mux.HandleFunc("/api/credentials", s.auth(s.handleCredentials))
	mux.HandleFunc("/api/password", s.auth(s.handlePassword))
	mux.HandleFunc("/api/ddns/check", s.auth(s.handleDDNSCheck))
	mux.HandleFunc("/api/ddns/update", s.auth(s.handleDDNSUpdate))
	// 域名页的三个即时操作：加 / 删 / 切换包含子域。每个都自己落盘并立刻
	// 写 AdGuard，不经过 /api/config 那套全量保存。详见 web/domains.go。
	mux.HandleFunc("/api/domains", s.auth(s.handleDomains))
	mux.HandleFunc("/api/domains/check", s.auth(s.handleDomainCheck))
	mux.HandleFunc("/api/domains/wildcard", s.auth(s.handleDomainWildcard))
	mux.HandleFunc("/api/adguard/rewrites", s.auth(s.handleAdguardRewrites))
	mux.HandleFunc("/api/run", s.auth(s.handleRun))
	mux.HandleFunc("/api/history", s.auth(s.handleHistory))
	// 本机 IPv6 只读检测（阶段①）。只读、不改任何状态，但含本机网卡细节，仍需登录。
	mux.HandleFunc("/api/ipv6", s.auth(s.handleIPv6))
	// IPv6 阶段①探测：只测 CF 的 v6 节点、不写任何解析。
	// candidates 端点给测速引擎喂 v6 候选，和主测速的 /api/candidates 完全隔离。
	mux.HandleFunc("/api/ipv6/candidates", s.candidatesGuard)
	mux.HandleFunc("/api/ipv6/probe", s.auth(s.handleIPv6Probe))
	mux.HandleFunc("/api/ipv6/probe/result", s.auth(s.handleIPv6ProbeResult))
	// v6 段来源不再是独立接口：它和「优选 IP 段」一样是 /api/config 里的一个
	// 字段，跟着「保存全部设置」一起存。原来那个 /api/ipv6/source 已删除，
	// 留着就有两条写入路径，只改一条会覆盖另一条写的内容。

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
		// IPv6 探测的候选入口返回 CF v6 段采样，和主测速的 v4 候选完全隔离。
		if r.URL.Path == "/api/ipv6/candidates" {
			s.handleIPv6Candidates(w, r)
			return
		}
		s.handleCandidates(w, r)
		return
	}
	http.Error(w, "forbidden", http.StatusForbidden)
}

// handleCandidates 返回候选 IP 列表（每行 ip:port#国家）。
//
// 内容由用户配置决定：没设自定义来源 → 内置官方段；设了段/单 IP/链接 →
// 只从那里来（链接由 runOnce 预先下载解析后暂存）。详见 candidateList 的注释。
func (s *Server) handleCandidates(w http.ResponseWriter, r *http.Request) {
	count := atoiDefault(r.URL.Query().Get("n"), candidateCount)
	if count > 3000 {
		count = 3000
	}

	s.mu.Lock()
	c := s.cfg.Clone()
	staged, stagedOK := s.candText, s.candStaged
	s.mu.Unlock()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if stagedOK {
		_, _ = w.Write([]byte(staged))
		return
	}
	_, _ = w.Write([]byte(candidateList(&c, count)))
}

// candidateCount 是交给测速引擎的候选条数上限。
//
// 和 cfnb 请求 /api/candidates 不带 n 时的默认值保持一致：引擎实际拿到多少
// 取决于这个上限，两边不一致就会出现「界面说 600、实际给了 3000」的错觉。
const candidateCount = 600

// stageCandidates 暂存这一轮算好的候选列表（含链接解析结果），供 /api/candidates 用。
func (s *Server) stageCandidates(text string) {
	s.mu.Lock()
	s.candText, s.candStaged = text, true
	s.mu.Unlock()
}

func (s *Server) unstageCandidates() {
	s.mu.Lock()
	s.candText, s.candStaged = "", false
	s.mu.Unlock()
}

// resolveLinkSources 把配置里的链接下载下来，当成另一份 IP 列表并进 src。
//
// 返回合并后的来源，以及「本地认不出、留给引擎再试一次」的链接。
// 两种情况都必须打日志说明原因：链接是用户自己填的，出问题时他只能靠日志判断
// 是「地址坏了」还是「内容格式不对」，而这两件事的处理方式完全不同。
// sourceLabel 决定一条来源在日志里怎么写。内置来源是写死在程序里的链接，打出来等于
// 把它暴露出去（用户要的就是不暴露），所以只写「内置来源」；自定义来源原样写，
// 出问题时用户得能看出是哪一条挂了。
func sourceLabel(mode, u string) string {
	if mode == config.SourceBuiltin {
		return "内置来源"
	}
	return u
}

func (s *Server) resolveLinkSources(ctx context.Context, src extraSources, mode string) (extraSources, []string) {
	if len(src.urls) == 0 {
		return src, nil
	}
	merged := src
	merged.urls = nil
	var unparsed []string

	for _, u := range src.urls {
		text, err := fetchSourceText(ctx, u)
		if err != nil {
			s.appendLog(fmt.Sprintf("来源链接拉取失败（%s）：%v", sourceLabel(mode, u), err))
			unparsed = append(unparsed, u)
			continue
		}
		got, st := parseSourceText(text)
		if got.isEmpty() {
			s.appendLog(fmt.Sprintf(
				"来源链接里没认出任何 IP（%s）：内容共 %d 条认不出%s",
				sourceLabel(mode, u), st.skippedTotal, sampleHint(st.skipped)))
			unparsed = append(unparsed, u)
			continue
		}
		s.appendLog(fmt.Sprintf(
			"来源链接解析完成（%s）：单个 IP %d 个、带端口节点 %d 个、IP 段 %d 个%s",
			sourceLabel(mode, u), st.ips, st.nodes, st.cidrs, sampleHint(st.skipped)))
		mergeSources(&merged, got)
	}
	return merged, unparsed
}

// sampleHint 把「认不出的样例行」拼成一句人话，最多列 5 条。
// 认不出的内容最值钱：用户给的链接格式变了、或者干脆是一个 404 网页，
// 看这几条样例比看「0 节点」有用得多。
func sampleHint(samples []string) string {
	if len(samples) == 0 {
		return ""
	}
	quoted := make([]string, 0, len(samples))
	for _, x := range samples {
		if len(x) > 24 {
			x = x[:24] + "…"
		}
		quoted = append(quoted, "「"+x+"」")
	}
	return "，认不出的例如 " + strings.Join(quoted, "、")
}

// sourcePlanText 用一句话说清「这一轮本地凑出了哪些来源」。
//
// 刻意不写「0 个」：用户只填一条链接时，「IP 段 1 个、单个 IP 0 个、带端口
// 节点 0 个」里那两个 0 只会让本来就心慌的人更慌，信息量为零。
func sourcePlanText(src extraSources) string {
	var parts []string
	if n := len(src.cidrs); n > 0 {
		parts = append(parts, fmt.Sprintf("IP 段 %d 个", n))
	}
	if n := len(src.ips); n > 0 {
		parts = append(parts, fmt.Sprintf("单个 IP %d 个", n))
	}
	if n := len(src.nodes); n > 0 {
		parts = append(parts, fmt.Sprintf("带端口节点 %d 个", n))
	}
	if len(parts) == 0 {
		return "本地没认出任何 IP"
	}
	return strings.Join(parts, "、")
}

// ---------- 认证 ----------
//
// 令牌用 HMAC 签名，服务端不存会话表：容器重启后登录状态不丢，签名密钥由密码派生，
// 改密码即等于吊销全部旧令牌。令牌两种携带方式，按顺序取：Authorization: Bearer
// （前端首选）、Cookie: cfddns_session（直连浏览器兜底）。必须支持第一种：飞牛把后台
// 嵌在 iframe 里，跨站上下文下浏览器可能根本不保存 Cookie，于是「登录成功 → 下一个
// 请求又 401」，表现为输什么密码都提示未登录。

const (
	sessionCookie = "cfddns_session"
	sessionTTL    = 30 * 24 * time.Hour
)

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 正常路径上密码一定非空（main 读不到会现生成一个）。
		// 真走到这里说明连生成都失败了，此时必须拒绝而不是放行，
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
// 表现为「登录成功但下一个请求又 401」，这正是最早那版「怎么输密码都进不去」的原因。
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

// handlePassword 修改后台登录密码。要在后台自己做一个入口而不是只靠「应用设置」：
// 那里那个密码框没有任何校验，填 123456 也能保存；改完还要回桌面重开页面，没法当场
// 确认生效。这里当场校验强度、原子写入、换发令牌，改完立刻可验证。
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

	// 下面两个是「必须让用户看见」的状态：配置是从备份恢复的。以前只进运行日志，而
	// 运行日志在卡片最下面、还要往下滚，等于没提示。这里曾有一个 password_weak 用来挂
	// 「登录密码太短」的黄条，2026-11-17 按用户要求删掉了（他从向导里设的就是 6 位）。
	RestoredConfig bool `json:"restored_config"`
	// 恢复的两种来路，界面据此决定说哪句话（见 index.html 的 renderBanners）：
	//   restored_upgrade=false → 只是 config.json 丢了，config.json.bak 顶上；
	//   restored_upgrade=true  → 整个数据目录被删过，连 .bak 都没了，
	//                            靠升级前搬到外面的那份救回来，来源在 restored_source。
	RestoredUpgrade bool   `json:"restored_upgrade"`
	RestoredSource  string `json:"restored_source"`
	LogFile         string `json:"log_file"`

	// 定时器状态：下次几点跑、还有多少秒、上次成没成、连续失败几次。
	// next_run_at 给人看（「01:12」），next_run_in_sec 给「还剩 N 分钟」用。
	NextRunAt    string `json:"next_run_at"`
	NextRunInSec int    `json:"next_run_in_sec"`
	LastOK       bool   `json:"last_ok"`
	FailCount    int    `json:"fail_count"`

	// 上次测速排好序的完整 IP 列表。界面用它显示「已写入前 N 条」，
	// 也让用户在改条数之前就能看到有哪些备选。
	LastIPs []string `json:"last_ips"`

	// 上一轮测出来的 IPv6（同样排好序）。只用于概览页「当前最优 IP」那一格多显示
	// 一行 v6 地址——没有 v6 的机器上这一行不出现。重启后由 New 从配置里回填，
	// 否则卡片这行会消失、而下面的 v6 表格还在（那张表空了会回落配置）。
	LastV6IPs []string `json:"last_v6_ips"`

	// 上面那批里最快那条的位置，v6 那行用它显示「国家(机房)」。
	// 和 v4 那格的「位置 · 条数」同一套写法，两族看起来才是一件事。
	LastV6Place string `json:"last_v6_place"`

	// Nodes 与 last_ips 一一对应，多带速度、延迟、机房。
	// 以前界面只有一个光秃秃的 IP，用户看不出「为什么这条排第一」，
	// 也没法判断换个 IP 是不是更好，这三个数就是答案。
	Nodes []config.NodeStat `json:"nodes"`

	// 上次测速花了多少秒。0 表示没记录（刚重启、还没跑过）。
	LastDurationSec int `json:"last_duration_sec"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	cfg := s.cfg.Clone()
	// 概览页 v6 那行的位置取这一批最快的那条。LastIPv6Nodes 和 LastIPv6IPs 是同一次
	// buildNodeStats 出来的，下标一一对应；老配置里 Place 还是空的，就按机房代码现拼。
	v6Place := ""
	if len(s.lastV6IPs) > 0 && len(cfg.LastIPv6Nodes) > 0 {
		if p := cfg.LastIPv6Nodes[0].Place; p != "" {
			v6Place = p
		} else {
			v6Place = exitInfo(cfg.LastIPv6Nodes[0].Colo)
		}
	}
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
		NextRunInSec:    secsUntil(s.nextRunAt),
		LastOK:          s.lastOK,
		FailCount:       s.failCount,
		LastIPs:         append([]string{}, cfg.LastIPs...),
		LastV6IPs:       append([]string{}, s.lastV6IPs...),
		LastV6Place:     v6Place,
		Nodes:           append([]config.NodeStat{}, cfg.LastNodes...),
		LastDurationSec: s.lastDurSec,
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
	// DomainRows 是 domains 的展开版：多了「包含子域」和添加时间。
	// 两个都发是故意的，domains 保持原样，别的调用方（导入、脚本）不用改；
	// 界面要画列表就得知道每个域名的子域开关，而那信息在 domain_meta 里。
	DomainRows      []domainRow `json:"domain_rows"`
	TopN            int         `json:"top_n"`
	Candidates      int         `json:"bandwidth_candidates"`
	IntervalMinutes int         `json:"interval_minutes"`
	ExtraSources    []string    `json:"extra_sources"`
	SourceMode      string      `json:"source_mode"`
	IPv6ProbeURL    string      `json:"ipv6_probe_url"`
	IPv6SourceMode  string      `json:"ipv6_source_mode"`
	// hosts 源那一块（GitHub hosts 清单写进 AdGuard 重写）。和上面那些设置
	// 完全独立，见 web/hosts.go 顶部。
	HostsEnabled    bool   `json:"hosts_enabled"`
	HostsSource     string `json:"hosts_source"`
	HostsEntryCount int    `json:"hosts_entry_count"`
	HostsSyncedAt   string `json:"hosts_synced_at"`
	DDNSEnabled     bool   `json:"ddns_enabled"`
	DDNSProvider    string `json:"ddns_provider"`
	DDNSDomain      string `json:"ddns_domain"`
	DDNSTTL         int    `json:"ddns_ttl"`
	DDNSProxied     bool   `json:"ddns_proxied"`
	DDNSIPCount     int    `json:"ddns_ip_count"`
	// DDNSMinSpeed 是写解析的最低下载速度（Mbps），0 表示不限。
	// 报原值而不是「实际生效值」：这里没有「0 按 1 处理」那种折算，
	// 0 就是用户选的「不限」，界面上要照原样回填。
	DDNSMinSpeed float64 `json:"ddns_min_speed"`
	// DDNSRecordType 是要写的记录类型：A（IPv4）或 AAAA（IPv6）。
	// 和上面的开关不同，它有两个合法值，所以用「空 = A」没法表达「用户主动选了 A」；
	// 真要区分得用指针。这里取值受限、且老界面不会传，用字符串足够：
	// 前端始终会带上当前值，不存在「漏传就把用户的选择清掉」的问题。
	DDNSRecordType string `json:"ddns_record_type"`

	// 高级设置：引擎参数表 + 用户改过的值。
	//
	// 表跟着配置一起发，不单开一个接口：它和「当前值」必须成对出现，
	// 分成两个请求就有中间态，界面拿着旧表去渲染新值，那个参数会静默丢失。
	EngineGroups    []engine.OptGroup `json:"engine_groups"`
	EngineOptions   []engine.OptSpec  `json:"engine_options"`
	EngineOverrides map[string]any    `json:"engine_overrides"`
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
			DomainRows:      domainRows(c),
			TopN:            c.Speed.TopN,
			Candidates:      c.Speed.BandwidthCandidates,
			IntervalMinutes: c.Speed.IntervalMinutes,
			ExtraSources:    c.Speed.ExtraSources,
			// 发的是实际生效的模式，不是裸字段：老配置里没有这项，前端要能拿到
			// 下拉该显示的那一项（见 config.EffectiveSourceMode）。
			SourceMode:      c.EffectiveSourceMode(),
			IPv6ProbeURL:    c.IPv6ProbeURL,
			IPv6SourceMode:  c.EffectiveIPv6SourceMode(),
			HostsEnabled:    c.HostsEnabled,
			HostsSource:     c.HostsSource,
			HostsEntryCount: len(c.HostsEntries),
			HostsSyncedAt:   c.HostsSyncedAt,
			DDNSEnabled:     c.DDNS.Enabled,
			DDNSProvider:    c.DDNS.Provider,
			DDNSDomain:      c.DDNS.Domain,
			DDNSTTL:         c.DDNS.TTL,
			DDNSProxied:     c.DDNS.Proxied,
			DDNSIPCount:     c.DDNS.EffectiveIPCount(),
			DDNSMinSpeed:    c.DDNS.MinSpeedMbps,
			DDNSRecordType:  c.DDNS.EffectiveRecordMode(),
			EngineGroups:    engine.Groups,
			EngineOptions:   engine.Schema,
			EngineOverrides: c.Speed.EngineOverrides,
		})
	case http.MethodPost:
		s.saveConfig(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// parseSourceURLLines 把「一行一个链接」的输入框按行校验成链接列表。label 是这一栏在
// 界面上的名字，出错时原样带回：只报「第 3 行不合法」而不说哪一栏，两栏同在一页时用户
// 还得自己找。只认 http(s) 链接，想手写 IP 段去「优选 IP 段」。空行丢掉，# 开头的注释
// 行原样保留但不参与拉取。保存配置和导入备份必须共用这一份实现，否则会出现「界面存得
// 进、备份导不进」这种没人想得到的分歧。
func parseSourceURLLines(raw, label string) ([]string, error) {
	var out []string
	for i, l := range strings.Split(raw, "\n") {
		t := strings.TrimSpace(l)
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "#") {
			out = append(out, t)
			continue
		}
		u, perr := url.Parse(t)
		if perr != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf(
				"「%s」第 %d 行不是合法链接：%s。每行要填 http:// 或 https:// 开头的地址",
				label, i+1, t)
		}
		out = append(out, t)
	}
	return out, nil
}

// parseV6SourceInput 是「IPv6 段链接」那一栏的校验，规则见 parseSourceURLLines。
func parseV6SourceInput(raw string) ([]string, error) {
	return parseSourceURLLines(raw, "IPv6 段链接")
}

func (s *Server) saveConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AdGuardURL      string `json:"adguard_url"`
		AdGuardUser     string `json:"adguard_user"`
		AdGuardPassword string `json:"adguard_password"`
		// 域名列表也用指针，但理由和下面 ExtraSources 略有不同：
		// 域名现在由 /api/domains 那几个小接口增删（点「添加」就生效），
		// 全量保存时界面**不再提交**这个字段。若还是普通切片，没传就等于
		// 「传了空列表」→ cfg.Domains 被清空 → 用户点一次「保存全部设置」
		// 域名全没了。传了的话仍然照旧走检查（导入文件、旧客户端）。
		Domains         *[]string `json:"domains"`
		TopN            int       `json:"top_n"`
		Candidates      int       `json:"bandwidth_candidates"`
		IntervalMinutes int       `json:"interval_minutes"`
		// 用指针是为了区分「没传这个字段」和「传了空数组」：
		//   没传（nil）  → 保持原值，不动用户已设的段（老的导入文件、旧客户端）；
		//   传了 []      → 用户主动清空，恢复用内置官方段。
		// 若用普通切片，这两种情况都是长度 0，清空就永远生效不了。
		ExtraSources *[]string `json:"extra_sources"`
		// 来源模式同样用指针：「没传」= 不动（老界面、老备份文件里没有这一项）。
		// 传了只在 builtin / custom / off 三个值里认一个，别的当场退回。
		SourceMode *string `json:"source_mode"`
		// v6 段来源用指针，理由同上：没传 = 不动（旧客户端、老的导入文件），
		// 传了空串 = 用户主动清空，要真的清掉。
		IPv6ProbeURL   *string `json:"ipv6_probe_url"`
		IPv6SourceMode *string `json:"ipv6_source_mode"`
		// hosts 源那一块。开关和链接都用指针：没传 = 不动（老界面、老的导入
		// 文件里没有这两项），传了空串 = 用户主动清空来源。用普通 bool 的话
		// 「没传」和「关掉」都是 false，一次只改 AdGuard 地址的保存就会把它关掉。
		HostsEnabled *bool   `json:"hosts_enabled"`
		HostsSource  *string `json:"hosts_source"`
		DDNSEnabled  bool    `json:"ddns_enabled"`
		DDNSProvider string  `json:"ddns_provider"`
		DDNSDomain   string  `json:"ddns_domain"`
		DDNSTTL      int     `json:"ddns_ttl"`
		DDNSProxied  bool    `json:"ddns_proxied"`
		DDNSIPCount  int     `json:"ddns_ip_count"`
		// 用指针：0 = 不限，本身就是用户能选的值，不能用零值代表「没传」。
		// 旧界面不传这个字段时保持原样，否则一次「只改域名」的保存就把门槛清了，
		// 而它一清就会开始写低速地址，界面上又看不出门槛被改过。
		DDNSMinSpeed *float64 `json:"ddns_min_speed"`
		// 用指针：「没传」和「传了空串」要区分开。空串归一成 A 是合法的主动选择，
		// 而旧客户端/老的导入文件里根本没有这个字段，那时必须保持原样不动，
		// 否则一次「只改域名」的保存就会把用户选的 AAAA 悄悄改回 A。
		DDNSRecordType *string `json:"ddns_record_type"`
		// 高级设置。同样用指针：没传 = 不动（旧客户端、老导入文件），
		// 传了空对象 = 用户点了「恢复默认」，要真的清空。
		EngineOverrides *map[string]any `json:"engine_overrides"`
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
	// 0 表示「没填/用默认」，按 1 条处理，老界面和老的备份文件里没有这个字段，
	// 一上来就要求 1..20 会把它们全部判成非法。
	if body.DDNSIPCount < 0 || body.DDNSIPCount > 20 {
		writeJSON(w, 400, map[string]string{
			"error": "「同步几条 IP」请填 1 到 20 之间的整数",
		})
		return
	}
	// 上限 1000：不为限制谁的家宽，只为拦住手滑多打几个 0。门槛填成 10000
	// 的效果是「一条都不写」，而界面上它看起来只是个数字，用户不会立刻想到
	// 解析停更是因为它。
	if body.DDNSMinSpeed != nil {
		if v := *body.DDNSMinSpeed; v < 0 || v > 1000 {
			writeJSON(w, 400, map[string]string{
				"error": "「最低下载速度」请填 0（不限）到 1000 之间的数，单位是 Mbps",
			})
			return
		}
	}
	// 记录类型 / 同步模式：只认 A / AAAA / A+AAAA。写错的值**当场退回**，
	// 不回落成 A，用户以为在写 v6、实际写了 v4 的话，任何日志都不会提示，
	// 只能等他自己发现访问没变快。
	// 没传（旧界面/老备份文件）就保持原样，不当作改成了 A。
	if body.DDNSRecordType != nil {
		if _, err := ddns.NormalizeRecordMode(*body.DDNSRecordType); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
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

	// 「IPv6 段链接」逐行校验，错一行就整单退回并指明第几行。
	var v6Lines []string
	if body.IPv6ProbeURL != nil {
		lines, verr := parseV6SourceInput(*body.IPv6ProbeURL)
		if verr != nil {
			writeJSON(w, 400, map[string]string{"error": verr.Error()})
			return
		}
		v6Lines = lines
	}

	// hosts 源链接：同一套逐行校验，错一行就整单退回并指明第几行。
	var hostsLines []string
	if body.HostsSource != nil {
		lines, herr := parseSourceURLLines(*body.HostsSource, "hosts 源链接")
		if herr != nil {
			writeJSON(w, 400, map[string]string{"error": herr.Error()})
			return
		}
		hostsLines = lines
	}

	// 来源模式：只认三个值，写错当场退回。
	var srcMode, v6Mode string
	if body.SourceMode != nil {
		m, merr := config.NormalizeSourceMode(*body.SourceMode)
		if merr != nil {
			writeJSON(w, 400, map[string]string{"error": merr.Error()})
			return
		}
		srcMode = m
	}
	if body.IPv6SourceMode != nil {
		m, merr := config.NormalizeSourceMode(*body.IPv6SourceMode)
		if merr != nil {
			writeJSON(w, 400, map[string]string{"error": merr.Error()})
			return
		}
		v6Mode = m
	}

	s.mu.Lock()
	cfg := s.cfg.Clone()
	cfg.AdGuard.URL = strings.TrimSpace(body.AdGuardURL)
	cfg.AdGuard.Username = strings.TrimSpace(body.AdGuardUser)
	// 密码留空表示「不修改」，避免用户只改域名时把 AdGuard 密码清掉
	if body.AdGuardPassword != "" {
		cfg.AdGuard.Password = body.AdGuardPassword
	}
	// 域名：先规范化，再逐个确认是不是真走 Cloudflare 边缘（判据见 cfcheck.go）。拦的
	// 理由：域名压根没接 CF 的话，改完指向的是一个不认识它的边缘节点，页面直接打不开，
	// 而用户几乎想不到是这个原因。三类结果分开处理：确认走 CF 的保存，确认不走的**不
	// 保存**，查不了的（DNS 超时）照样保存只标出来。没传 domains 就整段跳过：域名已由
	// 增量接口管着，保存别的设置时不该顺手再验一遍。
	var keptDomains []string
	var rejectedDomains, unknownDomains []DomainCheck
	if body.Domains != nil {
		submitted := normalizeDomains(*body.Domains)
		keptDomains, rejectedDomains, unknownDomains = screenDomains(r.Context(), submitted)
		cfg.Domains = keptDomains
		// 列表被整体替换了（界面上可能删过行），元信息要跟着对齐，否则删掉的
		// 域名会把「包含子域」和添加时间留给下次同名域名。
		cfg.PruneDomainMeta()
	}
	if body.TopN > 0 {
		cfg.Speed.TopN = body.TopN
	}
	if body.Candidates > 0 {
		cfg.Speed.BandwidthCandidates = body.Candidates
	}
	cfg.Speed.IntervalMinutes = body.IntervalMinutes
	// body.ExtraSources 为 nil 表示请求里没带这个字段（旧客户端/老导入文件），
	// 此时保留原值，不能顺手清空，那会把用户辛苦填的段默默删掉。
	if body.ExtraSources != nil {
		cfg.Speed.ExtraSources = extraLines
	}
	if body.IPv6ProbeURL != nil {
		// 存成多行字符串（一行一个链接），和字段定义保持一致。
		cfg.IPv6ProbeURL = strings.Join(v6Lines, "\n")
	}
	if body.HostsSource != nil {
		cfg.HostsSource = strings.Join(hostsLines, "\n")
	}
	if body.HostsEnabled != nil {
		cfg.HostsEnabled = *body.HostsEnabled
	}
	if srcMode != "" {
		cfg.Speed.SourceMode = srcMode
	}
	if v6Mode != "" {
		cfg.IPv6SourceMode = v6Mode
	}
	// 「自定义」但一条来源都没有 = 这一族实际上没东西可测。在这里退回，比等下一轮
	// 测速报「来源里没解析出任何可用 IP」清楚得多——那时用户已经忘了自己改过什么。
	if cfg.EffectiveSourceMode() == config.SourceCustom && len(cfg.Speed.ExtraSources) == 0 {
		s.mu.Unlock()
		writeJSON(w, 400, map[string]string{
			"error": "「优选 IP 段」选的是「自定义」，但一条来源都没填",
		})
		return
	}
	if cfg.EffectiveIPv6SourceMode() == config.SourceCustom && len(cfg.IPv6SourceURLs()) == 0 {
		s.mu.Unlock()
		writeJSON(w, 400, map[string]string{
			"error": "「IPv6 段链接」选的是「自定义」，但一条链接都没填",
		})
		return
	}
	// 引擎参数：同样「没传就不动」。NormalizeOverrides 会丢掉未知键、把
	// 类型转成 cfnb 认识的（"443,8443" → []int{443,8443}）、把越界值钳住，
	// 并丢掉「和默认值一样」的项，所以用户点「恢复默认」传空对象时，
	// 结果就是 nil，config.json 里那条不会留下一个空壳。
	if body.EngineOverrides != nil {
		cfg.Speed.EngineOverrides = engine.NormalizeOverrides(*body.EngineOverrides)
	}
	cfg.DDNS.Enabled = body.DDNSEnabled
	cfg.DDNS.Provider = strings.ToLower(strings.TrimSpace(body.DDNSProvider))
	cfg.DDNS.Domain = config.NormalizeDomain(body.DDNSDomain)
	cfg.DDNS.TTL = body.DDNSTTL
	cfg.DDNS.Proxied = body.DDNSProxied
	cfg.DDNS.IPCount = body.DDNSIPCount
	if body.DDNSMinSpeed != nil {
		cfg.DDNS.MinSpeedMbps = *body.DDNSMinSpeed
	}
	if body.DDNSRecordType != nil {
		rt, _ := ddns.NormalizeRecordMode(*body.DDNSRecordType) // 上面已校验过
		cfg.DDNS.RecordType = rt
	}

	s.cfg = &cfg
	s.mu.Unlock()

	if err := cfg.Save(); err != nil {
		writeJSON(w, 500, map[string]string{"error": "保存失败: " + friendlyErr(err)})
		return
	}

	// 用户主动保存过一次 = 已经看过并确认了恢复出来的内容，那条红条可以撤了。
	// 只在这里清，不在定时测速顺手保存时清，那种保存不是「人看过了」。
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

	// v4 / v6 的来源被设成「关闭」之后，AdGuard 里由它写进去的那一族要当刻收回。
	// 不这么做的话，「关闭」这件事要等到下一轮测速（默认 60 分钟）才生效，中间这段
	// 时间用户看到的就是「关了还在」，而日志里什么都不说。hosts 开关那边是同一个
	// 理由，见 switch.go 里那段注释。
	//
	// 只在真有一族是关闭状态时才连 AdGuard：两族都开着的时候答案不会变，白连一次
	// 只是让「保存」这个按钮多等一两秒。
	if cfg.AdGuard.URL != "" &&
		(cfg.EffectiveSourceMode() == config.SourceOff || cfg.EffectiveIPv6SourceMode() == config.SourceOff) {
		if note := s.syncRewrites(cfg); note != "" {
			s.appendLog(note)
		}
	}

	// 开了云朵这件事必须留在日志里。以后用户看到「域名解析的 IP 不是最优 IP」
	// 时，日志里这一行能直接解释原因，是 Cloudflare 接手了，不是推送错了。
	if cfg.DDNS.Proxied && cfg.DDNS.Provider == "cloudflare" {
		s.appendLog("注意：Cloudflare 云朵（代理）已开启，域名会解析到 Cloudflare 的边缘节点，不再直接指向优选 IP")
	}

	// 被拦下的域名要进日志。用户过几天发现「我明明加了这个域名，怎么没生效」，
	// 翻日志能直接看到是哪一条、解析到了哪个 IP，比只在界面上弹一下有用。
	for _, r := range rejectedDomains {
		s.appendLog("域名未保存：" + r.Domain + " —— " + r.Reason)
	}
	for _, u := range unknownDomains {
		s.appendLog("域名已保存但没验成：" + u.Domain + " —— " + u.Reason)
	}

	writeJSON(w, 200, map[string]any{
		"ok":               true,
		"domains_kept":     keptDomains,
		"domains_rejected": rejectedDomains,
		"domains_unknown":  unknownDomains,
	})
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
		// 只收白名单里的密钥名。导入备份那条路早就这么做（allowedSecretKeys），这里
		// 原来没有，等于留了个「往 ddns.env 塞任意变量」的口子；而 ddns.env 会被宿主机
		// 的生命周期脚本当环境文件整个读进去。未知键直接退回并点名，不静默丢也不静默写。
		allowed := make(map[string]bool, 16)
		for _, k := range config.AllCredentialKeys() {
			allowed[k] = true
		}
		kv := make(map[string]string, len(body))
		var unknown []string
		for k, v := range body {
			v = strings.TrimSpace(v)
			if v == "" {
				continue // 留空表示不修改
			}
			if !allowed[k] {
				unknown = append(unknown, k)
				continue
			}
			kv[k] = v
		}
		if len(unknown) > 0 {
			sort.Strings(unknown)
			writeJSON(w, 400, map[string]string{
				"error": "不认识的密钥项：" + strings.Join(unknown, "、"),
			})
			return
		}
		// 用 UpdateEnvFile 而不是 SaveEnvFile：后者是整份重写，会把 ddns.env
		// 里用户自己写的注释、以及被注释掉的备用密钥（`#CF_API_TOKEN=旧的`）
		// 一起冲掉，这正是 UpdateEnvFile 顶部那段注释在防的事。
		if err := config.UpdateEnvFile(config.EnvFilePath(), kv); err != nil {
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

	go func() { _ = s.runOnce(cfg, triggerManual) }()

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
	return s.runOnce(cfg, triggerBoot)
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

// secsUntil 算「离这个时刻还有多少秒」，给界面上的「还剩 N 分钟」用。
//
// 为什么不直接让界面拿 next_run_at 自己减：next_run_at 是「15:04」这样的
// 字符串，跨天就分不清是今天还是明天；而且浏览器的时钟和 NAS 的时钟常常
// 差几分钟，算出来会对不上。在这里一次算清，界面只管照着念。
//
// 已经到点（或没开定时）返回 0：宁可少说一句，也不能显示「还剩 -3 分钟」。
func secsUntil(t time.Time) int {
	if t.IsZero() {
		return 0
	}
	d := int(time.Until(t).Seconds())
	if d < 0 {
		return 0
	}
	return d
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

// buildNodeStats 把「引擎结果 + 机房探测结果」拼成界面要的节点列表。
//
// 以 res.IPs 为准遍历而不是 res.Nodes：res.IPs 才是真正会被写进解析、也是 cfg.LastIPs
// 存下来的那份，两者一旦不一致，界面显示的条数和实际写进域名条数就对不上。
// 查不到机房的节点 Colo/Place 留空，界面显示「位置未知」。绝不按 IP 段猜国家：
// anycast IP 跟地理位置没有对应关系，猜出来的国家和真实出口可以差半个地球。
func buildNodeStats(res *engine.Result, colos map[string]string) []config.NodeStat {
	if res == nil || len(res.IPs) == 0 {
		return nil
	}
	byIP := make(map[string]engine.Node, len(res.Nodes))
	for _, n := range res.Nodes {
		byIP[n.IP] = n
	}

	out := make([]config.NodeStat, 0, len(res.IPs))
	for _, ip := range res.IPs {
		st := config.NodeStat{IP: ip}
		if n, ok := byIP[ip]; ok {
			st.Speed = n.Speed
			st.Delay = n.Delay
		}
		if colo := colos[ip]; colo != "" {
			st.Colo = colo
			st.Place = exitInfo(colo)
		}
		out = append(out, st)
	}
	return out
}

// failBeforeRun 记录「还没把候选交给引擎就失败」的情况，并把错误写进日志。
//
// 为什么不能只 return err：定时器那条路径是 `_ = s.runOnce(cfg, triggerTimer)`，
// 错误被丢掉了。2026-11-17 那次「候选全被筛掉」就是这样，日志停在「候选预筛：
// 剔除 N 个」半句话，用户完全看不出这一轮为什么没有结果，只会以为程序卡住了。
// （出错也会在历史里记一行，那是另一条让人看见的路。）
func (s *Server) failBeforeRun(msg string) error {
	s.mu.Lock()
	s.lastErr = msg
	s.lastOK = false
	s.failCount++
	s.mu.Unlock()
	s.appendLog("测速失败: " + msg)
	return errors.New(msg)
}

// rewriteAnswers 返回某个域名这一轮要写进 AdGuard 的答案集合。同一个域名可以既有 v4 又有
// v6 答案，客户端按自己支持的协议族各取一条，所以两族要一起给：认领语义下 want 里没有的
// 答案会被删掉，只写 v4 就等于每轮把 v6 抹了，还不报错。v6 这一轮没测出来时只给 v4，
// 此时删掉旧的 v6 答案是对的，比留着一条指向不可用地址的 AAAA 安全。
func rewriteAnswers(bestV4 string, v6IPs []string) map[string]bool {
	answers := make(map[string]bool, 2)
	if bestV4 != "" {
		answers[bestV4] = true
	}
	if len(v6IPs) > 0 && v6IPs[0] != "" {
		answers[v6IPs[0]] = true
	}
	return answers
}

// rewriteAnswersFor 按「当前的开关状态」算这一组域名该有哪些答案。
//
// 和 rewriteAnswers 的区别：那个是「这一轮测出什么」，这个是「现在允不允许有这一族」。
// 源设成「关闭」之后，对应的地址一个都不给——任何一次重同步都会把那一族从 AdGuard
// 里删掉。关掉开关却还留着记录，用户合理的判断就是「开关没生效」。
//
// 为什么不复用 LastIP / LastIPv6IPs 直接拼：那两个字段在关掉之后**不会清空**，
// 它们是「上次测出来的结果」，拿它算答案等于把刚关掉的那一族又写回去。以前就是这么
// 出问题的：v6 关掉后点一下「添加域名」，AdGuard 里那条 v6 又冒出来了。
//
// 所以关掉的那一族在这里被换成「没有」交给 rewriteAnswers，「取最优一条、空串不算」
// 这些规则只留在那一个地方，免得两处各写一遍、改了一处另一处还留着旧规则。
func rewriteAnswersFor(cfg config.Config) map[string]bool {
	v4 := cfg.LastIP
	if cfg.EffectiveSourceMode() == config.SourceOff {
		v4 = ""
	}
	var v6 []string
	if cfg.EffectiveIPv6SourceMode() != config.SourceOff {
		v6 = cfg.LastIPv6IPs
	}
	return rewriteAnswers(v4, v6)
}

// keptNote 把「保留了 N 条别人的记录」拼成日志尾巴，没有就返回空串。这句是给用户吃的
// 定心丸，也让「会不会顺手删掉我的规则」每次都有一次可核对的记录。
func keptNote(kept int) string {
	if kept <= 0 {
		return ""
	}
	return "，保留了 " + strconv.Itoa(kept) + " 条不是本工具写的记录"
}

// rewritePlan 组装这一轮要写进 AdGuard 的完整意图，两部分：当前域名列表（含
// 「包含子域」派生的 *.域名）各自该有的答案；账本里有、这一轮已经不管的域名给空答案集，
// 意思是「把记录全清掉」，这就是用户删掉域名后 AdGuard 上那条旧记录能被清掉的原因。
//
// answers 为空（还没测出任何 IP）时不做清理：那样空答案集会变成「把所有域名下的记录
// 都删掉」，把上一轮好好的结果抹了。调用方都会先拦住「没有 IP 就不写」，这里再兜一层，
// 因为这一层出错是静默的。
func rewritePlan(cfg config.Config, names []string, answers map[string]bool) map[string]map[string]bool {
	want := make(map[string]map[string]bool, len(names))
	for _, d := range names {
		want[d] = answers
	}
	if len(answers) == 0 {
		return want
	}
	for _, d := range cfg.RewrittenDomains {
		if d == "" {
			continue
		}
		if _, ok := want[d]; ok {
			continue // 又加回列表了，按当前答案写，不当成要清的
		}
		want[d] = map[string]bool{}
	}
	return want
}

// rememberRewritten 把「这一轮真正认领了哪些域名」记进配置并落盘。
//
// 只在内容变了的时候写盘：没变还写的话，每一轮测速都会顺手刷新一次
// config.json 和它的 .bak，等于每轮都覆盖掉「升级出事后能捡回来的那一份」。
//
// 失败只打日志、不往上抛：账本没记上不影响这一轮已经写进 AdGuard 的结果，
// 下一轮同步会自动再记一次（账本是自愈的，不需要人工补救）。
func (s *Server) rememberRewritten(domains []string) {
	s.mu.Lock()
	cur := s.cfg
	if cur == nil || slices.Equal(cur.RewrittenDomains, domains) {
		s.mu.Unlock()
		return
	}
	next := cur.Clone()
	next.RewrittenDomains = domains
	s.cfg = &next
	s.mu.Unlock()

	if err := next.Save(); err != nil {
		s.appendLog("记下 AdGuard 域名清单失败（不影响这次写入，下次同步会再记一次）: " + friendlyErr(err))
	}
}

// runIPv4Round 跑一轮 v4：解析来源 → 引擎（失败重试一次）→ 读出口机房 → 按国家筛。
// 调用方已确认来源模式不是 off。返回的 colos 是每个 IP 的真实机房，界面和筛选都要用。
//
// 出错只返回错误，记账和打日志由 runOnce 统一做：这里再记一次，「连续失败 N 次」
// 就会一次失败数成两次。
func (s *Server) runIPv4Round(ctx context.Context, cfg config.Config) (*engine.Result, map[string]string, error) {
	mode := cfg.EffectiveSourceMode()

	// 「优选 IP 段」：三类来源统一在本地解析，再由 /api/candidates 交给引擎。
	// 链接为什么也由我们下载：cfnb 的解析器只认单个 IP，遇到 104.16.0.0/13 这种段会
	// 整条丢掉，拉到内容却解析出 0 节点。本地解析之后段能采样、单 IP 能直通、带端口的
	// 节点能保住原端口，日志里也能说清认出了多少。实在解析不出的链接才回退给引擎。
	extra, _ := parseExtraSources(cfg.IPv4Sources())
	// 从配置里把链接原文单独留一份：resolveLinkSources 会把 extra.urls 清空（已被消费成
	// IP 列表），但日志得说清这一轮用的是哪几条来源。
	configuredURLs := append([]string(nil), extra.urls...)

	localCandidates := s.selfURL + "/api/candidates"
	var fallbackURLs []string

	s.appendLog("开始测速…")
	// 只打「用户改过的」那些。四十个参数全打会把日志淹掉，而用户改了开关
	// 过几天忘了、行为和预期不符时，这一行是唯一的线索。
	if d := engine.DescribeOverrides(cfg.Speed.EngineOverrides); d != "" {
		s.appendLog("高级设置已生效：" + d)
	}

	// 先交代「这一轮用的是哪份来源」，再交代「解析成了什么」。顺序不能反：
	// 22:14 那次真机反馈就是「结果出来了，但日志里找不到我那条链接」。
	if len(configuredURLs) > 0 {
		if mode == config.SourceBuiltin {
			s.appendLog("候选来源：内置来源（地址不显示）")
		} else {
			s.appendLog(fmt.Sprintf("候选来源：从你填的 %d 条链接下载 —— %s",
				len(configuredURLs), strings.Join(configuredURLs, "、")))
		}
	}
	if len(extra.urls) > 0 {
		extra, fallbackURLs = s.resolveLinkSources(ctx, extra, mode)
	}
	if mode == config.SourceBuiltin {
		// 内置链接绝不能交给引擎去拉：cfnb 会把数据源地址原样打进日志
		// （「拉取数据源 第 1/2 次（https://…）」），「不显示地址」就白做了。
		// 本地拉不到就是这一轮没来源，报错也只说没拉到。
		fallbackURLs = nil
	}
	staged := candidatesText(extra, candidateCount)

	if extra.isEmpty() && len(fallbackURLs) == 0 {
		if mode == config.SourceBuiltin {
			return nil, nil, fmt.Errorf("内置来源这一轮没拉到可用 IP（原因见上面那行），" +
				"隔一轮会自动再试")
		}
		return nil, nil, fmt.Errorf("这一轮的 v4 来源里没解析出任何可用 IP：请检查「优选 IP 段」里那几行" +
			"有没有写错、链接能否打开（具体原因看上面几行日志）")
	}
	// 本地一条候选都没有时不要把这个地址交给引擎：它会去拉一个空列表，
	// 日志里留一行「0 节点」，而这一次纯粹是我们没东西给它。
	if extra.isEmpty() {
		localCandidates = ""
	}

	// 第二句：解析成了什么。前半句用「候选来源：」还是「解析结果：」
	// 取决于上一句在不在，避免出现「解析结果」却不知道解析的是什么的怪句子。
	planHead := "候选来源："
	if len(configuredURLs) > 0 {
		planHead = "解析结果："
	}
	planTail := "；只用你填的来源，不叠加官方段和聚合源"
	if mode == config.SourceBuiltin {
		planTail = "；只用内置来源，不叠加官方段和聚合源"
	}
	s.appendLog(planHead + sourcePlanText(extra) + planTail)
	// 这里只说「解析出多少条」，不说「交给引擎」，真正交出去的是
	// 下面筛选之后的那一批，由 screenCandidates 自己报数。
	if n := strings.Count(staged, "\n"); n > 0 {
		s.appendLog(fmt.Sprintf(
			"候选池：本地解析出 %d 条候选（每次最多 %d 条）", n, candidateCount))
	}
	if len(fallbackURLs) > 0 {
		s.appendLog(fmt.Sprintf(
			"其中 %d 个链接的内容本地没认出 IP，已交给引擎自己再试一次", len(fallbackURLs)))
	}

	// 两道筛选（官方段预筛 + 1034 实测）放在这里，也就是**引擎启动之前**。
	//
	// 顺序是硬要求，不是顺手：带宽测速跑一次要几十秒，而一个会返回
	// 1034 的 IP 照样能测出速度，它在带宽那一轮是「合格」的，只有真去
	// 访问用户域名时才露馅。所以必须在这之前把它剔掉，否则这一轮的
	// 带宽测试就是白跑，最终还会把一个用户根本打不开的 IP 写进 AdGuard。
	rawStaged := staged
	staged = s.screenCandidates(ctx, &cfg, staged)
	s.stageCandidates(staged)
	defer s.unstageCandidates()
	if staged == "" && strings.TrimSpace(rawStaged) != "" {
		return nil, nil, fmt.Errorf("候选 IP 全被筛掉了：都不在 Cloudflare 官方段内，或对你的域名返回 1034。" +
			"这一轮没有写入任何结果——换一批来源，或把「优选 IP 段」放宽些")
	}

	run := func() (*engine.Result, error) {
		return engine.Run(ctx, s.enginePath, s.workDir, engine.Options{
			TopN:                cfg.Speed.TopN,
			BandwidthCandidates: cfg.Speed.BandwidthCandidates,
			CandidatesURL:       localCandidates,
			ExtraURLs:           fallbackURLs,
			// 内置和自定义都是「只用这一份」：内置那一条链接也是我们指定的来源，
			// 再叠官方 15 段和两个聚合源等于把用户划定的范围淹掉。
			UseBuiltinSources: false,
			// 用户的高级设置照传，但「按国家筛」那 8 个键要摘掉：候选带的是
			// 占位标签 `#US`，交给引擎等于按假数据筛（见 country_filter.go）。
			// 真实位置只有测完才知道，所以筛选挪到下面 colos 之后。
			Overrides: v4Overrides(cfg),
		}, s.appendLog)
	}

	res, err := run()

	// 失败自动重试一次。cfnb 的失败大多是「某个数据源或节点刚好超时」这类
	// 偶发问题，重试一次往往就过了。以前碰到只能干等下一个周期（默认 60
	// 分钟），等于白丢一轮。ctx 已经耗尽时不重试，那说明是真跑满了超时。
	if err != nil && ctx.Err() == nil {
		s.appendLog("测速失败: " + friendlyErr(err) + "；" + delayText(retryDelay) + "后自动重试一次")
		if waitFor(ctx, retryDelay) {
			s.appendLog("开始重试…")
			res, err = run()
		}
	}
	if err != nil {
		return nil, nil, err
	}

	// 上面那些 `1. x.x.x.x:443#US` 里的 `#US` **不是真实位置**，是为了满足引擎的
	// 解析格式补的占位值（没国家标签的裸 IP 会被逐条探测，慢且探测失败即丢）。
	// 所以引擎侧一律不按国家筛，按占位标签筛等于筛假数据，真正的国家筛选在下面
	// 拿到真实位置之后做。
	//
	// ctx 独立于测速：沿用测速那个快用完的预算会一条都探不出去，日志就成了误导。
	// 预算按实际条数算，10 条要跑两轮，固定 8 秒会在第二轮被打断。
	_, exitAllowance := exitProbePlan(len(res.IPs))
	exitCtx, exitCancel := context.WithTimeout(context.Background(), exitAllowance)
	colos := s.logExitCountries(exitCtx, res.IPs)
	exitCancel()

	// 国家筛选在这里做，代价是被筛掉的节点也白测了一遍，一轮比以前慢，所以日志
	// 里如实写「%d → %d 条」，想快就把国家开关关掉。
	// 筛完一条不剩必须走失败分支：空列表会让后面把空结果写进 AdGuard / DDNS，
	// 比直接报错更难查。
	if res, err = s.refineResultByCountry(cfg, res, colos, "IPv4"); err != nil {
		return nil, nil, err
	}
	return res, colos, nil
}

// runOnce 跑一轮完整流程。trigger 是「谁触发的」，只用来在历史里标一行
// （手动 / 定时 / 开机），不参与任何逻辑判断。
func (s *Server) runOnce(cfg config.Config, trigger string) error {
	startedAt := time.Now()
	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()

	v4Mode, v6Mode := cfg.EffectiveSourceMode(), cfg.EffectiveIPv6SourceMode()
	// 两族都关：用户要的是「这一轮什么都不测」。不当失败（不刷连续失败次数），
	// 也不当成功（last_ok 保持原样），界面上的「上次测速」停在真跑过的那一次。
	if v4Mode == config.SourceOff && v6Mode == config.SourceOff {
		s.appendLog("v4 和 v6 的来源都设成了「关闭」，这一轮不测速")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), engine.DefaultTimeout())
	defer cancel()

	res := &engine.Result{}
	var colos map[string]string
	if v4Mode == config.SourceOff {
		s.appendLog("v4 来源已关闭，这一轮只优选 v6")
	} else {
		var err error
		res, colos, err = s.runIPv4Round(ctx, cfg)
		if err != nil {
			msg := friendlyErr(err)
			s.mu.Lock()
			s.lastErr = msg
			s.lastOK = false
			s.failCount++
			s.mu.Unlock()
			s.appendLog("测速失败: " + msg)
			s.recordRound(startedAt, roundRecord{Trigger: trigger, Err: msg})
			return err
		}
		// 最优 IP 必须在筛完之后再取，否则被筛掉的那个会一路带到 AdGuard 和 DDNS，
		// 日志上还写着「最优 IP: x」，用户看到的是他刚明确排除掉的机房。
		s.appendLog("测速完成，最优 IP: " + res.Best())
	}

	best := res.Best()
	s.mu.Lock()
	s.lastErr = ""
	s.lastOK = true
	s.failCount = 0
	s.mu.Unlock()

	// 每个 IP 一行「质量数据」，界面直接渲染，不用再算。
	nodes := buildNodeStats(res, colos)

	// 0) v6 优选（可选，来源是「内置」或「自定义」且有内容才跑）。排在写入之前，
	// 因为下一步要按记录类型把 v6 写进 AAAA / AdGuard，那两处都要这一轮刚测出来的结果。
	//
	// 三条约定：来源设成「关闭」就完全不跑；v6 跑空不牵连 v4（v4 照旧写）；手动探测
	// 正在跑时跳过这一轮，两个一起跑会互相清掉对方的候选暂存，这里不阻塞等待。
	//
	// v6RoundIPs 是这一轮的结果，写 AdGuard / DDNS 都用它而不是 cfg.LastIPv6
	// （那是上一次成功的，可能是上一个小时的，拿去写解析等于塞一个早就不通的地址）。
	var v6RoundIPs []string
	// v6Nodes 是这一轮 v6 的明细，跟 v6RoundIPs 一起给历史用。探测刚跑完时
	// s.v6ProbeNodes 正好是这一轮的结果，拷一份走，别和历史记录共享底层数组。
	var v6Nodes []config.NodeStat
	if len(cfg.IPv6Sources()) > 0 {
		if s.claimIPv6Probe() {
			s.appendLog("开始 v6 优选…")
			ips, verr := s.runIPv6Probe()
			if verr != nil {
				// v4 关掉的时候不能再说「不影响 v4 结果」，这一轮压根没有 v4。
				if v4Mode == config.SourceOff {
					s.appendLog("v6 优选失败: " + friendlyErr(verr))
				} else {
					s.appendLog("v6 优选失败（不影响本次 v4 结果）: " + friendlyErr(verr))
				}
			} else {
				v6RoundIPs = ips
				s.mu.Lock()
				v6Nodes = append([]config.NodeStat(nil), s.v6ProbeNodes...)
				// 概览页那行 v6 不在这里赋：runIPv6Probe 里已经跟着 v6ProbeNodes
				// 一起更新了。两处各赋一次，定时跑和手动探测会走出两个不同的地址。
				s.mu.Unlock()
			}
		} else {
			s.appendLog("v6 探测正在手动进行中，这一轮跳过 v6 优选")
		}
	} else {
		// v6 关掉之后卡片上不该还挂着上一次的地址。
		s.mu.Lock()
		s.lastV6IPs = nil
		s.mu.Unlock()
	}

	// v4 关掉之后 v6 就是这一轮唯一的腿。它没测出地址等于这一轮什么都没测到，
	// 不能顺着往下把 last_ok 刷成「成功」——那会让界面显示一切正常，而记录一条没更新。
	if v4Mode == config.SourceOff && len(v6RoundIPs) == 0 {
		err := s.failBeforeRun("v4 已关闭，这一轮 v6 也没测出可用地址（原因看上几行日志）")
		s.recordRound(startedAt, roundRecord{Trigger: trigger, Err: err.Error()})
		return err
	}

	// 时间戳放在 v6 之后取：v6 可能要跑 1~2 分钟，用开始时刻会让「上次测速」
	// 显示的时间比实际早了整整一段。
	now := time.Now().Format("2006-01-02 15:04:05")

	// 1) 写入 AdGuard Home 重写表
	//
	// 写的是 cfg.RewriteDomains() 而不是 cfg.Domains：勾了「包含子域」的域名
	// 会多出一条 `*.域名`，AdGuard 的重写支持通配符，一条就盖住所有子域。
	//
	// 从 2026-11-18 起这张表上有**两块内容**：加速域名（答案是测速结果）和
	// GitHub hosts 源（答案是清单里写的地址）。它们共用一个 ReplaceRewrites，
	// 但边界写在 web/hosts.go 顶部：独立开关 + 独立账本，冲突时加速域名优先。
	rewriteNames := cfg.RewriteDomains()

	// hosts 源：只有配了 AdGuard 才去拉。没配 AdGuard 的话这几十条没地方写，
	// 每轮白拉一次外部链接只是给对方的站点添流量，日志里还多一行噪音。
	//
	// ctx 单独一个：上面那个的预算在测速和 v6 上已经花得差不多了，沿用它会
	// 一条都拉不回来（和出口探测那里同一个理由）。
	var hostsEntries map[string]string
	if cfg.AdGuard.URL != "" {
		hostsCtx, hostsCancel := context.WithTimeout(context.Background(), 40*time.Second)
		hostsEntries = s.resolveHosts(hostsCtx, cfg)
		hostsCancel()
	}

	// 这一轮允不允许改写 hosts 账本。只有真的动过 AdGuard 重写表（写成功）才
	// 更新；地址没填、或者压根没东西可写时保持原样，账本记的是「AdGuard 上
	// 现在有哪些是我的」，没动过表就不该动它。
	hostsLedgerOK := false

	needSync := len(rewriteNames) > 0 || len(hostsEntries) > 0 || len(cfg.HostsEntries) > 0
	if cfg.AdGuard.URL != "" && needSync {
		provider, perr := dns.New(cfg.AdGuard.Instance())
		if perr != nil {
			s.appendLog("AdGuard 写入失败: " + perr.Error())
		} else {
			want := rewritePlan(cfg, rewriteNames, rewriteAnswers(best, v6RoundIPs))
			hostsStat := mergeHostsWant(want, cfg, rewriteNames, hostsEntries)
			stats, werr := provider.ReplaceRewrites(want)
			if werr != nil {
				s.appendLog("写入 AdGuard 失败: " + werr.Error())
			} else {
				// 记下这一轮认领的域名：下次用户从列表里删掉某个域名时，
				// 靠这份账本才知道 AdGuard 上那条旧记录该清掉。
				s.rememberRewritten(rewriteNames)
				hostsLedgerOK = true
				wild := len(rewriteNames) - len(cfg.Domains)
				fam := "仅 IPv4"
				if len(v6RoundIPs) > 0 {
					fam = "IPv4 + IPv6"
				}
				if wild > 0 {
					s.appendLog(fmt.Sprintf("已写入 AdGuard：%d 条重写（%d 个域名，其中 %d 条子域通配符，%s）%s",
						stats.Written, len(cfg.Domains), wild, fam, keptNote(stats.Kept)))
				} else {
					s.appendLog(fmt.Sprintf("已写入 AdGuard：%d 条重写（%d 个域名，%s）%s",
						stats.Written, len(cfg.Domains), fam, keptNote(stats.Kept)))
				}
				// hosts 那一块单独说一句。合成一句会变成「已写入 AdGuard：70 条
				// （1 个域名…）」，用户数一下 AdGuard 里的条数对不上，还得自己猜
				// 那 69 条是从哪来的。只报非零项，一个「写入 0 条」纯属噪音。
				//
				// 这里说「进重写表」而不是「写入」：上面那句的数字是**这次真的
				// 动了多少条**（答案没变的不会重写），这一句是**这些域名归它管**。
				// 两个都用「写入」，就会出现「已写入 1 条」紧跟「写入 3 条」。
				var hp []string
				if hostsStat.added > 0 {
					hp = append(hp, fmt.Sprintf("%d 条进 AdGuard 重写表", hostsStat.added))
				}
				if hostsStat.skipped > 0 {
					hp = append(hp, fmt.Sprintf("%d 条与加速域名重名已跳过（用测速结果那个 IP）", hostsStat.skipped))
				}
				if hostsStat.cleared > 0 {
					hp = append(hp, fmt.Sprintf("清掉 %d 条不再归它管的", hostsStat.cleared))
				}
				if len(hp) > 0 {
					s.appendLog("hosts 源：" + strings.Join(hp, "，"))
				}
			}
		}
	} else if cfg.AdGuard.URL == "" {
		s.appendLog("未配置 AdGuard Home，跳过写入")
	}

	// 2) 推送域名解析（DDNS）
	//
	// 写几条由用户设定（默认 1 条）。注意 pushIPs 是「按排名截前 N」，
	// 而 cfg.LastIPs 存的是完整排名，用户之后把条数从 1 改成 5，点一下「立即更新
	// 一次」就能补齐，不用重跑测速。
	//
	// 按记录类型选来源：A 用 v4 排名，AAAA 用这一轮的 v6 排名。服务商那边两族是
	// 两张表，一次只能动一张，所以按族循环。某一族这轮没结果就只跳过那一族，
	// 绝不能拿 v4 地址去顶 AAAA（ddns 包的族校验会拦，这里先说明白更好读）。
	ddnsMode := cfg.DDNS.EffectiveRecordMode()
	families := ddns.FamiliesOf(ddnsMode)
	// ddnsWritten 是这一轮真的推上去的记录条数，只有历史那张表用。
	// 按族累加：A 和 AAAA 是两条记录集，各算各的。
	ddnsWritten := 0
	// writtenFamily 记这一轮真的写成功的是哪一族。单族模式靠它决定要不要清另一族：
	// 一族都没写上去时不能清，否则服务商那头一坏，域名会两头都空。
	writtenFamily := ""
	switch {
	case cfg.DDNS.Enabled && cfg.DDNS.Provider != "" && cfg.DDNS.Domain != "":
		missing := config.MissingCredentials(cfg.DDNS.Provider)
		if len(missing) > 0 {
			s.appendLog("域名解析未推送：缺少密钥 " + strings.Join(missing, ", "))
			break
		}
		creds := config.DDNCredentials()
		p, derr := ddns.New(cfg.DDNS.Provider, cfg.DDNS.Domain, creds)
		if derr != nil {
			s.appendLog("域名解析配置有误: " + derr.Error())
			break
		}
		for _, family := range families {
			source, familyNodes := res.IPs, nodes
			if family == ddns.TypeAAAA {
				source, familyNodes = v6RoundIPs, v6Nodes
			}
			pick := pickForWrite(source, familyNodes, cfg.DDNS.MinSpeedMbps, cfg.DDNS.EffectiveIPCount())
			pushIPs := pick.IPs
			if len(pushIPs) == 0 {
				// 绝不能拿空列表去「对齐」，ddns 包会把它当成「这次没结果，别动」，
				// 但日志里得如实说一句，否则用户会以为这一类记录已经更新过了。
				// 「测出来但全没到门槛」和「压根没测出节点」要分开说：前者该去
				// 改门槛，后者该去查测速，写成一句话会把人引到错误的方向。
				if pick.dropped() > 0 {
					s.appendLog(fmt.Sprintf("域名解析未推送 %s：%s，一条也没写（现有 %s 记录保持不变）",
						family, pick.skipReason(cfg.DDNS.MinSpeedMbps), family))
				} else {
					s.appendLog(fmt.Sprintf("域名解析未推送 %s：%s（现有 %s 记录保持不变）",
						family, emptySourceReason(family), family))
				}
				continue
			}
			if derr := p.EnsureRecords(cfg.DDNS.Domain, pushIPs, recordOptions(cfg.DDNS, family)); derr != nil {
				// 一族失败不打断另一族：Cloudflare 令牌权限、华为云的记录集
				// 覆盖都可能只影响其中一族，另一族没理由跟着不写。
				s.appendLog(fmt.Sprintf("域名解析推送 %s 失败: %s", family, derr.Error()))
				continue
			}
			msg := fmt.Sprintf("域名解析已更新：%s → %s（共 %d 条 %s 记录）",
				cfg.DDNS.Domain, strings.Join(pushIPs, "、"), len(pushIPs), family)
			if pick.dropped() > 0 {
				msg += "；另有 " + pick.skipReason(cfg.DDNS.MinSpeedMbps) + " 未写"
			}
			s.appendLog(msg)
			ddnsWritten += len(pushIPs)
			writtenFamily = family
		}
		// 单族模式要和用户的选择对齐：选了「只写 IPv4」，这个域名下就不该再留着 AAAA。
		// 放在写成功之后，理由见上面 writtenFamily 那段。
		if len(families) == 1 {
			s.pruneOtherFamily(p, cfg.DDNS.Domain, writtenFamily)
		}
	case len(res.IPs) == 0 && len(v6RoundIPs) == 0:
		s.appendLog("域名解析未推送：本次没有可用的 IP")
	}

	// 3) 记录结果
	s.mu.Lock()
	s.cfg.LastIP = best
	s.cfg.LastIPs = append(make([]string, 0, len(res.IPs)), res.IPs...)
	s.cfg.LastNodes = nodes
	s.cfg.LastTime = now
	// hosts 账本：只在真的动过 AdGuard 重写表之后才更新。写失败时保持原样，
	// 下一轮自然会再试一次，账本是自愈的，不需要人补救。这里不单独 Save，
	// 跟着下面这一整份配置一起落盘（每轮本来就要写一次 last_ip/last_time）。
	if hostsLedgerOK {
		s.cfg.HostsEntries = hostsEntries
		s.cfg.HostsSyncedAt = ""
		if len(hostsEntries) > 0 {
			s.cfg.HostsSyncedAt = now
		}
	}
	s.lastDurSec = int(time.Since(startedAt).Seconds())
	toSave := s.cfg.Clone()
	s.mu.Unlock()

	if err := toSave.Save(); err != nil {
		log.Printf("保存配置失败: %v", err)
	}

	// 历史放在最后记：走到这里「写了多少条、花了多久」才都定下来。
	// nodes 和 cfg.LastNodes 是同一个底层数组，历史要自己拷一份，
	// 否则以后谁在配置那份上原地改一格，历史里的数字会跟着变。
	var bSpeed, bDelay float64
	if len(nodes) > 0 {
		bSpeed, bDelay = nodes[0].Speed, nodes[0].Delay
	}
	s.recordRound(startedAt, roundRecord{
		At:      now,
		Trigger: trigger,
		OK:      true,
		Best:    best,
		Speed:   bSpeed,
		Delay:   bDelay,
		Written: ddnsWritten,
		Nodes:   append([]config.NodeStat(nil), nodes...),
		V6Nodes: v6Nodes,
	})
	return nil
}

// StartScheduler 启动定时测速。
//
// nextRunAt 在这里算并暴露给界面。算的是「真的要跑的时刻」，不是「间隔」，
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
			_ = s.runOnce(cfg, triggerTimer)
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
