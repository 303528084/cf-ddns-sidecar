package web

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 来源识别、登录限流、安全响应头这三件事，跟业务无关，但一改就得一起想清楚：
//   1) 分清「真本机调用」和「经反代/隧道进来的请求」；
//   2) 登录失败限流（没有它，密码就是唯一的一道门，而爆破脚本是并行的）；
//   3) 安全响应头。
//
// 为什么单独一个文件：这三样散在 server.go 里容易被后来的人漏看。

// ---------- 来源识别 ----------

// isTrustedProxy 判断这条连接是不是「我们自己的反代/隧道」发起的。
//
// 为什么重要：cloudflared（Cloudflare Tunnel）和反向代理通常都跑在同一台机器上，
// 于是**所有**外部请求在程序眼里都来自 127.0.0.1。
// 如果代码只看 RemoteAddr 判断「是不是本机」，那就等于对外网敞开。
func isTrustedProxy(r *http.Request) bool {
	ip := net.ParseIP(hostOnly(r.RemoteAddr))
	return ip != nil && ip.IsLoopback()
}

func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// clientIP 取「真实访问者的 IP」。
//
// 只有在连接来自本机（反代/隧道）时才采信转发头。原因：攻击者直连本机端口时，
// 可以随便伪造 X-Forwarded-For，每次换一个「IP」，限流就形同虚设。
func clientIP(r *http.Request) string {
	if isTrustedProxy(r) {
		if v := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); v != "" {
			return v
		}
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			if i := strings.IndexByte(v, ','); i > 0 {
				return strings.TrimSpace(v[:i])
			}
			return strings.TrimSpace(v)
		}
		if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
			return v
		}
	}
	return hostOnly(r.RemoteAddr)
}

// isLocalRequest 判断这是不是真正的「进程内调用」，目前只有测速引擎
// （cfnb 子进程）回调 /api/candidates 这一处。
//
// 只看 RemoteAddr 不够：加了隧道或反代之后，公网请求在程序眼里同样是 127.0.0.1。
// 所以额外要求「没有任何转发头」：真正的进程内 HTTP 调用不会加这些头，
// 而 cloudflared / Caddy / Nginx 一定会加。
func isLocalRequest(r *http.Request) bool {
	if !isTrustedProxy(r) {
		return false
	}
	for _, h := range []string{"X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP", "Forwarded"} {
		if r.Header.Get(h) != "" {
			return false
		}
	}
	return true
}

// isHTTPS 判断「用户浏览器到本服务」这一段是不是加密的。
// 用于决定要不要给会话 Cookie 打 Secure 标记：HTTP 下打了 Secure 浏览器就不发 Cookie，
// 会导致「登录成功但下一个请求又 401」。
func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	// Cloudflare Tunnel / 常见反代都会带这个头标明原始协议。
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// loginFailDelay 是密码错误时故意拖的时间。抽成变量是为了测试能把它调成 0，
// 否则测「连续失败 5 次被锁」要等 2.5 秒。
var loginFailDelay = 500 * time.Millisecond

// ---------- 登录失败限流 ----------

const (
	throttleMaxFail    = 5               // 连续失败几次开始锁
	throttleBaseLock   = 5 * time.Minute // 第一次锁多久
	throttleMaxLock    = time.Hour       // 锁定时间的上限
	throttleForget     = 24 * time.Hour  // 这么久没动静就丢掉这条记录
	throttleSweepEvery = 256             // 每这么多次调用顺手清理一遍过期记录
)

type failState struct {
	fails    int       // 本轮连续失败次数
	level    int       // 已经锁过几次，决定下次锁多久（指数退避）
	lockedTo time.Time // 锁到什么时候
	lastSeen time.Time
}

// loginThrottle 按来源 IP 限制登录失败次数。
//
// 为什么必须有：原来只在密码错误时 sleep 500ms。单线程爆破确实会被拖慢，
// 但爆破脚本是并发的，同时开 20 路，每秒就能试 40 个密码。
// 这台机器要是摆在反代或隧道后面，弱密码几分钟就会被猜中，而拿到后台
// 等于把 DNS 解析和各家 API 密钥一起交出去。
type loginThrottle struct {
	mu    sync.Mutex
	state map[string]*failState
	calls int
	// now 可注入，测试里用来「快进时间」，否则锁 5 分钟这种逻辑没法验证。
	now func() time.Time
}

func newLoginThrottle() *loginThrottle {
	return &loginThrottle{state: make(map[string]*failState), now: time.Now}
}

// allow 返回是否放行；被锁时同时给出还要等多久。
func (t *loginThrottle) allow(ip string) (bool, time.Duration) {
	now := t.now()

	t.mu.Lock()
	defer t.mu.Unlock()

	t.calls++
	if t.calls%throttleSweepEvery == 0 {
		t.sweepLocked(now)
	}

	st := t.state[ip]
	if st == nil {
		return true, 0
	}
	st.lastSeen = now
	if now.Before(st.lockedTo) {
		return false, st.lockedTo.Sub(now)
	}
	return true, 0
}

// fail 记一次失败；攒够阈值就锁，之后每再失败一轮锁定时间翻倍。
func (t *loginThrottle) fail(ip string) {
	now := t.now()

	t.mu.Lock()
	defer t.mu.Unlock()

	st := t.state[ip]
	if st == nil {
		st = &failState{}
		t.state[ip] = st
	}
	st.lastSeen = now
	st.fails++
	if st.fails < throttleMaxFail {
		return
	}

	lock := throttleBaseLock
	for i := 0; i < st.level; i++ {
		lock *= 2
		if lock >= throttleMaxLock {
			lock = throttleMaxLock
			break
		}
	}
	st.lockedTo = now.Add(lock)
	st.fails = 0
	st.level++
}

// reset 在登录成功后清掉这个 IP 的记录，正常用户不该因为偶尔手滑被越锁越久。
func (t *loginThrottle) reset(ip string) {
	t.mu.Lock()
	delete(t.state, ip)
	t.mu.Unlock()
}

func (t *loginThrottle) sweepLocked(now time.Time) {
	for ip, st := range t.state {
		if now.Sub(st.lastSeen) > throttleForget {
			delete(t.state, ip)
		}
	}
}

// ---------- 安全响应头 ----------

// securityHeaders 给所有响应加安全头。
//
// 特别注意：这里**绝对不能**加 X-Frame-Options，CSP 里也不能写
// frame-ancestors 'none' / 'self'。飞牛桌面是用 iframe 嵌入本后台的，
// 一旦禁止被嵌入，用户点桌面图标就是一片白（v1.0.0 刚因为「图标指错端口」
// 白过一次，不能再自己制造一次）。
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		// 前端是单文件、内联 <style>/<script>（见 web/static/index.html），
		// 所以必须放开 inline；其余一律限同源，挡住外部脚本。
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; "+
				"connect-src 'self'; "+
				"base-uri 'self'; "+
				"form-action 'self'; "+
				"frame-ancestors *")
		next.ServeHTTP(w, r)
	})
}

// ---------- 登录限流用到的响应辅助 ----------

func writeTooManyAttempts(w http.ResponseWriter, wait time.Duration) {
	secs := int(wait.Seconds()) + 1
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeJSON(w, http.StatusTooManyRequests, map[string]string{
		"error": fmt.Sprintf("密码错误次数过多，请 %d 秒后再试", secs),
	})
}
