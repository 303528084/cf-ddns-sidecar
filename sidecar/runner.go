package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/stone/cf-ddns-sidecar/config"
	"github.com/stone/cf-ddns-sidecar/provider"
)

// state 是持久化到磁盘的推送状态。
type state struct {
	LastPushedIP string `json:"last_pushed_ip"`
	Domain       string `json:"domain"`
	UpdatedAt    string `json:"updated_at"`
}

// Runner 编排轮询、更新与状态持久化。
//
// Tick 仅应在主循环 goroutine 内调用（Observer 非并发安全）。
type Runner struct {
	cfg       *config.Config
	observer  *Observer
	provider  provider.Provider
	statePath string
	mu        sync.Mutex
	st        state
	healthy   bool
	// lastWaitLog 记录上一次输出的等待原因，用于节流 EventNone 日志。
	lastWaitLog string
}

// NewRunner 构造 Runner，并从状态文件恢复上次推送的 IP。
func NewRunner(cfg *config.Config, p provider.Provider) (*Runner, error) {
	r := &Runner{
		cfg:       cfg,
		observer:  NewObserver(cfg.SubjectConfigPath),
		provider:  p,
		statePath: cfg.StatePath,
		healthy:   true,
	}
	if err := r.loadState(); err != nil {
		return nil, err
	}
	r.observer.Seed(r.st.LastPushedIP)
	return r, nil
}

func (r *Runner) loadState() error {
	data, err := os.ReadFile(r.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("读取状态文件失败: %w", err)
	}
	if err := json.Unmarshal(data, &r.st); err != nil {
		log.Printf("[警告] 状态文件损坏，忽略: %v", err)
		r.st = state{}
	}
	return nil
}

func (r *Runner) saveState(ip string) error {
	r.st = state{LastPushedIP: ip, Domain: r.cfg.Domain, UpdatedAt: time.Now().Format(time.RFC3339)}
	if dir := filepath.Dir(r.statePath); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(r.st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(r.statePath, data, 0o644)
}

// tickTimeout 必须大于单个 Provider 的最坏总耗时：
// 各 Provider 的 HTTP client 超时为 15s，一次 EnsureARecord 最多串行
// 两次调用（查询 + 写入）= 30s，故外层取 35s 作为兜底。
const tickTimeout = 35 * time.Second

// Tick 执行一轮读取与更新。推送失败或超时不确认（不 Ack、不保存状态），
// 下一轮 Read 仍会返回事件，从而自动重试。
func (r *Runner) Tick() {
	ev := r.observer.Read()
	if ev.Kind == EventNone || ev.IP == "" {
		if ev.Detail != "" && ev.Detail != r.lastWaitLog {
			r.lastWaitLog = ev.Detail
			log.Printf("[等待] %s", ev.Detail)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), tickTimeout)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- r.provider.EnsureARecord(r.cfg.Domain, ev.IP) }()

	select {
	case err := <-done:
		if err != nil {
			r.mu.Lock()
			r.healthy = false
			r.mu.Unlock()
			log.Printf("[错误] 更新 %s 的 A 记录到 %s 失败: %v（下一轮自动重试）", r.cfg.Domain, ev.IP, err)
			return
		}
		if err := r.saveState(ev.IP); err != nil {
			log.Printf("[错误] 保存状态失败: %v（下轮重推以保证一致）", err)
			return
		}
		r.observer.Ack(ev.IP)
		r.mu.Lock()
		r.healthy = true
		r.mu.Unlock()
		log.Printf("[成功] %s 的 A 记录已更新为 %s（%s）", r.cfg.Domain, ev.IP, r.provider.Name())
	case <-ctx.Done():
		r.mu.Lock()
		r.healthy = false
		r.mu.Unlock()
		log.Printf("[错误] 更新 %s 超时（%s），下一轮自动重试", r.cfg.Domain, ev.IP)
	}
}

// healthMux 返回 /healthz 路由（供 Run 与测试共用同一实现）。
func (r *Runner) healthMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		r.mu.Lock()
		ok := r.healthy
		r.mu.Unlock()
		if !ok {
			http.Error(w, "unhealthy", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

// Run 启动轮询、健康检查与优雅关闭，阻塞直到收到退出信号。
func (r *Runner) Run() error {
	srv := &http.Server{Addr: r.cfg.Listen, Handler: r.healthMux()}

	go func() {
		log.Printf("健康检查监听 %s", r.cfg.Listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[错误] 健康检查服务异常: %v", err)
		}
	}()

	log.Printf("DDNS 旁路已启动：服务商=%s 域名=%s 轮询间隔=%ds 读取=%s",
		r.cfg.Provider, r.cfg.Domain, r.cfg.PollIntervalSeconds, r.cfg.SubjectConfigPath)
	r.Tick()

	ticker := time.NewTicker(r.cfg.PollInterval())
	defer ticker.Stop()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			r.Tick()
		case <-sigCh:
			log.Println("收到退出信号，正在关闭...")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			return srv.Shutdown(ctx)
		}
	}
}
