// cf-ddns-sidecar —— 一个容器搞定：Cloudflare 优选 IP + AdGuard Home 重写 + 域名解析（DDNS）
//
// 测速引擎复用 xinyitang3/cfnb（MIT），本程序负责统一配置、写入 AdGuard Home、
// 推送四家 DNS 服务商，以及一个统一的后台界面。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/303528084/cf-ddns-sidecar/config"
	"github.com/303528084/cf-ddns-sidecar/web"
)

var version = "dev"

func main() {
	web.SetVersion(version)

	var (
		listen   string
		printVer bool
		runOnce  bool
	)
	flag.StringVar(&listen, "listen", defaultListen(), "后台监听地址")
	flag.BoolVar(&runOnce, "once", false, "只跑一次测速并写入后退出（可用于 cron）")
	flag.BoolVar(&printVer, "v", false, "打印版本")
	flag.Parse()

	if printVer {
		fmt.Println("cf-ddns-sidecar " + version)
		return
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	// 用户在飞牛「应用设置」里改过域名/服务商/间隔：把一次性覆盖落盘并清标记，
	// 之后仍以后台界面为准，避免两边互相覆盖。
	if cfg.PendingSave {
		if err := cfg.Save(); err != nil {
			log.Printf("[警告] 保存安装向导配置失败: %v", err)
		} else if err := config.UpdateEnvFile(config.EnvFilePath(),
			map[string]string{"CFDDNS_APPLY_ENV": "0"}); err != nil {
			log.Printf("[警告] 清理配置覆盖标记失败: %v", err)
		}
	}

	// 配置文件路径：默认与 ddns.env 同目录的 config.json
	configDir := filepath.Dir(config.EnvFilePath())
	configPath := filepath.Join(configDir, "config.json")
	if p := os.Getenv("CFDDNS_CONFIG"); p != "" {
		configPath = p
		configDir = filepath.Dir(p)
	}

	enginePath := os.Getenv("CFDDNS_ENGINE")
	if enginePath == "" {
		enginePath = "/app/cfnb/main.py"
	}
	workDir := os.Getenv("CFDDNS_WORKDIR")
	if workDir == "" {
		workDir = filepath.Join(configDir, "cfnb")
	}

	password := os.Getenv("DSA_PASSWORD")
	if password == "" {
		// 优先读安装时生成的固定密码，避免每次重启都换
		if b, err := os.ReadFile(filepath.Join(configDir, "dashboard-password")); err == nil {
			password = string(b)
		}
	}

	srv := web.New(cfg, configPath, enginePath, workDir, password, selfURL(listen), mustCIDRs())

	if runOnce {
		// 测速引擎要回调本进程的 /api/candidates 拿候选 IP（内置 Cloudflare 官方段），
		// 所以哪怕只跑一次也得先把 HTTP 服务拉起来。否则本地源不可用，
		// 只能依赖第三方聚合源，源挂了就会「没有产出可用 IP」。
		onceServer := &http.Server{
			Addr:              listen,
			Handler:           srv.Handler(),
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			if err := onceServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("[提示] 候选列表服务未启动（%v），本次只能依赖第三方数据源", err)
			}
		}()
		// 等端口真正进入监听，避免引擎的第一跳请求扑空
		waitListening(listen, 2*time.Second)

		err := srv.RunOnce()
		_ = onceServer.Close()
		if err != nil {
			log.Fatalf("测速失败: %v", err)
		}
		return
	}

	if password == "" {
		fmt.Println("[提示] 未设置后台密码，后台将不校验登录。可在「应用设置」里设置管理密码。")
	}

	srv.StartScheduler()

	httpServer := &http.Server{
		Addr:              listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	fmt.Printf("\n==============================================\n")
	fmt.Printf("  cf-ddns-sidecar %s\n", version)
	fmt.Printf("  后台地址: http://<本机IP>%s/\n", listen)
	fmt.Printf("  允许来源网段: %s\n", os.Getenv("DSA_ALLOWED_CIDRS"))
	fmt.Printf("==============================================\n\n")

	done := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		<-sig
		fmt.Println("\n收到退出信号，正在关闭…")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
		close(done)
	}()

	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("后台服务启动失败: %v", err)
	}
	<-done
	fmt.Println("已退出。")
}

// waitListening 等端口进入监听状态（最多等 timeout），用于 -once 模式。
// 端口起不来也不报错，让后面的测速自己走降级路径。
func waitListening(listen string, timeout time.Duration) {
	target := listen
	host, port, err := net.SplitHostPort(listen)
	if err == nil {
		if host == "" || host == "0.0.0.0" || host == "::" {
			host = "127.0.0.1"
		}
		target = net.JoinHostPort(host, port)
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, derr := net.DialTimeout("tcp", target, 200*time.Millisecond)
		if derr == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// defaultListen 决定后台监听端口。优先级：CFDDNS_PORT 环境变量 →
// ddns.env 里的 CFDDNS_PORT → 8080。
//
// 为什么要可配：8080 很容易和 NAS 上别的服务撞车，用户在安装向导或
// 「应用设置」里改了端口后，安装脚本会把 ddns.env 和桌面入口一起改掉，
// 这里负责让程序真的监听那个端口。
func defaultListen() string {
	port := strings.TrimSpace(os.Getenv("CFDDNS_PORT"))
	if port == "" {
		port = strings.TrimSpace(config.LoadEnvFile(config.EnvFilePath())["CFDDNS_PORT"])
	}
	if n, err := strconv.Atoi(port); err == nil && n > 0 && n < 65536 {
		return ":" + port
	}
	return ":8080"
}

// mustCIDRs 解析来源网段；配置非法时拒绝启动（避免后台意外暴露到公网）。
func mustCIDRs() []*net.IPNet {
	cidrs, err := web.ParseCIDRs(os.Getenv("DSA_ALLOWED_CIDRS"))
	if err != nil {
		log.Fatalf("[安全门禁] %v", err)
	}
	return cidrs
}

// selfURL 把监听地址转成本机可访问的 URL，供测速引擎拉候选列表。
// ":8080" / "0.0.0.0:8080" 都转成 http://127.0.0.1:8080。
func selfURL(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "http://127.0.0.1:8080"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port)
}
