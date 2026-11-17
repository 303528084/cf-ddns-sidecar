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
	"io"
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

	"github.com/303528084/cf-ddns-sidecar/applog"
	"github.com/303528084/cf-ddns-sidecar/config"
	"github.com/303528084/cf-ddns-sidecar/web"
)

var version = "dev"

func main() {
	web.SetVersion(version)

	// 数据目录要先算出来：运行日志落在里面，而且必须在最早那几条日志
	// （安装向导播种端口/密码）之前接好——否则排查「设置没生效」时最关键的
	// 那两行恰好不在文件里，等于白落盘。
	configDir := dataDir()
	logFile := setupLogFile(configDir)
	if logFile != nil {
		defer logFile.Close()
	}

	// 升级窗口最坏的情况：数据目录整个被平台删了（2026-11-17 第二次事故）。
	// 宿主机脚本 cmd/upgrade_init 在升级前把配置备到了 /var/apps/<app>-backup/<时间>，
	// 这里趁还没人往数据目录里写过 config.json，把最新那份搬回来。
	//
	// 为什么恢复必须在程序里做、而不是让宿主机脚本自己恢复：容器是 appcenter
	// 先拉起来的，cmd/main start 跑得更晚——等它动手，程序早就用空配置起来了
	// （证据：那次日志里「已把安装向导里设的密码写入…」是程序自己打的，
	// 宿主机脚本本该生成的那份 16 位随机密码根本没出现过）。
	//
	// 顺序也很关键：必须在 seedFromWizardEnv() 之前。恢复会连
	// .wizard-env-applied 一起搬回来，种子函数看到标记就直接退出，
	// 不会拿容器里烘死的旧端口/旧密码把刚恢复的内容再盖一遍。
	if src := config.RestoreFromUpgradeBackup(); src != "" {
		log.Printf("[警告] 数据目录是空的，已从升级前的自动备份恢复：%s", src)
	}

	// 必须放在最前面：-listen 的默认值在 flag.Parse 之前就已求值（看 defaultListen），
	// 所以安装向导的端口种子得先落进 ddns.env，否则程序会按旧端口起监听。
	seedFromWizardEnv()

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
	// 主配置不见了但备份还在：说明有东西动过数据目录（升级、清理脚本、误删）。
	// 必须显式说出来——静默恢复等于让用户以为一切正常。
	//
	// 两种情况分开说，因为严重程度和「用户该做什么」不一样：
	//   · 连 config.json.bak 都没了，靠外面那份备份救的 → 整个目录被删过，最严重；
	//   · .bak 还在 → 只是主文件丢了，还算温和。
	if cfg.RestoredFromUpgradeBackup {
		src := config.RestoreMarkerSource()
		if src == "" {
			src = "升级前的自动备份"
		}
		log.Printf("[警告] 升级期间数据目录被清空了，已从升级前的自动备份恢复（来源 %s）。"+
			"请核对后台里的 AdGuard 地址、要加速的域名、同步几条 IP 和各家密钥是否完整；"+
			"核对无误后点一次「保存全部设置」，页面顶上的红条就会消失", src)
	} else if cfg.RestoredFromBackup {
		log.Printf("[警告] config.json 不见了，已从 config.json.bak 恢复。" +
			"请核对后台里的 AdGuard 地址、要加速的域名和各家密钥是否完整")
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
	configPath := configFilePath(configDir)

	enginePath := os.Getenv("CFDDNS_ENGINE")
	if enginePath == "" {
		enginePath = "/app/cfnb/main.py"
	}
	workDir := os.Getenv("CFDDNS_WORKDIR")
	if workDir == "" {
		workDir = filepath.Join(configDir, "cfnb")
	}

	passFile := filepath.Join(configDir, "dashboard-password")
	password, passSource := resolvePassword(passFile)

	// 密码太弱就在启动日志里明说。后台对所有 IP 开放，这是唯一一道门，
	// 而「应用设置」里的密码框没有任何校验，填 123456 也能保存成功。
	// 这里不拒绝启动（把人锁在外面更糟），只提示，并让界面顶上挂一条黄条。
	if reason := web.WeakPasswordReason(password); reason != "" {
		if passSource == "env" {
			log.Printf("[警告] 后台登录密码%s。这个后台对所有 IP 开放，建议改环境变量 DSA_PASSWORD 换一个 8 位以上、不重复不连续的密码", reason)
		} else {
			log.Printf("[警告] 后台登录密码%s。这个后台对所有 IP 开放，请在后台页面的「登录密码」里换一个", reason)
		}
	}

	srv := web.New(cfg, configPath, enginePath, workDir, web.Auth{
		Env:      strings.TrimSpace(os.Getenv("DSA_PASSWORD")),
		File:     passFile,
		Fallback: password,
	}, selfURL(listen), logFile)

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

	srv.StartScheduler()

	httpServer := &http.Server{
		Addr:              listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	banner := buildBanner(version, listen, password, passSource, configDir)
	for _, ln := range banner {
		fmt.Println(ln)
	}
	if logFile != nil {
		// 启动横幅也抄一份进日志文件：翻 app.log 时才能知道这次跑的是哪个版本、
		// 用的哪个端口、诊断记录说了什么。时间戳只加在整块开头，和 log 包对
		// 一次带换行的输出只打一个前缀的行为保持一致。
		logFile.Line(time.Now().Format("2006/01/02 15:04:05") + " " + strings.Join(banner, "\n"))
	}

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

	// 端口热切换：脚本改不了容器（没有 docker 权限），但程序能改自己。
	go watchPortChange(config.EnvFilePath(), listen, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
		close(done)
	})

	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("后台服务启动失败: %v", err)
	}
	<-done
	fmt.Println("已退出。")
}

// watchPortChange 盯着 ddns.env 里的 CFDDNS_PORT，变了就优雅退出，
// 由 Docker（compose 里 restart: unless-stopped）用新端口重新拉起。
//
// 为什么要程序自己退出，而不是让安装脚本 `docker restart`：
// 飞牛的生命周期脚本以 run-as: package 运行，通常拿不到 docker 权限，
// 那条 restart 命令经常静默失败。结果是用户在安装向导/应用设置里改了端口，
// ddns.env 和桌面图标都改了，进程却还在老端口上跑——点图标打不开，
// 看起来就像「设置没生效」。程序自己退出是最可靠的触发方式。
//
// 只在端口真的变了才退出：启动时按 ddns.env 决定监听端口，所以重启后
// 新端口 == 当前端口，条件不成立，不会反复重启。
func watchPortChange(envFile, listen string, shutdown func()) {
	_, cur, err := net.SplitHostPort(listen)
	if err != nil {
		cur = strings.TrimPrefix(listen, ":")
	}

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		want := strings.TrimSpace(config.LoadEnvFile(envFile)["CFDDNS_PORT"])
		n, err := strconv.Atoi(want)
		if err != nil || n < 1 || n > 65535 || want == cur {
			continue
		}
		log.Printf("[信息] 检测到后台端口已改为 %s（当前 %s），正在自动重启以生效…", want, cur)
		shutdown()
		time.Sleep(1500 * time.Millisecond) // 让 HTTP 服务把响应吐完
		os.Exit(0)
	}
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

// defaultListen 决定后台监听端口。优先级：ddns.env 里的 CFDDNS_PORT →
// CFDDNS_PORT 环境变量 → 8080。
//
// 为什么**文件优先于环境变量**（这里曾经反着来，会引发无限重启）：
// 安装向导的值会通过 compose 的 ${wizard_port} 变成容器环境变量，而容器环境
// 变量一旦建好就不会再变。如果环境变量优先，用户在「应用设置」里把端口改成
// 9090 之后，程序重启时又会从环境变量读到安装时的旧值（比如 8080），于是
// 监听 8080 → 发现 ddns.env 是 9090 → 退出 → 重启 → 又读旧值……死循环。
// 现在安装时的值只当「种子」写进 ddns.env 一次，之后一律以文件为准。
func defaultListen() string {
	port := strings.TrimSpace(config.LoadEnvFile(config.EnvFilePath())["CFDDNS_PORT"])
	if !isPort(port) {
		port = strings.TrimSpace(os.Getenv("CFDDNS_PORT"))
	}
	if isPort(port) {
		return ":" + port
	}
	return ":8080"
}

// isPort 判断字符串是不是 1-65535 的合法端口号。
func isPort(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n > 0 && n < 65536
}

// seedFromWizardEnv 把安装向导里填的端口和密码落盘，只做一次。
//
// 为什么需要这一步：飞牛不是执行 `docker compose up`，而是通过 Docker 接口
// 建容器，而且在 install_callback 之前容器就已经建好跑起来了。所以在回调
// 脚本里写文件、再重启让它生效，时机上永远晚一步。飞牛唯一保证会做的，是
// 建容器之前对 compose 里的 ${wizard_xxx} 做变量替换。于是 compose 里放了
// 两个占位符（CFDDNS_PORT / CFDDNS_PASSWORD_SEED），由这里落成文件。
//
// 为什么只做一次（marker 文件）：环境变量一旦烘进容器就不再变。如果每次都
// 用环境变量覆盖文件，用户在「应用设置」里改完端口，重启后又被改回安装时的
// 旧值，会无限重启。
func seedFromWizardEnv() {
	configDir := filepath.Dir(config.EnvFilePath())
	if p := os.Getenv("CFDDNS_CONFIG"); p != "" {
		configDir = filepath.Dir(p)
	}

	marker := filepath.Join(configDir, ".wizard-env-applied")
	if _, err := os.Stat(marker); err == nil {
		return
	}

	if port := strings.TrimSpace(os.Getenv("CFDDNS_PORT")); isPort(port) {
		envFile := config.EnvFilePath()
		if cur := strings.TrimSpace(config.LoadEnvFile(envFile)["CFDDNS_PORT"]); cur != port {
			if err := config.UpdateEnvFile(envFile, map[string]string{"CFDDNS_PORT": port}); err != nil {
				log.Printf("[警告] 安装向导端口 %s 未能写入 ddns.env：%v", port, err)
			} else {
				log.Printf("[信息] 已把安装向导里填的端口 %s 写入 ddns.env", port)
			}
		}
	}

	if seed := os.Getenv("CFDDNS_PASSWORD_SEED"); strings.TrimSpace(seed) != "" {
		passFile := filepath.Join(configDir, "dashboard-password")
		cur, _ := os.ReadFile(passFile)
		if strings.TrimSpace(string(cur)) == "" {
			if err := os.WriteFile(passFile, []byte(seed), 0o644); err != nil {
				log.Printf("[警告] 安装向导密码未能写入 %s：%v", passFile, err)
			} else {
				log.Printf("[信息] 已把安装向导里设的密码写入 %s（%d 位）", passFile, len(seed))
			}
		}
	}

	// 无论有没有值都记标记：留空本身就等于「不用种子」，之后走文件那条路。
	if err := os.WriteFile(marker, []byte(time.Now().Format(time.RFC3339)+"\n"), 0o644); err != nil {
		log.Printf("[提示] 无法写入标记 %s：%v（下次启动会再试一次，无副作用）", marker, err)
	}
}

// printInstallDebug 把 config_callback 留下的诊断日志转述到运行日志。
//
// 飞牛不会收集生命周期脚本的标准输出，所以脚本内部出问题时用户在界面上
// 什么都看不到。脚本把「这次收到了哪几个向导变量」写进 install-debug.log，
// 这里读出来打印——用户看「应用中心 → 运行日志」就能判断是「值没送到脚本」
// 还是「送到了但写不进去」，不用碰命令行。
func installDebugLines(configDir string) []string {
	p := filepath.Join(configDir, "install-debug.log")
	b, err := os.ReadFile(p)
	if err != nil {
		return []string{"  [诊断] 暂无 config_callback 记录（安装/设置向导尚未提交过）"}
	}
	lines := strings.Split(strings.TrimRight(string(b), "\r\n"), "\n")
	const keep = 14
	out := make([]string, 0, keep+1)
	if len(lines) > keep {
		lines = lines[len(lines)-keep:]
		out = append(out, "  [诊断] config_callback 最近记录（只显示最后 14 行）:")
	} else {
		out = append(out, "  [诊断] config_callback 记录:")
	}
	for _, ln := range lines {
		out = append(out, "  "+ln)
	}
	return out
}

// buildBanner 生成启动横幅的每一行。
//
// 单独抽出来是为了能同时打到控制台和写进日志文件：以前这里只走 stdout，
// 而飞牛的「运行日志」里看不到，用户问「我现在是哪个版本」时无从回答。
func buildBanner(ver, listen, password, passSource, configDir string) []string {
	lines := []string{
		"==============================================",
		"  cf-ddns-sidecar " + ver,
		"  后台地址: http://<本机IP>" + listen + "/",
	}
	switch passSource {
	case "generated":
		lines = append(lines, "  登录密码: "+password+"（本次自动生成，可复制；在后台页面「登录密码」里重设后立即以新密码为准）")
	case "file":
		lines = append(lines, "  登录密码: 安装时设置的那个（忘了可在后台页面「登录密码」里重设）")
	default:
		lines = append(lines, "  登录密码: 由环境变量 DSA_PASSWORD 指定")
	}
	lines = append(lines,
		"  改密码: 在后台页面「登录密码」里保存即生效，无需重启",
		"  访问限制: 无，所有 IP 均可打开后台（请务必设置登录密码）",
		"  日志文件: "+filepath.Join(configDir, "app.log")+"（超过 2MB 自动轮转，留一份 .1 历史）",
	)
	lines = append(lines, installDebugLines(configDir)...)
	lines = append(lines, "==============================================", "")
	return lines
}

// dataDir 返回数据目录。CFDDNS_CONFIG 指向具体的配置文件时，以它的所在目录为准；
// 否则就是 ddns.env 的所在目录（容器里是 /app/data）。
func dataDir() string {
	if p := strings.TrimSpace(os.Getenv("CFDDNS_CONFIG")); p != "" {
		return filepath.Dir(p)
	}
	return filepath.Dir(config.EnvFilePath())
}

// configFilePath 返回 config.json 的路径。CFDDNS_CONFIG 是精确覆盖，优先于推导。
func configFilePath(configDir string) string {
	if p := strings.TrimSpace(os.Getenv("CFDDNS_CONFIG")); p != "" {
		return p
	}
	return filepath.Join(configDir, "config.json")
}

// setupLogFile 打开数据目录下的 app.log，并让所有 log.* 输出同时进文件和控制台。
//
// 打开失败不算致命：退回「日志只在界面内存里」的老样子，但要明确告诉用户，
// 否则他会以为日志已经存下来了，等重启后一片空白才发现没有。
func setupLogFile(configDir string) *applog.Log {
	p := filepath.Join(configDir, "app.log")
	lf, err := applog.Open(p, 0)
	if err != nil {
		log.Printf("[警告] 运行日志无法写入 %s（%v）：本次日志只在界面上显示，重启后会清空", p, err)
		return nil
	}
	log.SetOutput(io.MultiWriter(os.Stderr, lf))
	return lf
}

// resolvePassword 决定后台登录密码的兜底值，返回密码与来源标记（env / file / generated）。
//
// 为什么没有「空密码 = 免登录」这一档：后台现在对所有来源 IP 开放，
// 空密码等于谁都能进来改你的 DNS 解析记录。所以读不到密码就现生成一个，
// 打印在启动日志里，并尽量落盘，保证重启后还是同一个。
//
// 注意：这里读到的只是**启动时**的值，真正校验时由 web.Auth.Current()
// 每次重读 passFile。用户在安装向导/应用设置里改了密码，即使容器没被重启，
// 下一次登录也会按新密码比对。
func resolvePassword(passFile string) (string, string) {
	if v := strings.TrimSpace(os.Getenv("DSA_PASSWORD")); v != "" {
		return v, "env"
	}

	if b, err := os.ReadFile(passFile); err == nil {
		if v := strings.TrimSpace(string(b)); v != "" {
			return v, "file"
		}
	}

	v, err := web.RandomPassword()
	if err != nil {
		log.Fatalf("生成后台密码失败: %v", err)
	}
	if err := os.WriteFile(passFile, []byte(v), 0o644); err != nil {
		log.Printf("[警告] 初始密码无法保存到 %s：%v", passFile, err)
		log.Printf("[警告] 当前密码是临时的，重启应用后会变；建议立刻在「应用设置」里设置固定密码")
	}
	return v, "generated"
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
