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
	//
	// v1.5.1：光看「数据目录是空的」会误判。2026-11-17 20:56 的真机日志就踩了这个：
	// 数据目录不是被删，而是**换到了飞牛官方的 @appdata 下**，新目录天然是空的，
	// 于是同一段代码打出了「升级期间数据目录被清空了」——把一次正常的换位置
	// 说成了事故。两种情形要分开说，判据是 compose 有没有把宿主机路径传进来。
	// v1.6.5：这里原来有一次「从 v1.4.x 旧数据目录搬配置」的调用
	// （config.MigrateFromLegacyData）。删掉的理由有两条，缺一条都不敢动：
	//   1. 它要读的旧目录由 compose 只读挂载进来，而那个挂载已经一起删了
	//      ——留着调用等于读一个永远不存在的路径；
	//   2. 它只对「从 v1.4.x 跳版升级到 v1.6.x」有意义。这个应用只有作者本人在用，
	//      不存在跳版升级的用户。
	// 真机上它本来就一次都没执行过（v1.5.1 验收时就是「新目录已有配置，正确跳过」）。
	//
	// 直接放在下面这次恢复之前的位置保持不变：恢复仍然要求「数据目录里没有
	// config.json」，只是不再先试一次搬迁。

	if src := config.RestoreFromUpgradeBackup(); src != "" {
		if host := dataHostPath(); host != "" {
			log.Printf("[信息] 数据目录已换到飞牛官方位置（%s），新目录是空的，"+
				"已从最近一次自动备份恢复：%s", host, src)
		} else {
			log.Printf("[警告] 数据目录是空的，已从升级前的自动备份恢复：%s", src)
		}
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
		if host := dataHostPath(); host != "" {
			// 换成官方目录后的正常路径：说清「换了位置」而不是「被清空了」，
			// 否则用户看到「数据目录被清空」只会以为又出了事故。
			log.Printf("[提示] 数据目录刚刚换到 %s（v1.5.1 起改用飞牛官方的应用数据目录），"+
				"配置是从最近一次自动备份恢复的（来源 %s）。"+
				"请核对 AdGuard 地址、要加速的域名、同步几条 IP 和各家密钥；"+
				"核对无误后点一次「保存全部设置」，页面顶上的红条就会消失", host, src)
			// v1.6.5：这里原来会提示「旧位置 /var/apps/cf-ddns-sidecar-data 里还留着
			// 一份配置，可以自己删掉」。那个位置是 v1.4.x 的自造目录，早已不用；
			// 提示也已经和旧目录的挂载一起删掉了。
		} else {
			log.Printf("[警告] 升级期间数据目录被清空了，已从升级前的自动备份恢复（来源 %s）。"+
				"请核对后台里的 AdGuard 地址、要加速的域名、同步几条 IP 和各家密钥是否完整；"+
				"核对无误后点一次「保存全部设置」，页面顶上的红条就会消失", src)
		}
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

	// 开机交代一句「备份目录现在什么状况」，哪怕一切正常。
	//
	// 这次事故最耗时间的地方就是「到底有没有备份」全靠猜：备份目录在宿主机上，
	// 容器日志里一个字都没有，只能一层层翻文件管理器。以后看日志就知道是
	// 「目录没建出来」「建了但容器写不进去」还是「里面本来是空的」，三种修法完全不同。
	//
	// 位置刻意放在上面那次 Save 之后：首次安装时 Save 会顺带备下第一份，
	// 若在这一行之前打印，日志会说「目前是空的」而备份其实已经在了，自相矛盾。
	// 也放在 -v 之后：-v 只是打印版本，不该去备份目录里写探针文件。
	if bs := config.InspectBackupDir(); !bs.Exists {
		log.Printf("[信息] 备份目录 %s 不存在：配置没法自己备份，升级或重装后可能找不回来"+
			"（用飞牛安装包装的话正常不该出现这一条，请把它发我）", bs.Dir)
	} else if !bs.Writable {
		log.Printf("[警告] 备份目录 %s 在，但容器里写不进去（权限或只读挂载）："+
			"升级前的备份只能靠安装脚本，而它不一定跑。请把这一行发我", bs.Dir)
	} else if bs.Count == 0 {
		log.Printf("[信息] 备份目录 %s 可用，目前是空的（在后台点一次「保存全部设置」就会备一份）", bs.Dir)
	} else {
		log.Printf("[信息] 备份目录 %s 可用：共 %d 份，最新 %s", bs.Dir, bs.Count, bs.Newest)
	}

	// 交代「数据/备份到底放在哪一层」。紧跟在备份那几行后面：
	// 一个说「有没有备份」，一个说「备份和数据在不在会被删的那一层」，凑在一起才完整。
	//
	// 这一段是 v1.4.2 补的。之前三版（v1.3.2/v1.4.0/v1.4.1）的日志都会说
	// 「数据目录已搬到存储卷」，而真机翻遍文件管理器压根没有那两个文件夹——
	// 搬失败的错误被脚本里的 2>/dev/null 吞了。现在脚本把真相写进账本，这里念出来。
	//
	// v1.5.1 起补一条硬事实：宿主机路径由 compose 传进来就直接念，不再依赖账本。
	// 真机实测证明飞牛对 Docker 应用做覆盖升级时**根本不执行** cmd/main，账本
	// 永远写不出来，只看账本等于每次都「什么都没读到」。
	// hostKnown 记住「宿主机路径是不是已经从 compose 拿到了」。拿到了就不让
	// reportLocation 再念一遍账本里的同一个路径——v1.5.1 真机日志里那两行
	// 「数据目录：/vol1/@appdata/cf-ddns-sidecar（容器内 /app/data）」和
	// 「数据放在 /vol1/@appdata/cf-ddns-sidecar」是连在一起的，看着像两件事，
	// 其实一句话说了两遍，反而让人以为有什么没对上。
	hostKnown := false
	if host := dataHostPath(); host != "" {
		log.Printf("[信息] 数据目录：%s（容器内 /app/data）", host)
		hostKnown = true
	}
	// v1.6.5：删掉了 `else if CFDDNS_LEGACY_HOST != ""` 那个分支。它只在
	// 「拿不到 CFDDNS_DATA_HOST」时说话，内容是「v1.4.x 老布局」——而那个变量
	// 现在连 compose 里都没有了，分支永远不成立。
	reportLocation(hostKnown)

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

	// 以前这里会对「密码太短」打一条 [警告]，并在后台页面顶上挂一条黄条。
	// 2026-11-17 用户明确要求砍掉：他从安装向导里设的就是 6 位，用得挺好，
	// 不想每次开机、每次开页面都被提醒一次（原话「密码这个问题就不用管了，
	// 不行就把这个砍掉，用弱密码也无所谓了」）。
	//
	// 现在密码强弱只在两处还有意义，都和「常驻提示」无关：
	//   · 主动改密码时校验（web.handleSetPassword）——那是用户正在输入、改一下的事；
	//   · 密码是自动生成的时候，横幅里直接把明文打出来，方便用户复制。

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

// reportLocation 把宿主机脚本留下的「目录安置账本」转述到运行日志。
//
// 唯一目的：让「我的数据到底在哪儿、为什么没在数据盘上」变成几行日志，
// 而不是让人去翻文件管理器猜。
//
// 判断依据分两档：**能拿到环境变量就以环境变量为准**，账本只在拿不到时兜底。
// 这不是偷懒，是 v1.5.1 真机证明的：compose 传进来的 CFDDNS_DATA_HOST 是一手
// 事实，而账本要等宿主机脚本执行才写得出来，覆盖升级时那个脚本根本不跑。
// 两档都念的结果就是同一句话出现两遍——所以 hostKnown 为真时直接闭嘴。
//
// 为什么必须由程序来念、而不是脚本自己 echo：飞牛不收集生命周期脚本的标准
// 输出，脚本打得再多，用户在「应用中心 → 运行日志」里也看不到一个字。
// 脚本能写文件、程序能说话，两边各干一半才有人看得见。
func reportLocation(hostKnown bool) {
	st := config.InspectLocation()
	if !st.Found {
		// 不是用飞牛安装包装的（自己写 compose 跑）就没有这个文件，属正常情况。
		return
	}

	if st.DataError == "" {
		// hostKnown 为真时，宿主机路径已经在上面由 CFDDNS_DATA_HOST 念过了，
		// 这里一个字都不再重复。
		//
		// v1.6.5：删掉了 symlink 那半。软链是 v1.3.2～v1.4.1 那套「自造目录」的
		// 产物，v1.6.4 已把 shell 侧的建链代码整段删除，之后 data_kind 恒为 real
		// ——那个分支永远进不去。留着只会让读日志的人以为还存在「链到存储卷」
		// 这种形态（而它恰恰是历史上从来没成功过的那件事）。
		if !hostKnown {
			log.Printf("[信息] 数据放在 %s", st.DataWhere())
		}
	} else {
		// v1.6.5：这四行原来是解释「为什么没能搬到存储卷」——退回 /var/apps 的
		// 安全位置、数据盘根属于 root、普通用户建不了目录、要停应用挪文件……
		// 那全是 v1.4.x 的话术。
		//
		// 现在 data_error 只有一个来源：飞牛给的官方数据目录（TRIM_PKGVAR）
		// 建不出来，或者建出来了但容器用户写不进去（见 cmd/main 的
		// init_on_platform_var）。所以照实说这两件事，不再猜「没搬到卷上」。
		log.Printf("[警告] 数据目录不可用：%s", st.DataError)
		log.Printf("[提示] 数据现在实际在 %s。请把上面这一行连同启动日志发我", st.DataWhere())
	}

	// 备份单独说一句：两个目录各判各的，可能一个成一个不成。
	// v1.6.5：措辞从「没在存储卷上」改成「不可用」——现在 backup_error 的来源是
	// 「建不了备份目录」或「建出来但写不进去」，不再是「没能搬到存储卷」。
	if st.BackupError != "" {
		prefix := "数据目录和备份目录都不可用"
		if st.DataError == "" {
			prefix = "备份目录不可用"
		}
		log.Printf("[警告] %s：%s", prefix, st.BackupError)
		log.Printf("[提示] 备份写不进去时，下一次升级可能找不到能恢复的配置；请把上面这一行发我")
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

// dataHostPath 返回「数据目录在宿主机上的真实路径」，没传就是空。
//
// 容器里只看得到 /app/data，看不见自己在宿主机上对应哪个目录。飞牛官方文档
// 说安装后会把 `var -> /vol{n}/@appdata/<app>` 建好、变量叫 TRIM_PKGVAR，
// 但那是**宿主机**的视角，容器进程拿不到。所以 compose 把它作为 CFDDNS_DATA_HOST
// 传进来，日志才能直接说「数据在 /vol1/@appdata/cf-ddns-sidecar」，
// 而不是让用户去文件管理器里一层层翻（v1.3.2～v1.4.1 就一直在翻）。
//
// 这个值同时是「数据目录换了位置」的判据：有它就说明这次跑在官方目录上。
func dataHostPath() string {
	return strings.TrimSpace(os.Getenv("CFDDNS_DATA_HOST"))
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
