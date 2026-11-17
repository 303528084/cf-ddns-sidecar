// Package engine 封装「测速」能力的调用。
//
// 测速不是我们自己写的：直接复用 xinyitang3/cfnb（MIT）的测速脚本。
// 它的机制是「多源聚合 → TCP 延迟筛选 → 反代验证（带延迟/抖动）→ 真实带宽测速」，
// 比单纯 TCP 探测更接近「这个 IP 我的浏览器到底能不能打开」。
//
// 我们只做两件事：
//  1. 按界面上的参数生成 cfnb 的 config.json；
//  2. 跑完解析它输出的 ip.txt，拿回可用 IP 列表。
package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Options 是界面上暴露的测速参数。
type Options struct {
	TopN                int    // 最终保留的 IP 数量
	BandwidthCandidates int    // 进入带宽测速的候选数
	CandidatesURL       string // 本地候选列表地址（Cloudflare 官方段随机采样）
	// ExtraURLs 是用户在后台填的链接型来源，原样交给引擎自己去拉。
	// 内容格式不用我们管：cfnb 的 parse_adaptive 已支持纯 IP 列表、
	// `IP:端口#国家`、以及 JSON 三种。
	ExtraURLs []string
	// UseBuiltinSources 决定要不要附带内置的两个外部聚合源
	// （ipdb.api.030101.xyz、zip.cm.edu.kg）。
	//
	// 用户**没有**指定自定义来源时必须为 true，那是原本的行为；
	// 一旦用户指定了（段/单 IP/链接），就必须为 false —— 这两个源一个能
	// 吐 12757 个 IP，叠加进来会把用户划定的范围整个淹没，
	// 表现为「我明明填了段，优选出来还是原来那些」。
	UseBuiltinSources bool
	// Overrides 是用户在「高级设置」里改过的引擎参数，键名见 engine.Schema。
	//
	// 它盖在下面 writeCfnbConfig 拼好的基础配置**之后**：基础配置里的那些值
	// 是我们替用户做的决定（端口只留 443、强制直连、关掉广告行……），
	// 用户明确改过的才算数。不在这张表里的键一律丢弃，见 ApplyOverrides。
	Overrides map[string]any
}

// Node 是一个优选节点，连同它的质量数据。
//
// 速度和延迟本来就在 cfnb 的产出里，只是以前我们让配置把它们关掉了
// （IP_TXT_SHOW_BANDWIDTH / IP_TXT_SHOW_LATENCY 都写死成 false），
// 于是界面只能显示一串光秃秃的 IP，用户看不出「为什么第一条排第一」。
// 打开之后 ip.txt 的行变成这样：
//
//	172.64.229.246:443#US 15.09 Mbps 45.23 ms
//
// 这两个数字是**那次测速量出来的真实值**，不是估算也不是补的。
// 界面要拿它们让用户判断哪个更快，编一个是最坏的一种错。
// 带宽测速整轮失败时 cfnb 会降级成「按 TCP 延迟排序」，那时候行里
// 只有延迟没有速度——这里就老实留 0，界面显示「—」。
type Node struct {
	IP    string  `json:"ip"`
	Speed float64 `json:"speed,omitempty"` // 下行带宽，Mbps
	Delay float64 `json:"delay,omitempty"` // TCP 握手往返，毫秒
}

// Result 是一次测速的结果。
type Result struct {
	IPs   []string // 按质量从优到劣排序的可用 IP
	Nodes []Node   // 与 IPs 一一对应，带速度/延迟
	Logs  []string // 测速过程的日志行（供界面展示）
}

// Best 返回最优 IP（没有结果时返回空串）。
func (r *Result) Best() string {
	if r == nil || len(r.IPs) == 0 {
		return ""
	}
	return r.IPs[0]
}

// Run 执行一次测速。scriptPath 是 cfnb/main.py 的路径，workDir 用于存放
// 配置与输出（需要可写）。onProgress 会在有新的日志行时被调用（可为 nil）。
func Run(ctx context.Context, scriptPath, workDir string, opt Options, onProgress func(string)) (*Result, error) {
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return nil, fmt.Errorf("创建测速工作目录失败: %w", err)
	}

	// cfnb 从「脚本所在目录」读取 config.json（CONFIG_FILE 由 __file__ 推导，不是 cwd），
	// 所以要把脚本复制到工作目录再执行，配置和输出才会落在可写的数据卷里。
	localScript := filepath.Join(workDir, "main.py")
	if err := copyFile(scriptPath, localScript); err != nil {
		return nil, fmt.Errorf("准备测速引擎失败: %w", err)
	}

	cfgPath := filepath.Join(workDir, "config.json")
	if err := writeCfnbConfig(cfgPath, opt); err != nil {
		return nil, fmt.Errorf("写入测速配置失败: %w", err)
	}

	outFile := filepath.Join(workDir, "ip.txt")
	_ = os.Remove(outFile) // 清掉上次结果，避免跑失败时误读旧数据

	cmd := exec.CommandContext(ctx, "python3", localScript)
	cmd.Dir = workDir
	cmd.Env = append(os.Environ(), "PYTHONUNBUFFERED=1", "PYTHONIOENCODING=utf-8")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = cmd.Stdout // 合并，避免缓冲区写满导致死锁

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动测速引擎失败: %w", err)
	}

	res := &Result{}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" {
			continue
		}
		res.Logs = append(res.Logs, line)
		if len(res.Logs) > 500 {
			res.Logs = res.Logs[len(res.Logs)-500:]
		}
		if onProgress != nil {
			onProgress(line)
		}
	}

	waitErr := cmd.Wait()
	if waitErr != nil {
		return res, fmt.Errorf("测速引擎退出异常: %w", waitErr)
	}

	ips, nodes, err := parseOutput(outFile)
	if err != nil {
		return res, err
	}
	res.IPs = ips
	res.Nodes = nodes
	if len(ips) == 0 {
		return res, fmt.Errorf("测速没有产出可用 IP（可能是数据源暂时不可达，稍后重试）")
	}
	return res, nil
}

// writeCfnbConfig 生成 cfnb 的配置文件。
// 只覆盖我们关心的项：其余参数由 cfnb 自身的默认值兜底。
// 通知、Cloudflare DNS 更新、GitHub 同步等与本产品无关的能力全部关闭，
// 域名解析统一由我们自己的 ddns 包推送（支持四家服务商）。
func writeCfnbConfig(path string, opt Options) error {
	topN := opt.TopN
	if topN <= 0 {
		topN = 5
	}
	candidates := opt.BandwidthCandidates
	if candidates <= 0 {
		candidates = 100
	}

	// 数据源顺序很关键：
	//  1) 先吃本地候选列表（这一段的内容由用户的「优选 IP 段」决定，
	//     没设置时就是 Cloudflare 官方段随机采样）——不依赖任何第三方，
	//     保证即使所有外部源都挂了，测速依然能跑出结果；
	//  2) 再叠加用户自己填的链接；
	//  3) 只有用户没指定任何自定义来源时，才带上内置的两个外部聚合源。
	//     这一条是「只用我给的段」能成立的前提，见 Options.UseBuiltinSources
	//     的注释——实测 zip.cm.edu.kg 一个源就有 12757 个 IP。
	sources := make([]map[string]any, 0, 4)
	if opt.CandidatesURL != "" {
		sources = append(sources, map[string]any{"url": opt.CandidatesURL, "enabled": true})
	}
	for _, u := range opt.ExtraURLs {
		// 这里再 TrimSpace 一次：web 层保存时已经去过空白，但 cfnb 拿到一个
		// 带空格的 URL 会静默当成「拉不到数据」，日志只说 0 节点，
		// 排查起来要去翻它内部实现。多这一步几乎不要成本。
		if u = strings.TrimSpace(u); u == "" {
			continue
		}
		sources = append(sources, map[string]any{"url": u, "enabled": true})
	}
	if opt.UseBuiltinSources {
		sources = append(sources,
			map[string]any{"url": "https://ipdb.api.030101.xyz/?type=bestcf", "enabled": true},
			map[string]any{"url": "https://zip.cm.edu.kg/all.txt", "enabled": true},
		)
	}

	cfg := map[string]any{
		// 输出与筛选
		"USE_GLOBAL_MODE":                 true,
		"GLOBAL_TOP_N":                    topN,
		"BANDWIDTH_CANDIDATES":            candidates,
		"OUTPUT_FILE":                     "ip.txt",
		"OUTPUT_FILTER_COUNTRIES_ENABLED": false,

		"ADDITIONAL_SOURCES":    sources,
		"FETCH_TIMEOUT":         8,
		"FETCH_CONNECT_TIMEOUT": 8,
		"FETCH_MAX_RETRIES":     2,

		// 反代验证：这是 cfnb 最有价值的部分，确保选出的 IP 真能承载请求。
		// 多轮验证会剔除「TCP 能连但实际打不开」的节点，这正是原方案的最大痛点。
		"TEST_AVAILABILITY":        true,
		"AVAILABILITY_TEST_ROUNDS": 3,

		// 前置过滤：端口只保留 443。
		// 国家黑名单默认关闭：聚合源大多不带国家信息，强开会把有效节点误杀。
		"PRE_FILTER_BLOCKED_ENABLED":       false,
		"PRE_FILTER_PORT_ENABLED":          true,
		"PRE_FILTER_PORTS":                 []int{443},
		"FILTER_BLOCKED_COUNTRIES_ENABLED": false,

		// 强制直连：测速必须量的是「本机网络到 Cloudflare 边缘」，不能被代理污染。
		// 设了它之后脚本会清掉所有 *_PROXY 环境变量并设置 NO_PROXY=*。
		"FORCE_DIRECT": true,

		// 关闭与本产品无关的附加能力
		"ENABLE_WXPUSHER":        false,
		"CF_ENABLED":             false,
		"IP_CALIBRATION_ENABLED": false,
		"ENABLE_LOGGING":         false,
		// 这里以前还写了 "GITHUB_SYNC_ENABLED": false，但 cfnb 根本没有这个键
		// （它只有 GITHUB_SYNC_MAX_RETRIES / GITHUB_SYNC_RETRY_DELAY /
		// GIT_SYNC_PROCESS_TIMEOUT），写进去等于什么都没做，还容易让人以为
		// 「GitHub 同步已经关掉了」是靠这一行保证的。

		// 输出内容：IP 后面跟上速度与延迟。
		//
		// 这两行以前是 false——当时界面只显示 IP，多出来反而要在解析时丢掉。
		// 现在界面要显示「速度 15.09 Mbps / 延迟 84.71 ms」，而这是唯一
		// 能拿到它们的地方：cfnb 不吐 JSON，只吐这个文本文件。
		//
		// 打开后每行形如 `172.64.229.246:443#US 15.09 Mbps 45.23 ms`，
		// parseOutput 按「数值+单位」成对读，顺序变了也不会读错。
		// 注意 TCP 延迟那一项（IP_TXT_SHOW_LATENCY）始终有值，
		// HTTP 延迟/抖动（另外两个）需要 HTTP_LATENCY_ENABLED，本产品不开。
		"IP_TXT_SHOW_BANDWIDTH":    true,
		"IP_TXT_SHOW_LATENCY":      true,
		"IP_TXT_SHOW_HTTP_LATENCY": false,
		"IP_TXT_SHOW_HTTP_JITTER":  false,
		"AD_HEADER_ENABLED":        false,
		"AD_FOOTER_ENABLED":        false,
		"AD_PERLINE_ENABLED":       false,
	}

	// 用户「高级设置」里改过的参数盖在最上面。
	//
	// 放在这里而不是逐个字段判断，是因为基础配置是「我们替用户做的决定」，
	// 而用户明确改过的值优先级更高。ApplyOverrides 只认 engine.Schema 里的键，
	// 手改 config.json 塞进来的奇怪参数会被丢掉。
	ApplyOverrides(cfg, opt.Overrides)

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// parseOutput 解析 cfnb 输出的 ip.txt，返回 IP 列表与带质量数据的节点列表。
//
// 每行的格式由 cfnb 的 write_ip_txt 决定：
//
//	172.64.229.246:443#US 15.09 Mbps 45.23 ms
//	172.64.229.246:443#US 45.23 ms          ← 带宽测速整轮失败、降级排序时
//	104.16.0.87:443#US                      ← 两个开关都没命中时（老配置兜底）
//
// 所以不能按固定列号取值：一律「取第一个字段当节点，剩下按『数值 单位』成对扫」。
// 单位只认 Mbps 和 ms；认不出来的词直接跳过，绝不让一个没见过的字段把整行读崩。
func parseOutput(path string) ([]string, []Node, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	defer f.Close()

	var ips []string
	var nodes []Node
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		// 取第一个字段，然后剥掉 "#地区" 与 ":端口"。
		// 那个 #地区 是**占位值**（我们补的 #US），不是真实位置，
		// 真实位置由 web 层去问 Cloudflare 出口（见 web/exitgeo.go）。
		token := fields[0]
		if i := strings.IndexByte(token, '#'); i > 0 {
			token = token[:i]
		}
		ip := token
		if host, _, err := net.SplitHostPort(token); err == nil {
			ip = host
		}
		ip = strings.Trim(ip, "[]")
		if !looksLikeIP(ip) || seen[ip] {
			continue
		}
		seen[ip] = true

		n := Node{IP: ip}
		// 从第 2 个字段起，两两一对：数值 + 单位。
		for i := 1; i+1 < len(fields); i += 2 {
			v, err := strconv.ParseFloat(fields[i], 64)
			if err != nil {
				// 不是「数值 单位」的排布，往后挪一个再看，
				// 不 break —— 少读一个数字总比整行丢掉好。
				continue
			}
			switch strings.ToLower(fields[i+1]) {
			case "mbps":
				n.Speed = v
			case "ms":
				// 可能有多段 ms（HTTP 延迟、抖动、TCP 延迟），
				// 取第一个：那是离用户感知最近的那个数。
				if n.Delay == 0 {
					n.Delay = v
				}
			}
		}

		ips = append(ips, ip)
		nodes = append(nodes, n)
	}
	return ips, nodes, scanner.Err()
}

// looksLikeIP 做轻量格式校验（不引入 net.ParseIP 的开销与 IPv6 括号差异）。
func looksLikeIP(s string) bool {
	if s == "" || len(s) > 45 {
		return false
	}
	dot, colon := strings.Count(s, "."), strings.Count(s, ":")
	if dot == 0 && colon == 0 {
		return false
	}
	for _, r := range s {
		if (r >= '0' && r <= '9') || r == '.' || r == ':' || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			continue
		}
		return false
	}
	return true
}

// DefaultTimeout 返回一次测速的合理上限。
func DefaultTimeout() time.Duration { return 10 * time.Minute }

// copyFile 复制文件（用于把测速脚本放到可写的工作目录）。
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
