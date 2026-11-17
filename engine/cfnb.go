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
	"strings"
	"time"
)

// Options 是界面上暴露的测速参数。
type Options struct {
	TopN                int    // 最终保留的 IP 数量
	BandwidthCandidates int    // 进入带宽测速的候选数
	CandidatesURL       string // 本地候选列表地址（Cloudflare 官方段随机采样）
}

// Result 是一次测速的结果。
type Result struct {
	IPs  []string // 按质量从优到劣排序的可用 IP
	Logs []string // 测速过程的日志行（供界面展示）
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

	ips, err := parseOutput(outFile)
	if err != nil {
		return res, err
	}
	res.IPs = ips
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
	//  1) 先吃本地候选列表（Cloudflare 官方段随机采样）——不依赖任何第三方，
	//     保证即使所有外部源都挂了，测速依然能跑出结果；
	//  2) 再叠加外部聚合源作为补充，扩大机房覆盖。
	sources := make([]map[string]any, 0, 4)
	if opt.CandidatesURL != "" {
		sources = append(sources, map[string]any{"url": opt.CandidatesURL, "enabled": true})
	}
	sources = append(sources,
		map[string]any{"url": "https://ipdb.api.030101.xyz/?type=bestcf", "enabled": true},
		map[string]any{"url": "https://zip.cm.edu.kg/all.txt", "enabled": true},
	)

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
		"GITHUB_SYNC_ENABLED":    false,
		"IP_CALIBRATION_ENABLED": false,
		"ENABLE_LOGGING":         false,

		// 输出内容：只要 IP，不要附加信息
		"IP_TXT_SHOW_BANDWIDTH":    false,
		"IP_TXT_SHOW_HTTP_LATENCY": false,
		"IP_TXT_SHOW_HTTP_JITTER":  false,
		"IP_TXT_SHOW_LATENCY":      false,
		"AD_HEADER_ENABLED":        false,
		"AD_FOOTER_ENABLED":        false,
		"AD_PERLINE_ENABLED":       false,
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// parseOutput 解析 cfnb 输出的 ip.txt。
// 每行通常是 `IP:端口#地区`，也可能是纯 IP 或带附加信息（速度/延迟），
// 这里统一取出其中的 IP 部分。
func parseOutput(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var ips []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 取第一个字段，然后剥掉 "#地区" 与 ":端口"
		token := strings.Fields(line)[0]
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
		ips = append(ips, ip)
	}
	return ips, scanner.Err()
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
