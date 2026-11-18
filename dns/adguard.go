package dns

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/303528084/cf-ddns-sidecar/config"
)

// APIError 类型化的 AdGuard API 错误，携带 HTTP 状态码。
// 用于重试逻辑精确区分 4xx（不重试）与网络错误/5xx（重试）。
type APIError struct {
	Method     string
	Path       string
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("api %s %s: HTTP %d: %s", e.Method, e.Path, e.StatusCode, strings.TrimSpace(e.Body))
}

// IsClientError 判断 err 是否为 4xx 客户端错误（凭据错误、参数错误等，重试无意义）。
func IsClientError(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode >= 400 && apiErr.StatusCode < 500
}

// adguardClient AdGuard Home 的 Provider 实现（在线管理型，HTTP API CRUD）。
type adguardClient struct {
	url      string
	username string
	password string
	http     *http.Client
}

// NewAdGuard 创建 AdGuard Home provider。
func NewAdGuard(inst config.AdguardInstance) Provider {
	return &adguardClient{
		url:      normalizeAPIURL(inst.URL),
		username: inst.Username,
		password: inst.Password,
		http:     &http.Client{Timeout: 15 * time.Second},
	}
}

// normalizeAPIURL 规范化 API 地址：trim + 去尾部斜杠；缺协议头时自动补 http://。
func normalizeAPIURL(url string) string {
	url = strings.TrimRight(strings.TrimSpace(url), "/")
	if url != "" && !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}
	return url
}

func (c *adguardClient) Name() string { return "adguard" }

// do 发送一个带 Basic Auth 的请求到 AdGuard Home 控制接口。
func (c *adguardClient) do(method, path string, body any) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.url+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.username != "" || c.password != "" {
		req.SetBasicAuth(c.username, c.password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return data, &APIError{Method: method, Path: path, StatusCode: resp.StatusCode, Body: string(data)}
	}
	return data, nil
}

// doWithRetry 带重试的请求：最多 attempts 次，指数退避 + 抖动。
// 仅对网络错误与 5xx 重试；4xx（如凭据错误）不重试。
func (c *adguardClient) doWithRetry(method, path string, body any, attempts int) ([]byte, error) {
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			backoff := time.Duration(1<<uint(i-1)) * time.Second
			backoff += time.Duration(rand.Int63n(int64(500 * time.Millisecond))) // 抖动
			time.Sleep(backoff)
		}
		data, err := c.do(method, path, body)
		if err == nil {
			return data, nil
		}
		lastErr = err
		if IsClientError(err) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("重试 %d 次后仍失败: %w", attempts, lastErr)
}

// agRewrite 对应 AdGuard Home 的一条 DNS 重写规则。
type agRewrite struct {
	Domain  string `json:"domain"`
	Answer  string `json:"answer"`
	Enabled bool   `json:"enabled"`
}

func (c *adguardClient) TestConnection() error {
	_, err := c.list()
	return err
}

func (c *adguardClient) list() ([]agRewrite, error) {
	data, err := c.doWithRetry(http.MethodGet, "/control/rewrite/list", nil, 3)
	if err != nil {
		return nil, err
	}
	var list []agRewrite
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	return list, nil
}

func (c *adguardClient) ListRewrites() ([]RewriteEntry, error) {
	list, err := c.list()
	if err != nil {
		return nil, err
	}
	out := make([]RewriteEntry, 0, len(list))
	for _, e := range list {
		out = append(out, RewriteEntry{Domain: e.Domain, Answer: e.Answer, Enabled: e.Enabled})
	}
	return out, nil
}

func (c *adguardClient) addRewrite(domain, answer string) error {
	if _, err := c.doWithRetry(http.MethodPost, "/control/rewrite/add", agRewrite{Domain: domain, Answer: answer, Enabled: true}, 3); err != nil {
		return fmt.Errorf("添加重写规则失败 (%s -> %s): %w", domain, answer, err)
	}
	return nil
}

func (c *adguardClient) removeRewrite(e agRewrite) error {
	if _, err := c.doWithRetry(http.MethodPost, "/control/rewrite/delete", e, 3); err != nil {
		return fmt.Errorf("删除重写规则失败 (%s -> %s): %w", e.Domain, e.Answer, err)
	}
	return nil
}

// ReplaceRewrites 把重写状态收敛到期望集合 want，**只动 want 里点名的域名**。
//
// 2026-11-18 之前这里是「清空整张表、再按 want 全量重建」，两个毛病：
//
//  1. 用户在 AdGuard 后台自己加的、或者别的工具写的重写规则，每轮测速都被
//     一起删掉，而界面上只会说「已写入 AdGuard：N 条」，看起来一切正常。
//  2. 删光和重建之间有一段窗口，重写表是空的。这段时间里家里设备来查域名
//     拿不到重写结果，只能回落到正常解析（对「加速」这个目的来说等于白跑）。
//
// 现在改成差异收敛：先按域名分组比对现有记录，只删「归本工具管、但答案已经
// 不对」的那几条，只补「该有还没有」的那几条，答案已经对上的原样不动。
// 前一个毛病没了（不在这份集合里的域名一条都不碰），后一个窗口也没了
// （不需要先删后建）。
//
// want 的键就是「这个域名归本工具管」的声明。空集合表示「这域名不该有任何
// 记录」，调用方用它清理用户已经从域名列表里删掉的域名（见
// config.Config.RewrittenDomains）。
//
// 一个无法区分的情况，写在明处：同一个域名下如果用户自己也加了一条重写，
// 那条会被我们删掉，AdGuard 的重写记录里没有「谁写的」这个字段，只能按
// 「域名归谁管」划分地盘。域名一旦被本工具接管，它的重写就由本工具全权负责，
// 界面上要说明白，不能只留在代码注释里。
func (c *adguardClient) ReplaceRewrites(want map[string]map[string]bool) (SyncStats, error) {
	var stats SyncStats

	list, err := c.list()
	if err != nil {
		return stats, fmt.Errorf("获取重写列表失败: %w", err)
	}

	// 现有记录里「已经写对了的」答案，加的时候用来跳过重复添加。
	//
	// 只算**启用**状态的：用户把某条停用过之后，它对我们来说等于不存在，
	// 该删了重写成启用状态，否则会出现「记录在、但不生效」这种界面上完全
	// 看不出来的坏状态（重写表里明明有一条，域名就是不解析成那个 IP）。
	have := make(map[string]map[string]bool, len(want))
	for _, ent := range list {
		if _, managed := want[ent.Domain]; !managed {
			stats.Kept++ // 别人的地盘，只记个数，一个字都不动
			continue
		}
		if ent.Enabled {
			if have[ent.Domain] == nil {
				have[ent.Domain] = make(map[string]bool, 2)
			}
			have[ent.Domain][ent.Answer] = true
		}
	}

	// 1) 删：归本工具管、但答案不在期望集合里（或已停用）的记录。
	for _, ent := range list {
		allowed, managed := want[ent.Domain]
		if !managed {
			continue
		}
		if ent.Enabled && allowed[ent.Answer] {
			continue // 已经对了，不删了再加，省一次写操作
		}
		if err := c.removeRewrite(ent); err != nil {
			return stats, fmt.Errorf("删除重写规则失败 (%s -> %s): %w", ent.Domain, ent.Answer, err)
		}
		stats.Removed++
	}

	// 2) 加：want 里有、表里还没有的（排序保证顺序确定，重复跑和日志都稳定）
	domains := make([]string, 0, len(want))
	for d := range want {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	for _, d := range domains {
		answers := make([]string, 0, len(want[d]))
		for a := range want[d] {
			answers = append(answers, a)
		}
		sort.Strings(answers)
		for _, a := range answers {
			if have[d][a] {
				continue
			}
			if err := c.addRewrite(d, a); err != nil {
				return stats, err
			}
			stats.Written++
		}
	}
	return stats, nil
}
