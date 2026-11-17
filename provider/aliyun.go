package provider

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var aliyunAPIBase = "https://alidns.aliyuncs.com/"

type aliyun struct {
	root     string
	akID     string
	akSecret string
	client   *http.Client
}

type aliyunRecordsResp struct {
	TotalCount    int `json:"TotalCount"`
	DomainRecords struct {
		Record []struct {
			RecordID string `json:"RecordID"`
			Value    string `json:"Value"`
		} `json:"Record"`
	} `json:"DomainRecords"`
}

func newAliyun(domain string, creds map[string]string) (Provider, error) {
	id := strings.TrimSpace(creds["ALIYUN_ACCESS_KEY_ID"])
	secret := strings.TrimSpace(creds["ALIYUN_ACCESS_KEY_SECRET"])
	if id == "" || secret == "" {
		return nil, fmt.Errorf("阿里云需要 ALIYUN_ACCESS_KEY_ID 与 ALIYUN_ACCESS_KEY_SECRET")
	}
	// 根域默认按末两段推断；多级公共后缀（如 example.com.cn）必须
	// 通过环境变量 ALIYUN_ROOT_DOMAIN 显式指定，否则 API 调用会失败。
	root := inferRoot(domain)
	if v := strings.TrimSpace(creds["ALIYUN_ROOT_DOMAIN"]); v != "" {
		root = v
	}
	return &aliyun{root: root, akID: id, akSecret: secret, client: &http.Client{Timeout: 15 * time.Second}}, nil
}

// inferRoot 从完整域名推断根域（取末两段）。
// 对多级公共后缀（如 example.com.cn）推断结果不正确，
// 需通过环境变量 ALIYUN_ROOT_DOMAIN / DNSPOD_ROOT_DOMAIN 覆盖。
func inferRoot(domain string) string {
	parts := strings.Split(strings.TrimSuffix(domain, "."), ".")
	if len(parts) <= 2 {
		return domain
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func (a *aliyun) Name() string { return "阿里云" }

func (a *aliyun) EnsureARecord(domain, ip string) error {
	// 查询现有记录
	q := url.Values{}
	q.Set("Action", "DescribeSubDomainRecords")
	q.Set("SubDomain", domain)
	q.Set("Type", "A")
	var list aliyunRecordsResp
	if err := a.request(q, &list); err != nil {
		return fmt.Errorf("查询记录失败: %w", err)
	}
	if list.TotalCount > 0 && len(list.DomainRecords.Record) > 0 {
		rec := list.DomainRecords.Record[0]
		if rec.Value == ip {
			return nil
		}
		u := url.Values{}
		u.Set("Action", "UpdateDomainRecord")
		u.Set("RecordId", rec.RecordID)
		u.Set("RR", a.rr(domain))
		u.Set("Type", "A")
		u.Set("Value", ip)
		return a.request(u, &struct{}{})
	}

	c := url.Values{}
	c.Set("Action", "AddDomainRecord")
	c.Set("DomainName", a.root)
	c.Set("RR", a.rr(domain))
	c.Set("Type", "A")
	c.Set("Value", ip)
	return a.request(c, &struct{}{})
}

func (a *aliyun) rr(domain string) string {
	_, rec := splitDomain(domain, a.root)
	return rec
}

func (a *aliyun) request(params url.Values, result any) error {
	AliyunSign(a.akID, a.akSecret, &params, http.MethodGet, "2015-01-09")
	req, err := http.NewRequest(http.MethodGet, aliyunAPIBase, nil)
	if err != nil {
		return err
	}
	req.URL.RawQuery = params.Encode()
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	// 阿里云业务错误在 JSON 的 Code 字段中
	var probe struct {
		Code    string `json:"Code"`
		Message string `json:"Message"`
	}
	_ = json.Unmarshal(data, &probe)
	if probe.Code != "" {
		return fmt.Errorf("%s: %s", probe.Code, probe.Message)
	}
	if err := json.Unmarshal(data, result); err != nil {
		return fmt.Errorf("解析响应失败: %w", err)
	}
	return nil
}
