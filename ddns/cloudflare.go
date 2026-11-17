package ddns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// cloudflareAPIBase 可被测试替换。
var cloudflareAPIBase = "https://api.cloudflare.com/client/v4"

type cloudflare struct {
	zoneID string
	token  string
	client *http.Client
}

type cfRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

type cfListResp struct {
	Success  bool       `json:"success"`
	Messages []string   `json:"messages"`
	Result   []cfRecord `json:"result"`
}

type cfWriteResp struct {
	Success  bool     `json:"success"`
	Messages []string `json:"messages"`
}

func newCloudflare(domain string, creds map[string]string) (Provider, error) {
	zone := strings.TrimSpace(creds["CF_ZONE_ID"])
	token := strings.TrimSpace(creds["CF_API_TOKEN"])
	if zone == "" || token == "" {
		return nil, fmt.Errorf("Cloudflare 需要 CF_ZONE_ID 与 CF_API_TOKEN")
	}
	return &cloudflare{zoneID: zone, token: token, client: &http.Client{Timeout: 15 * time.Second}}, nil
}

func (c *cloudflare) Name() string { return "Cloudflare" }

// aRecords 查这条域名的 A 记录。查询和校验共用，避免两处各写一遍参数。
func (c *cloudflare) aRecords(domain string) ([]cfRecord, error) {
	q := url.Values{}
	q.Set("name", domain)
	q.Set("type", "A")
	q.Set("per_page", "50")

	var list cfListResp
	if err := c.do(http.MethodGet,
		fmt.Sprintf("%s/zones/%s/dns_records?%s", cloudflareAPIBase, c.zoneID, q.Encode()),
		nil, &list); err != nil {
		return nil, fmt.Errorf("查询记录失败: %w", err)
	}
	if !list.Success {
		return nil, fmt.Errorf("查询记录返回失败: %s", strings.Join(list.Messages, ", "))
	}
	return list.Result, nil
}

func (c *cloudflare) Verify(domain string) (RecordState, error) {
	recs, err := c.aRecords(domain)
	if err != nil {
		return RecordState{}, err
	}
	for _, rec := range recs {
		if strings.EqualFold(rec.Name, domain) && rec.Type == "A" {
			return RecordState{Found: true, CurrentIP: rec.Content}, nil
		}
	}
	return RecordState{}, nil
}

func (c *cloudflare) EnsureARecord(domain, ip string, opt RecordOptions) error {
	list, err := c.aRecords(domain)
	if err != nil {
		return err
	}

	ttl := opt.cfTTL()
	for _, rec := range list {
		if strings.EqualFold(rec.Name, domain) && rec.Type == "A" {
			// IP、TTL、云朵三者都得对上才算「已经好了」。
			// 只比 IP 的话，用户刚把云朵打开时 IP 没变，这一趟会被当成无事
			// 可做而直接跳过，界面上显示保存成功、线上其实一点没动。
			if rec.Content == ip && rec.TTL == ttl && rec.Proxied == opt.Proxied {
				return nil
			}
			rec.Content = ip
			rec.TTL = ttl
			rec.Proxied = opt.Proxied
			var wr cfWriteResp
			if err := c.do(http.MethodPut,
				fmt.Sprintf("%s/zones/%s/dns_records/%s", cloudflareAPIBase, c.zoneID, rec.ID),
				rec, &wr); err != nil {
				return err
			}
			// Cloudflare v4 存在 HTTP 200 但 success:false 的业务错误，必须校验。
			if !wr.Success {
				return fmt.Errorf("更新记录返回失败: %s", strings.Join(wr.Messages, ", "))
			}
			return nil
		}
	}

	var wr cfWriteResp
	if err := c.do(http.MethodPost,
		fmt.Sprintf("%s/zones/%s/dns_records", cloudflareAPIBase, c.zoneID),
		map[string]any{"name": domain, "type": "A", "content": ip, "ttl": ttl, "proxied": opt.Proxied},
		&wr); err != nil {
		return err
	}
	if !wr.Success {
		return fmt.Errorf("创建记录返回失败: %s", strings.Join(wr.Messages, ", "))
	}
	return nil
}

func (c *cloudflare) do(method, urlStr string, body any, result any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, urlStr, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if result == nil {
		return nil
	}
	if err := json.Unmarshal(data, result); err != nil {
		return fmt.Errorf("解析响应失败: %w", err)
	}
	return nil
}
