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

// cfRecords 查这条域名的某一类记录（A 或 AAAA）。查询和校验共用，避免两处各写一遍参数。
func (c *cloudflare) cfRecords(domain, rtype string) ([]cfRecord, error) {
	q := url.Values{}
	q.Set("name", domain)
	q.Set("type", rtype)
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

func (c *cloudflare) Verify(domain string, rtype string) (RecordState, error) {
	rtype, err := NormalizeRecordType(rtype)
	if err != nil {
		return RecordState{}, err
	}
	recs, err := c.cfRecords(domain, rtype)
	if err != nil {
		return RecordState{}, err
	}
	var state RecordState
	for _, rec := range recs {
		// 服务端已按 type 过滤过，这里再判一次是为了不依赖对端行为：
		// 万一哪天接口忽略了 type 参数，越过这一行的就是「把 A 当成 AAAA 显示」。
		if strings.EqualFold(rec.Name, domain) && rec.Type == rtype {
			state.Found = true
			state.CurrentIPs = append(state.CurrentIPs, rec.Content)
		}
	}
	if len(state.CurrentIPs) > 0 {
		state.CurrentIP = state.CurrentIPs[0]
	}
	return state, nil
}

func (c *cloudflare) EnsureRecords(domain string, ips []string, opt RecordOptions) error {
	rtype, err := opt.recordType()
	if err != nil {
		return err
	}
	ips, err = prepareIPs(ips, rtype)
	if err != nil {
		return err
	}
	// 空集合不是「把域名清空」，是「这次没结果，别动」。
	if len(ips) == 0 {
		return nil
	}

	list, err := c.cfRecords(domain, rtype)
	if err != nil {
		return err
	}

	ttl := opt.cfTTL()
	// 先建一张「现在有哪些 IP」的表，避免为每个期望 IP 都遍历一次全表。
	have := make(map[string]cfRecord, len(list))
	for _, rec := range list {
		if strings.EqualFold(rec.Name, domain) && rec.Type == rtype {
			have[rec.Content] = rec
		}
	}

	// 第一遍：把期望的每一条都弄好（已有的校准，没有的新建）。
	for _, ip := range ips {
		if rec, ok := have[ip]; ok {
			// IP 对了，但 TTL 或云朵不是我们要的，得改一次。
			if rec.TTL == ttl && rec.Proxied == opt.Proxied {
				continue
			}
			rec.Content = ip
			rec.TTL = ttl
			rec.Proxied = opt.Proxied
			if err := c.putRecord(rec); err != nil {
				return err
			}
			continue
		}
		if err := c.createRecord(domain, rtype, ip, ttl, opt.Proxied); err != nil {
			return err
		}
	}

	// 第二遍：删掉不在期望集合里的。
	//
	// 这一步会删掉用户手工加的、以及上一次写入但这次掉出前 N 名的记录。
	// 用户明确选了「不要原有记录」，所以这是要的行为；但顺序必须放在补齐
	// 之后，否则中间那一瞬间域名没有任何记录。
	want := make(map[string]bool, len(ips))
	for _, ip := range ips {
		want[ip] = true
	}
	for _, rec := range list {
		if !strings.EqualFold(rec.Name, domain) || rec.Type != rtype || want[rec.Content] {
			continue
		}
		if err := c.deleteRecord(rec.ID); err != nil {
			return err
		}
	}
	return nil
}

// ClearRecords 删掉这个域名下 rtype 那一族的全部记录。
// 服务端已按 name + type 过滤，这里再判一次 Name 与 Type 是为了不依赖对端行为：
// 万一哪天接口忽略了 type 参数，越过这一行的就是「删 A 的时候把 AAAA 顺手删了」。
func (c *cloudflare) ClearRecords(domain string, rtype string) (int, error) {
	rtype, err := NormalizeRecordType(rtype)
	if err != nil {
		return 0, err
	}
	list, err := c.cfRecords(domain, rtype)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, rec := range list {
		if !strings.EqualFold(rec.Name, domain) || rec.Type != rtype {
			continue
		}
		if err := c.deleteRecord(rec.ID); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func (c *cloudflare) putRecord(rec cfRecord) error {
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

func (c *cloudflare) createRecord(domain, rtype, ip string, ttl int, proxied bool) error {
	var wr cfWriteResp
	if err := c.do(http.MethodPost,
		fmt.Sprintf("%s/zones/%s/dns_records", cloudflareAPIBase, c.zoneID),
		map[string]any{"name": domain, "type": rtype, "content": ip, "ttl": ttl, "proxied": proxied},
		&wr); err != nil {
		return err
	}
	if !wr.Success {
		return fmt.Errorf("创建记录返回失败: %s", strings.Join(wr.Messages, ", "))
	}
	return nil
}

func (c *cloudflare) deleteRecord(id string) error {
	var wr cfWriteResp
	if err := c.do(http.MethodDelete,
		fmt.Sprintf("%s/zones/%s/dns_records/%s", cloudflareAPIBase, c.zoneID, id),
		nil, &wr); err != nil {
		return err
	}
	if !wr.Success {
		return fmt.Errorf("删除记录返回失败: %s", strings.Join(wr.Messages, ", "))
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
