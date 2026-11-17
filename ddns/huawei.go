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

var huaweiAPIBase = "https://dns.myhuaweicloud.com"

type huawei struct {
	ak     string
	sk     string
	zoneID string
	client *http.Client
}

type hwRecordset struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	ZoneID  string   `json:"zone_id"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	Records []string `json:"records"`
}

type hwListResp struct {
	Recordsets []hwRecordset `json:"recordsets"`
}

type hwZonesResp struct {
	Zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"zones"`
}

func newHuawei(domain string, creds map[string]string) (Provider, error) {
	ak := strings.TrimSpace(creds["HUAWEI_AK"])
	sk := strings.TrimSpace(creds["HUAWEI_SK"])
	zone := strings.TrimSpace(creds["HUAWEI_ZONE_ID"])
	if ak == "" || sk == "" || zone == "" {
		return nil, fmt.Errorf("华为云需要 HUAWEI_AK、HUAWEI_SK、HUAWEI_ZONE_ID")
	}
	return &huawei{ak: ak, sk: sk, zoneID: zone, client: &http.Client{Timeout: 15 * time.Second}}, nil
}

func (h *huawei) Name() string { return "华为云" }

func (h *huawei) EnsureARecord(domain, ip string) error {
	q := url.Values{}
	q.Set("name", domain+".")
	q.Set("type", "A")
	var list hwListResp
	if err := h.request(http.MethodGet, huaweiAPIBase+"/v2.1/recordsets", q, nil, &list); err != nil {
		return fmt.Errorf("查询记录失败: %w", err)
	}
	for _, rec := range list.Recordsets {
		if strings.TrimSuffix(rec.Name, ".") == domain && rec.Type == "A" {
			if len(rec.Records) > 0 && rec.Records[0] == ip {
				return nil
			}
			body := map[string]any{
				"name": rec.Name, "type": rec.Type,
				"records": []string{ip}, "ttl": 300,
			}
			u := fmt.Sprintf("%s/v2.1/zones/%s/recordsets/%s", huaweiAPIBase, rec.ZoneID, rec.ID)
			var out hwRecordset
			return h.request(http.MethodPut, u, nil, body, &out)
		}
	}

	body := map[string]any{
		"name": domain + ".", "type": "A",
		"records": []string{ip}, "ttl": 300,
	}
	u := fmt.Sprintf("%s/v2.1/zones/%s/recordsets", huaweiAPIBase, h.zoneID)
	var out hwRecordset
	return h.request(http.MethodPost, u, nil, body, &out)
}

func (h *huawei) request(method, urlStr string, query url.Values, body any, result any) error {
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
	if query != nil {
		req.URL.RawQuery = query.Encode()
	}
	req.Header.Set("Content-Type", "application/json")
	if err := HuaweiSign(h.ak, h.sk, req); err != nil {
		return err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if result != nil {
		if err := json.Unmarshal(data, result); err != nil {
			return fmt.Errorf("解析响应失败: %w", err)
		}
	}
	return nil
}
