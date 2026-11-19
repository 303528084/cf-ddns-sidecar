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

// queryRecords 查这条域名某一类记录（A 或 AAAA），查询与校验共用。
func (h *huawei) queryRecords(domain, rtype string) (hwRecordset, bool, error) {
	q := url.Values{}
	q.Set("name", domain+".")
	q.Set("type", rtype)
	var list hwListResp
	if err := h.request(http.MethodGet, huaweiAPIBase+"/v2.1/recordsets", q, nil, &list); err != nil {
		return hwRecordset{}, false, fmt.Errorf("查询记录失败: %w", err)
	}
	for _, rec := range list.Recordsets {
		if strings.TrimSuffix(rec.Name, ".") == domain && rec.Type == rtype {
			return rec, true, nil
		}
	}
	return hwRecordset{}, false, nil
}

func (h *huawei) Verify(domain string, rtype string) (RecordState, error) {
	rtype, err := NormalizeRecordType(rtype)
	if err != nil {
		return RecordState{}, err
	}
	rec, found, err := h.queryRecords(domain, rtype)
	if err != nil {
		return RecordState{}, err
	}
	if !found {
		return RecordState{}, nil
	}
	state := RecordState{Found: true, CurrentIPs: append([]string(nil), rec.Records...)}
	if len(rec.Records) > 0 {
		state.CurrentIP = rec.Records[0]
	}
	return state, nil
}

// EnsureRecords 对华为云来说最省事：一个「记录集」本身就是一个值列表，
// 一次 PUT 把 records 整体换掉，多余的自然就没了，不需要逐条删除。
//
// 也正因为整集覆盖，这里绝不能读错类型：A 和 AAAA 在华为云是两个独立的
// 记录集，查哪一类、写哪一类必须一致，否则会把另一族整个盖掉。
func (h *huawei) EnsureRecords(domain string, ips []string, opt RecordOptions) error {
	rtype, err := opt.recordType()
	if err != nil {
		return err
	}
	ips, err = prepareIPs(ips, rtype)
	if err != nil {
		return err
	}
	if len(ips) == 0 {
		return nil
	}
	// 华为云没填时沿用一直以来的 300。
	ttl := opt.TTL
	if ttl <= 0 {
		ttl = 300
	}
	rec, found, err := h.queryRecords(domain, rtype)
	if err != nil {
		return err
	}
	if found {
		body := map[string]any{
			"name": rec.Name, "type": rec.Type,
			"records": ips, "ttl": ttl,
		}
		u := fmt.Sprintf("%s/v2.1/zones/%s/recordsets/%s", huaweiAPIBase, rec.ZoneID, rec.ID)
		var out hwRecordset
		return h.request(http.MethodPut, u, nil, body, &out)
	}

	body := map[string]any{
		"name": domain + ".", "type": rtype,
		"records": ips, "ttl": ttl,
	}
	u := fmt.Sprintf("%s/v2.1/zones/%s/recordsets", huaweiAPIBase, h.zoneID)
	var out hwRecordset
	return h.request(http.MethodPost, u, nil, body, &out)
}

// ClearRecords 删掉这个域名下 rtype 那一族的记录集。
// 华为云一个记录集就是一整族，删掉它这一族就一条不剩。返回集里的地址条数而不是 1，
// 这样四家返回值的含义一致（都表示「几条地址没了」），日志不用按服务商改写。
func (h *huawei) ClearRecords(domain string, rtype string) (int, error) {
	rtype, err := NormalizeRecordType(rtype)
	if err != nil {
		return 0, err
	}
	rec, found, err := h.queryRecords(domain, rtype)
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, nil
	}
	u := fmt.Sprintf("%s/v2.1/zones/%s/recordsets/%s", huaweiAPIBase, rec.ZoneID, rec.ID)
	if err := h.request(http.MethodDelete, u, nil, nil, nil); err != nil {
		return 0, err
	}
	return len(rec.Records), nil
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
