package ddns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var dnspodAPIBase = "https://dnspod.tencentcloudapi.com"

type dnspod struct {
	root      string
	secretID  string
	secretKey string
	client    *http.Client
}

type tcRecord struct {
	Domain     string `json:"Domain"`
	SubDomain  string `json:"SubDomain,omitempty"`
	Subdomain  string `json:"Subdomain,omitempty"`
	RecordType string `json:"RecordType,omitempty"`
	RecordLine string `json:"RecordLine,omitempty"`
	Value      string `json:"Value,omitempty"`
	RecordId   int64  `json:"RecordId,omitempty"`
	TTL        int    `json:"TTL,omitempty"`
}

type tcListResp struct {
	Response struct {
		Error struct {
			Code    string `json:"Code"`
			Message string `json:"Message"`
		} `json:"Error"`
		RecordCountInfo struct {
			TotalCount int `json:"TotalCount"`
		} `json:"RecordCountInfo"`
		RecordList []tcRecord `json:"RecordList"`
	} `json:"Response"`
}

type tcStatusResp struct {
	Response struct {
		Error struct {
			Code    string `json:"Code"`
			Message string `json:"Message"`
		} `json:"Error"`
	} `json:"Response"`
}

func newDNSPod(domain string, creds map[string]string) (Provider, error) {
	id := strings.TrimSpace(creds["TENCENT_SECRET_ID"])
	key := strings.TrimSpace(creds["TENCENT_SECRET_KEY"])
	if id == "" || key == "" {
		return nil, fmt.Errorf("腾讯云 DNSPod 需要 TENCENT_SECRET_ID 与 TENCENT_SECRET_KEY")
	}
	// 根域默认按末两段推断；多级公共后缀（如 example.com.cn）必须
	// 通过环境变量 DNSPOD_ROOT_DOMAIN 显式指定。
	root := inferRoot(domain)
	if v := strings.TrimSpace(creds["DNSPOD_ROOT_DOMAIN"]); v != "" {
		root = v
	}
	return &dnspod{root: root, secretID: id, secretKey: key, client: &http.Client{Timeout: 15 * time.Second}}, nil
}

func (d *dnspod) Name() string { return "腾讯云 DNSPod" }

// queryAllA 查这条域名下全部的 A 记录（查询与校验共用）。
func (d *dnspod) queryAllA(domain string) ([]tcRecord, error) {
	sub, _ := splitDomain(domain, d.root)
	if sub == "@" {
		sub = ""
	}
	query := tcRecord{Domain: d.root, Subdomain: sub, RecordType: "A", RecordLine: "默认"}
	var list tcListResp
	if err := d.request("DescribeRecordList", query, &list); err != nil {
		return nil, fmt.Errorf("查询记录失败: %w", err)
	}
	if list.Response.Error.Code != "" {
		return nil, fmt.Errorf("%s: %s", list.Response.Error.Code, list.Response.Error.Message)
	}
	return list.Response.RecordList, nil
}

func (d *dnspod) Verify(domain string) (RecordState, error) {
	recs, err := d.queryAllA(domain)
	if err != nil {
		return RecordState{}, err
	}
	var state RecordState
	for _, r := range recs {
		state.Found = true
		state.CurrentIPs = append(state.CurrentIPs, r.Value)
	}
	if len(state.CurrentIPs) > 0 {
		state.CurrentIP = state.CurrentIPs[0]
	}
	return state, nil
}

func (d *dnspod) EnsureARecords(domain string, ips []string, opt RecordOptions) error {
	ips = normalizeIPs(ips)
	if len(ips) == 0 {
		return nil
	}

	sub, _ := splitDomain(domain, d.root)
	if sub == "@" {
		sub = ""
	}
	stdSub := sub
	if stdSub == "" {
		stdSub = "@"
	}
	// DNSPod 免费版要求 TTL ≥ 600，所以没填时沿用一直以来的 600。
	ttl := opt.TTL
	if ttl <= 0 {
		ttl = 600
	}

	recs, err := d.queryAllA(domain)
	if err != nil {
		return err
	}

	// 先补齐、再删多余：顺序反了的话中间有一瞬间这域名没有任何 A 记录。
	have := make(map[string]tcRecord, len(recs))
	for _, r := range recs {
		have[r.Value] = r
	}
	for _, ip := range ips {
		if rec, ok := have[ip]; ok {
			// 值对了，TTL 不对就顺手改一次。
			if rec.TTL == ttl {
				continue
			}
			if err := d.modifyRecord(tcRecord{
				Domain: d.root, SubDomain: stdSub, RecordType: "A",
				RecordLine: "默认", Value: ip, RecordId: rec.RecordId, TTL: ttl,
			}); err != nil {
				return err
			}
			continue
		}
		if err := d.createRecord(tcRecord{
			Domain: d.root, SubDomain: stdSub, RecordType: "A",
			RecordLine: "默认", Value: ip, TTL: ttl,
		}); err != nil {
			return err
		}
	}

	want := make(map[string]bool, len(ips))
	for _, ip := range ips {
		want[ip] = true
	}
	for _, r := range recs {
		if want[r.Value] {
			continue
		}
		if err := d.deleteRecord(r.RecordId); err != nil {
			return err
		}
	}
	return nil
}

func (d *dnspod) modifyRecord(rec tcRecord) error {
	var st tcStatusResp
	if err := d.request("ModifyRecord", rec, &st); err != nil {
		return err
	}
	if st.Response.Error.Code != "" {
		return fmt.Errorf("%s: %s", st.Response.Error.Code, st.Response.Error.Message)
	}
	return nil
}

func (d *dnspod) createRecord(rec tcRecord) error {
	var st tcStatusResp
	if err := d.request("CreateRecord", rec, &st); err != nil {
		return err
	}
	if st.Response.Error.Code != "" {
		return fmt.Errorf("%s: %s", st.Response.Error.Code, st.Response.Error.Message)
	}
	return nil
}

func (d *dnspod) deleteRecord(recordID int64) error {
	var st tcStatusResp
	if err := d.request("DeleteRecord", tcRecord{Domain: d.root, RecordId: recordID}, &st); err != nil {
		return err
	}
	if st.Response.Error.Code != "" {
		return fmt.Errorf("%s: %s", st.Response.Error.Code, st.Response.Error.Message)
	}
	return nil
}

func (d *dnspod) request(action string, payload any, result any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, dnspodAPIBase, bytes.NewReader(body))
	if err != nil {
		return err
	}
	TencentCloudSign(d.secretID, d.secretKey, req, action, string(body), "dnspod")
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if err := json.Unmarshal(data, result); err != nil {
		return fmt.Errorf("解析响应失败: %w（raw=%s）", err, strconv.Quote(string(data)))
	}
	return nil
}
