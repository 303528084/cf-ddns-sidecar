package provider

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

func (d *dnspod) EnsureARecord(domain, ip string) error {
	sub, _ := splitDomain(domain, d.root)
	if sub == "@" {
		sub = ""
	}
	query := tcRecord{Domain: d.root, Subdomain: sub, RecordType: "A", RecordLine: "默认"}
	var list tcListResp
	if err := d.request("DescribeRecordList", query, &list); err != nil {
		return fmt.Errorf("查询记录失败: %w", err)
	}
	if list.Response.Error.Code != "" {
		return fmt.Errorf("%s: %s", list.Response.Error.Code, list.Response.Error.Message)
	}

	stdSub := sub
	if stdSub == "" {
		stdSub = "@"
	}
	if list.Response.RecordCountInfo.TotalCount > 0 && len(list.Response.RecordList) > 0 {
		rec := list.Response.RecordList[0]
		if rec.Value == ip {
			return nil
		}
		modify := tcRecord{
			Domain: d.root, SubDomain: stdSub, RecordType: "A",
			RecordLine: "默认", Value: ip, RecordId: rec.RecordId, TTL: 600,
		}
		var st tcStatusResp
		if err := d.request("ModifyRecord", modify, &st); err != nil {
			return err
		}
		if st.Response.Error.Code != "" {
			return fmt.Errorf("%s: %s", st.Response.Error.Code, st.Response.Error.Message)
		}
		return nil
	}

	create := tcRecord{Domain: d.root, SubDomain: stdSub, RecordType: "A", RecordLine: "默认", Value: ip, TTL: 600}
	var st tcStatusResp
	if err := d.request("CreateRecord", create, &st); err != nil {
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
