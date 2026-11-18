package ddns

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
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

type aliyunRecord struct {
	RecordID string `json:"RecordID"`
	Value    string `json:"Value"`
	TTL      int    `json:"TTL"`
}

type aliyunRecordsResp struct {
	TotalCount    int `json:"TotalCount"`
	DomainRecords struct {
		Record []aliyunRecord `json:"Record"`
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

// queryRecords 查这条域名下某一类记录（A 或 AAAA），查询与校验共用。
//
// 注意 Type 是**服务端过滤条件**：查 AAAA 时阿里云只返回 AAAA，
// 后面的「删多余」也就删不到 A 记录——这正是我们要的安全边界。
func (a *aliyun) queryRecords(domain, rtype string) ([]aliyunRecord, error) {
	q := url.Values{}
	q.Set("Action", "DescribeSubDomainRecords")
	q.Set("SubDomain", domain)
	q.Set("Type", rtype)
	var list aliyunRecordsResp
	if err := a.request(q, &list); err != nil {
		return nil, fmt.Errorf("查询记录失败: %w", err)
	}
	return list.DomainRecords.Record, nil
}

func (a *aliyun) Verify(domain string, rtype string) (RecordState, error) {
	rtype, err := NormalizeRecordType(rtype)
	if err != nil {
		return RecordState{}, err
	}
	recs, err := a.queryRecords(domain, rtype)
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

func (a *aliyun) EnsureRecords(domain string, ips []string, opt RecordOptions) error {
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
	recs, err := a.queryRecords(domain, rtype)
	if err != nil {
		return err
	}

	// 先补齐、再删多余：顺序反了的话中间有一瞬间这域名没有任何记录。
	have := make(map[string]aliyunRecord, len(recs))
	for _, r := range recs {
		have[r.Value] = r
	}
	for _, ip := range ips {
		if rec, ok := have[ip]; ok {
			// 值已经对了，只差 TTL 就顺手改掉。opt.TTL 为 0 表示
			// 「用账号默认」，那就不去动它——我们并不知道默认值是多少。
			if opt.TTL > 0 && rec.TTL != opt.TTL {
				if err := a.updateRecord(domain, rtype, rec.RecordID, ip, opt.TTL); err != nil {
					return err
				}
			}
			continue
		}
		if err := a.addRecord(domain, rtype, ip, opt.TTL); err != nil {
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
		if err := a.deleteRecord(r.RecordID); err != nil {
			return err
		}
	}
	return nil
}

func (a *aliyun) addRecord(domain, rtype, ip string, ttl int) error {
	q := url.Values{}
	q.Set("Action", "AddDomainRecord")
	q.Set("DomainName", a.root)
	q.Set("RR", a.rr(domain))
	q.Set("Type", rtype)
	q.Set("Value", ip)
	// TTL 没填就一个字都不传：阿里云这时用账号默认值，也就是升级前的行为。
	if ttl > 0 {
		q.Set("TTL", strconv.Itoa(ttl))
	}
	return a.request(q, &struct{}{})
}

func (a *aliyun) updateRecord(domain, rtype, recordID, ip string, ttl int) error {
	q := url.Values{}
	q.Set("Action", "UpdateDomainRecord")
	q.Set("RecordId", recordID)
	q.Set("RR", a.rr(domain))
	q.Set("Type", rtype)
	q.Set("Value", ip)
	if ttl > 0 {
		q.Set("TTL", strconv.Itoa(ttl))
	}
	return a.request(q, &struct{}{})
}

func (a *aliyun) deleteRecord(recordID string) error {
	q := url.Values{}
	q.Set("Action", "DeleteDomainRecord")
	q.Set("RecordId", recordID)
	return a.request(q, &struct{}{})
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
