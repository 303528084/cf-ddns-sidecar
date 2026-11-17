package ddns

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCloudflareEnsureRecord(t *testing.T) {
	var gotCreate bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("缺少 Bearer token: %q", r.Header.Get("Authorization"))
		}
		switch r.Method {
		case http.MethodGet:
			if !strings.Contains(r.URL.Path, "/dns_records") {
				t.Errorf("查询路径错误: %s", r.URL.Path)
			}
			io.WriteString(w, `{"success":true,"result":[]}`)
		case http.MethodPost:
			gotCreate = true
			body, _ := io.ReadAll(r.Body)
			var m map[string]any
			json.Unmarshal(body, &m)
			if m["type"] != "A" || m["content"] != "1.2.3.4" || m["name"] != "cf.example.com" {
				t.Errorf("创建记录内容错误: %s", body)
			}
			io.WriteString(w, `{"success":true,"result":{}}`)
		default:
			t.Errorf("非预期方法: %s", r.Method)
		}
	}))
	defer srv.Close()
	old := cloudflareAPIBase
	cloudflareAPIBase = srv.URL
	defer func() { cloudflareAPIBase = old }()

	p, _ := newCloudflare("cf.example.com", map[string]string{"CF_API_TOKEN": "tok", "CF_ZONE_ID": "z1"})
	if err := p.EnsureARecords("cf.example.com", []string{"1.2.3.4"}, RecordOptions{}); err != nil {
		t.Fatal(err)
	}
	if !gotCreate {
		t.Fatal("记录不存在时应创建")
	}
}

// M1 回归：Cloudflare 返回 HTTP 200 但 success:false 时必须报错，
// 否则会产生“健康且已更新”的假象且不再重试。
func TestCloudflareWriteBusinessFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			io.WriteString(w, `{"success":true,"result":[]}`)
			return
		}
		io.WriteString(w, `{"success":false,"messages":["9103 Unknown X-Api-Key or invalid API Key"]}`)
	}))
	defer srv.Close()
	old := cloudflareAPIBase
	cloudflareAPIBase = srv.URL
	defer func() { cloudflareAPIBase = old }()

	p, _ := newCloudflare("cf.example.com", map[string]string{"CF_API_TOKEN": "tok", "CF_ZONE_ID": "z1"})
	err := p.EnsureARecords("cf.example.com", []string{"1.2.3.4"}, RecordOptions{})
	if err == nil {
		t.Fatal("HTTP 200 + success:false 必须返回错误")
	}
	if !strings.Contains(err.Error(), "9103") {
		t.Fatalf("错误信息应包含服务商消息，得到: %v", err)
	}
}

// 记录存在但 IP 不一样时：新建期望的那条，再把旧的删掉。
//
// 为什么不是「就把旧记录改个值」：一个域名可以有多条 A，程序要做的是
// 「对齐到某一组 IP」，按值匹配是唯一能一次说清的逻辑。代价是同一条记录
// 换 IP 后 ID 会变（Cloudflare 那边看不到这个 ID，无影响）。
func TestCloudflareReplacesExistingIP(t *testing.T) {
	var created, deleted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			io.WriteString(w, `{"success":true,"result":[{"id":"r1","name":"cf.example.com","type":"A","content":"9.9.9.9","ttl":1,"proxied":false}]}`)
			return
		case http.MethodPost:
			created = true
		case http.MethodDelete:
			if strings.Contains(r.URL.Path, "/dns_records/r1") {
				deleted = true
			}
		}
		io.WriteString(w, `{"success":true,"result":{}}`)
	}))
	defer srv.Close()
	old := cloudflareAPIBase
	cloudflareAPIBase = srv.URL
	defer func() { cloudflareAPIBase = old }()

	p, _ := newCloudflare("cf.example.com", map[string]string{"CF_API_TOKEN": "tok", "CF_ZONE_ID": "z1"})
	if err := p.EnsureARecords("cf.example.com", []string{"1.2.3.4"}, RecordOptions{}); err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Error("新的 IP 应该被创建")
	}
	if !deleted {
		t.Error("不在期望集合里的旧记录应该被删掉")
	}
}

func TestAliyunEnsureRecord(t *testing.T) {
	var action string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action = r.URL.Query().Get("Action")
		if r.URL.Query().Get("Signature") == "" {
			t.Error("缺少签名")
		}
		if action == "DescribeSubDomainRecords" {
			io.WriteString(w, `{"TotalCount":0,"DomainRecords":{"Record":[]}}`)
			return
		}
		if r.URL.Query().Get("Value") != "1.2.3.4" {
			t.Errorf("Value 错误: %s", r.URL.Query().Get("Value"))
		}
		io.WriteString(w, `{"RecordID":"new"}`)
	}))
	defer srv.Close()
	old := aliyunAPIBase
	aliyunAPIBase = srv.URL
	defer func() { aliyunAPIBase = old }()

	p, _ := newAliyun("cf.example.com", map[string]string{
		"ALIYUN_ACCESS_KEY_ID": "id", "ALIYUN_ACCESS_KEY_SECRET": "secret",
	})
	if err := p.EnsureARecords("cf.example.com", []string{"1.2.3.4"}, RecordOptions{}); err != nil {
		t.Fatal(err)
	}
	if action != "AddDomainRecord" {
		t.Fatalf("记录不存在应调用 AddDomainRecord，实际 %s", action)
	}
}

func TestDNSPodEnsureRecord(t *testing.T) {
	var action string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action = r.Header.Get("X-TC-Action")
		if r.Header.Get("Authorization") == "" || !strings.Contains(r.Header.Get("Authorization"), "TC3-HMAC-SHA256") {
			t.Errorf("缺少 TC3 鉴权头: %q", r.Header.Get("Authorization"))
		}
		if action == "DescribeRecordList" {
			io.WriteString(w, `{"Response":{"RecordCountInfo":{"TotalCount":0},"RecordList":[]}}`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "1.2.3.4") {
			t.Errorf("创建记录未含 IP: %s", body)
		}
		io.WriteString(w, `{"Response":{}}`)
	}))
	defer srv.Close()
	old := dnspodAPIBase
	dnspodAPIBase = srv.URL
	defer func() { dnspodAPIBase = old }()

	p, _ := newDNSPod("cf.example.com", map[string]string{
		"TENCENT_SECRET_ID": "id", "TENCENT_SECRET_KEY": "key",
	})
	if err := p.EnsureARecords("cf.example.com", []string{"1.2.3.4"}, RecordOptions{}); err != nil {
		t.Fatal(err)
	}
	if action != "CreateRecord" {
		t.Fatalf("记录不存在应调用 CreateRecord，实际 %s", action)
	}
}

func TestHuaweiEnsureRecord(t *testing.T) {
	var created bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" || !strings.Contains(r.Header.Get("Authorization"), "SDK-HMAC-SHA256") {
			t.Errorf("缺少华为云鉴权头: %q", r.Header.Get("Authorization"))
		}
		if r.Method == http.MethodGet {
			io.WriteString(w, `{"recordsets":[]}`)
			return
		}
		if r.Method == http.MethodPost {
			created = true
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), "1.2.3.4") {
				t.Errorf("创建记录未含 IP: %s", body)
			}
		}
		io.WriteString(w, `{"id":"x","records":["1.2.3.4"]}`)
	}))
	defer srv.Close()
	old := huaweiAPIBase
	huaweiAPIBase = srv.URL
	defer func() { huaweiAPIBase = old }()

	p, _ := newHuawei("cf.example.com", map[string]string{
		"HUAWEI_AK": "ak", "HUAWEI_SK": "sk", "HUAWEI_ZONE_ID": "z",
	})
	if err := p.EnsureARecords("cf.example.com", []string{"1.2.3.4"}, RecordOptions{}); err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("记录不存在时应创建")
	}
}
