package ddns

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 这一组只验一件事：Verify 是纯读的——它会发查询、能报错、能拿到当前 IP，
// 但绝不允许出现 POST/PUT。用户点「测试密钥」时线上解析不能被改。

func TestCloudflareVerifyIsReadOnly(t *testing.T) {
	var wrote bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			wrote = true
		}
		io.WriteString(w, `{"success":true,"result":[{"id":"r1","name":"cf.example.com","type":"A","content":"9.9.9.9"}]}`)
	}))
	defer srv.Close()
	old := cloudflareAPIBase
	cloudflareAPIBase = srv.URL
	defer func() { cloudflareAPIBase = old }()

	p, _ := newCloudflare("cf.example.com", map[string]string{"CF_API_TOKEN": "tok", "CF_ZONE_ID": "z1"})
	st, err := p.Verify("cf.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !st.Found || st.CurrentIP != "9.9.9.9" {
		t.Fatalf("没拿到当前记录: %+v", st)
	}
	if wrote {
		t.Fatal("Verify 发起了写请求，测试密钥不该改线上解析")
	}
}

func TestCloudflareVerifyEmptyZone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"success":true,"result":[]}`)
	}))
	defer srv.Close()
	old := cloudflareAPIBase
	cloudflareAPIBase = srv.URL
	defer func() { cloudflareAPIBase = old }()

	p, _ := newCloudflare("cf.example.com", map[string]string{"CF_API_TOKEN": "tok", "CF_ZONE_ID": "z1"})
	st, err := p.Verify("cf.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if st.Found {
		t.Fatal("账号里没有这条记录时 Found 应为 false")
	}
}

// 密钥错了要能一眼看出来是密钥的问题，而不是笼统的「失败」。
func TestCloudflareVerifySurfacesAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"success":false,"messages":["9109 Invalid access token"]}`)
	}))
	defer srv.Close()
	old := cloudflareAPIBase
	cloudflareAPIBase = srv.URL
	defer func() { cloudflareAPIBase = old }()

	p, _ := newCloudflare("cf.example.com", map[string]string{"CF_API_TOKEN": "bad", "CF_ZONE_ID": "z1"})
	_, err := p.Verify("cf.example.com")
	if err == nil {
		t.Fatal("密钥无效时必须报错")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("错误信息应带上状态码，得到: %v", err)
	}
}

func TestAliyunVerifyIsReadOnly(t *testing.T) {
	var wrote bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := r.URL.Query().Get("Action"); a != "DescribeSubDomainRecords" {
			wrote = true
		}
		io.WriteString(w, `{"TotalCount":1,"DomainRecords":{"Record":[{"RecordID":"r1","Value":"7.7.7.7"}]}}`)
	}))
	defer srv.Close()
	old := aliyunAPIBase
	aliyunAPIBase = srv.URL
	defer func() { aliyunAPIBase = old }()

	p, _ := newAliyun("cf.example.com", map[string]string{
		"ALIYUN_ACCESS_KEY_ID": "id", "ALIYUN_ACCESS_KEY_SECRET": "secret",
	})
	st, err := p.Verify("cf.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !st.Found || st.CurrentIP != "7.7.7.7" {
		t.Fatalf("没拿到当前记录: %+v", st)
	}
	if wrote {
		t.Fatal("Verify 调用了写接口")
	}
}

func TestDNSPodVerifyIsReadOnly(t *testing.T) {
	var wrote bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := r.Header.Get("X-TC-Action"); a != "DescribeRecordList" {
			wrote = true
		}
		io.WriteString(w, `{"Response":{"RecordCountInfo":{"TotalCount":1},"RecordList":[{"Value":"5.5.5.5"}]}}`)
	}))
	defer srv.Close()
	old := dnspodAPIBase
	dnspodAPIBase = srv.URL
	defer func() { dnspodAPIBase = old }()

	p, _ := newDNSPod("cf.example.com", map[string]string{
		"TENCENT_SECRET_ID": "id", "TENCENT_SECRET_KEY": "key",
	})
	st, err := p.Verify("cf.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !st.Found || st.CurrentIP != "5.5.5.5" {
		t.Fatalf("没拿到当前记录: %+v", st)
	}
	if wrote {
		t.Fatal("Verify 调用了写接口")
	}
}

func TestHuaweiVerifyIsReadOnly(t *testing.T) {
	var wrote bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			wrote = true
		}
		io.WriteString(w, `{"recordsets":[{"id":"x","name":"cf.example.com.","zone_id":"z","type":"A","records":["3.3.3.3"]}]}`)
	}))
	defer srv.Close()
	old := huaweiAPIBase
	huaweiAPIBase = srv.URL
	defer func() { huaweiAPIBase = old }()

	p, _ := newHuawei("cf.example.com", map[string]string{
		"HUAWEI_AK": "ak", "HUAWEI_SK": "sk", "HUAWEI_ZONE_ID": "z",
	})
	st, err := p.Verify("cf.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !st.Found || st.CurrentIP != "3.3.3.3" {
		t.Fatalf("没拿到当前记录: %+v", st)
	}
	if wrote {
		t.Fatal("Verify 调用了写接口")
	}
}
