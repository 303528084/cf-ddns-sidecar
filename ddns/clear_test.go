package ddns

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 单族模式下要清掉另一族，四家的 ClearRecords 各测一遍。
// 共同点：只删指定类型的记录，另一族一条都不许碰——删错会让另一套解析安静地断掉。

func TestCloudflareClearRecords(t *testing.T) {
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if got := r.URL.Query().Get("type"); got != "AAAA" {
				t.Errorf("只该查 AAAA，实际查了 %q", got)
			}
			// 混进一条 A 和一条别的域名：服务端已按 name + type 过滤，这里模拟
			// 「对端没照做」的情况，确认我们自己那道判断还在。
			io.WriteString(w, `{"success":true,"result":[
				{"id":"r1","name":"cf.example.com","type":"AAAA","content":"2408:1::1"},
				{"id":"r2","name":"CF.example.com","type":"AAAA","content":"2408:1::2"},
				{"id":"keep1","name":"cf.example.com","type":"A","content":"1.2.3.4"},
				{"id":"keep2","name":"other.example.com","type":"AAAA","content":"2408:1::9"}]}`)
		case http.MethodDelete:
			deleted = append(deleted, strings.TrimPrefix(r.URL.Path, "/zones/z1/dns_records/"))
			io.WriteString(w, `{"success":true}`)
		default:
			t.Errorf("非预期方法 %s", r.Method)
		}
	}))
	defer srv.Close()
	old := cloudflareAPIBase
	cloudflareAPIBase = srv.URL
	defer func() { cloudflareAPIBase = old }()

	p, _ := newCloudflare("cf.example.com", map[string]string{"CF_API_TOKEN": "tok", "CF_ZONE_ID": "z1"})
	n, err := p.ClearRecords("cf.example.com", "AAAA")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || len(deleted) != 2 {
		t.Fatalf("应删 2 条 AAAA，实际 n=%d deleted=%v", n, deleted)
	}
	for _, id := range deleted {
		if id != "r1" && id != "r2" {
			t.Fatalf("删到了不该删的记录 %q（另一族或别的域名）", id)
		}
	}
}

func TestDNSPodClearRecords(t *testing.T) {
	var deleted int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("X-TC-Action") {
		case "DescribeRecordList":
			io.WriteString(w, `{"Response":{"RecordCountInfo":{"TotalCount":2},"RecordList":[
				{"RecordId":7,"Value":"2408:1::1"},{"RecordId":8,"Value":"2408:1::2"}]}}`)
		case "DeleteRecord":
			deleted++
			io.WriteString(w, `{"Response":{}}`)
		default:
			t.Errorf("非预期动作 %s", r.Header.Get("X-TC-Action"))
			io.WriteString(w, `{"Response":{}}`)
		}
	}))
	defer srv.Close()
	old := dnspodAPIBase
	dnspodAPIBase = srv.URL
	defer func() { dnspodAPIBase = old }()

	p, _ := newDNSPod("cf.example.com", map[string]string{
		"TENCENT_SECRET_ID": "id", "TENCENT_SECRET_KEY": "key",
	})
	n, err := p.ClearRecords("cf.example.com", "AAAA")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || deleted != 2 {
		t.Fatalf("应删 2 条，实际 n=%d deleted=%d", n, deleted)
	}
}

func TestAliyunClearRecords(t *testing.T) {
	var deleted []string
	var queriedType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch q.Get("Action") {
		case "DescribeSubDomainRecords":
			queriedType = q.Get("Type")
			io.WriteString(w, `{"TotalCount":2,"DomainRecords":{"Record":[
				{"RecordID":"a","Value":"2408:1::1"},{"RecordID":"b","Value":"2408:1::2"}]}}`)
		case "DeleteDomainRecord":
			deleted = append(deleted, q.Get("RecordId"))
			io.WriteString(w, `{}`)
		default:
			t.Errorf("非预期动作 %s", q.Get("Action"))
			io.WriteString(w, `{}`)
		}
	}))
	defer srv.Close()
	old := aliyunAPIBase
	aliyunAPIBase = srv.URL
	defer func() { aliyunAPIBase = old }()

	p, _ := newAliyun("cf.example.com", map[string]string{
		"ALIYUN_ACCESS_KEY_ID": "id", "ALIYUN_ACCESS_KEY_SECRET": "secret",
	})
	n, err := p.ClearRecords("cf.example.com", "AAAA")
	if err != nil {
		t.Fatal(err)
	}
	if queriedType != "AAAA" {
		t.Errorf("查询类型应为 AAAA，实际 %q", queriedType)
	}
	if n != 2 || len(deleted) != 2 {
		t.Fatalf("应删 2 条，实际 n=%d deleted=%v", n, deleted)
	}
}

// 华为云一个记录集就是一整族，清一族 = 删一个集；返回值按集里的地址条数算，
// 这样四家日志里那个数字含义一致。
func TestHuaweiClearRecords(t *testing.T) {
	var deletedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if got := r.URL.Query().Get("type"); got != "AAAA" {
				t.Errorf("只该查 AAAA，实际查了 %q", got)
			}
			io.WriteString(w, `{"recordsets":[{"id":"rs1","name":"cf.example.com.","zone_id":"z","type":"AAAA","ttl":300,"records":["2408:1::1","2408:1::2"]}]}`)
		case http.MethodDelete:
			deletedPath = r.URL.Path
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("非预期方法 %s", r.Method)
		}
	}))
	defer srv.Close()
	old := huaweiAPIBase
	huaweiAPIBase = srv.URL
	defer func() { huaweiAPIBase = old }()

	p, _ := newHuawei("cf.example.com", map[string]string{
		"HUAWEI_AK": "ak", "HUAWEI_SK": "sk", "HUAWEI_ZONE_ID": "z",
	})
	n, err := p.ClearRecords("cf.example.com", "AAAA")
	if err != nil {
		t.Fatal(err)
	}
	if deletedPath != "/v2.1/zones/z/recordsets/rs1" {
		t.Fatalf("删错了记录集: %q", deletedPath)
	}
	if n != 2 {
		t.Errorf("应报告 2 条地址被删，实际 %d", n)
	}
}

// 记录集本来就不存在时不能报错：第一次跑、或者上一轮已经清过了。
func TestHuaweiClearRecordsMissing(t *testing.T) {
	var wrote bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			wrote = true
		}
		io.WriteString(w, `{"recordsets":[]}`)
	}))
	defer srv.Close()
	old := huaweiAPIBase
	huaweiAPIBase = srv.URL
	defer func() { huaweiAPIBase = old }()

	p, _ := newHuawei("cf.example.com", map[string]string{
		"HUAWEI_AK": "ak", "HUAWEI_SK": "sk", "HUAWEI_ZONE_ID": "z",
	})
	n, err := p.ClearRecords("cf.example.com", "AAAA")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 || wrote {
		t.Fatalf("没有记录集时应该什么都不做，实际 n=%d 写了=%v", n, wrote)
	}
}

// 类型写错必须报错，绝不能被当成 A 悄悄删掉一串 IPv4 记录。
// 非法值在发请求之前就被 NormalizeRecordType 拦下，所以这里不会碰到网络。
func TestClearRecordsRejectsBadType(t *testing.T) {
	p, err := newCloudflare("cf.example.com", map[string]string{"CF_API_TOKEN": "tok", "CF_ZONE_ID": "z1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{ModeBoth, "CNAME", "AAAA+A"} {
		if _, err := p.ClearRecords("cf.example.com", bad); err == nil {
			t.Errorf("类型 %q 应该被拒绝", bad)
		}
	}
}
