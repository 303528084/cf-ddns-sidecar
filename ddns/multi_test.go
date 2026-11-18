package ddns

// 「同步多个 IP」的对齐逻辑测试。
//
// 这一组盯的是三件一旦搞错就会把用户域名弄坏的事：
//  1. 期望列表为空时**一个请求都不许发**——测速失败时传空列表进来是可能的，
//     要是被理解成「期望集合为空」，域名就被清空了，访问当场断。
//  2. 顺序必须是「先补齐、再删多余」。反过来的话，中间有一小段时间这个域名
//     一条 A 记录都没有，正在访问的人会解析失败。
//  3. 不在期望集合里的旧记录必须删掉（用户明确选了「不要原有记录」）。

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// cfRecorder 记录假 Cloudflare 收到的写请求，按发生顺序。
type cfRecorder struct {
	methods []string
	bodies  []map[string]any
	paths   []string
	listed  string
}

func newCFServer(t *testing.T, listed string) (*httptest.Server, *cfRecorder) {
	t.Helper()
	rec := &cfRecorder{listed: listed}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			io.WriteString(w, rec.listed)
			return
		case http.MethodDelete:
			rec.methods = append(rec.methods, "DELETE")
			rec.paths = append(rec.paths, r.URL.Path)
		default:
			var m map[string]any
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &m)
			rec.methods = append(rec.methods, r.Method)
			rec.bodies = append(rec.bodies, m)
			rec.paths = append(rec.paths, r.URL.Path)
		}
		io.WriteString(w, `{"success":true,"result":{}}`)
	}))
	return srv, rec
}

func withCF(t *testing.T, srv *httptest.Server) *cloudflare {
	t.Helper()
	old := cloudflareAPIBase
	cloudflareAPIBase = srv.URL
	t.Cleanup(func() { cloudflareAPIBase = old })
	p, _ := newCloudflare("cf.example.com", map[string]string{"CF_API_TOKEN": "tok", "CF_ZONE_ID": "z1"})
	return p.(*cloudflare)
}

func TestNormalizeIPs(t *testing.T) {
	got := normalizeIPs([]string{"1.1.1.1", "", "  ", "2.2.2.2", "1.1.1.1", " 3.3.3.3 "})
	want := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}
	if len(got) != len(want) {
		t.Fatalf("去重/去空后应剩 %d 条，得到 %v", len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 条应为 %s（顺序要保留排名），实际 %s", i, want[i], got[i])
		}
	}
}

// 空列表 = 「这次没结果，别动」。一个请求都不许发。
func TestCloudflareEmptyListTouchesNothing(t *testing.T) {
	srv, rec := newCFServer(t, `{"success":true,"result":[{"id":"r1","name":"cf.example.com","type":"A","content":"9.9.9.9","ttl":1,"proxied":false}]}`)
	defer srv.Close()
	p := withCF(t, srv)

	for _, ips := range [][]string{nil, {}, {"  ", ""}} {
		if err := p.EnsureRecords("cf.example.com", ips, RecordOptions{}); err != nil {
			t.Fatalf("空列表不该报错: %v", err)
		}
	}
	if len(rec.methods) != 0 {
		t.Fatalf("空列表时不该发出任何写请求（更不能删记录），实际发出：%v", rec.methods)
	}
}

// 一次写 5 条：5 次创建，内容与顺序都要对得上。
func TestCloudflareWritesAllIPs(t *testing.T) {
	srv, rec := newCFServer(t, `{"success":true,"result":[]}`)
	defer srv.Close()
	p := withCF(t, srv)

	ips := []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"}
	if err := p.EnsureRecords("cf.example.com", ips, RecordOptions{TTL: 600}); err != nil {
		t.Fatal(err)
	}
	if len(rec.methods) != 5 {
		t.Fatalf("应创建 5 条，实际 %d 次写请求（%v）", len(rec.methods), rec.methods)
	}
	for i, want := range ips {
		if rec.bodies[i]["content"] != want {
			t.Errorf("第 %d 条应为 %s，实际 %v", i, want, rec.bodies[i]["content"])
		}
		if rec.bodies[i]["ttl"] != float64(600) {
			t.Errorf("第 %d 条 ttl 应为 600，实际 %v", i, rec.bodies[i]["ttl"])
		}
	}
}

// 只删多余的：已有的两条正好是期望的，就不该再建、也不该删；第三条要删。
func TestCloudflareRemovesOnlyStale(t *testing.T) {
	srv, rec := newCFServer(t, `{"success":true,"result":[
		{"id":"r1","name":"cf.example.com","type":"A","content":"1.1.1.1","ttl":1,"proxied":false},
		{"id":"r2","name":"cf.example.com","type":"A","content":"2.2.2.2","ttl":1,"proxied":false},
		{"id":"r3","name":"cf.example.com","type":"A","content":"9.9.9.9","ttl":1,"proxied":false}]}`)
	defer srv.Close()
	p := withCF(t, srv)

	if err := p.EnsureRecords("cf.example.com", []string{"1.1.1.1", "2.2.2.2"}, RecordOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(rec.methods) != 1 || rec.methods[0] != "DELETE" {
		t.Fatalf("只该删 1 条（r3），实际请求：%v", rec.methods)
	}
	if !strings.HasSuffix(rec.paths[0], "/r3") {
		t.Errorf("该删的是 r3，实际删了 %s", rec.paths[0])
	}
}

// 顺序铁律：所有补齐/校准动作都排在删除之前。
func TestCloudflareAddsBeforeDeleting(t *testing.T) {
	srv, rec := newCFServer(t, `{"success":true,"result":[
		{"id":"r1","name":"cf.example.com","type":"A","content":"9.9.9.9","ttl":1,"proxied":false}]}`)
	defer srv.Close()
	p := withCF(t, srv)

	if err := p.EnsureRecords("cf.example.com", []string{"1.1.1.1", "2.2.2.2"}, RecordOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(rec.methods) != 3 {
		t.Fatalf("应为 2 次创建 + 1 次删除，实际 %v", rec.methods)
	}
	if rec.methods[2] != "DELETE" {
		t.Fatalf("删除必须排最后，实际顺序 %v", rec.methods)
	}
}

// 别的域名的记录一概不碰。
func TestCloudflareIgnoresOtherNames(t *testing.T) {
	srv, rec := newCFServer(t, `{"success":true,"result":[
		{"id":"r1","name":"other.example.com","type":"A","content":"9.9.9.9","ttl":1,"proxied":false},
		{"id":"r2","name":"cf.example.com","type":"AAAA","content":"::1","ttl":1,"proxied":false}]}`)
	defer srv.Close()
	p := withCF(t, srv)

	if err := p.EnsureRecords("cf.example.com", []string{"1.1.1.1"}, RecordOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, pth := range rec.paths {
		if strings.HasSuffix(pth, "/r1") || strings.HasSuffix(pth, "/r2") {
			t.Fatalf("不能删别的域名 / 别的类型的记录，实际删了 %s", pth)
		}
	}
}

// 阿里云：补齐缺失的、删掉多余的。
func TestAliyunEnsureRecords(t *testing.T) {
	var added, deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch q.Get("Action") {
		case "DescribeSubDomainRecords":
			io.WriteString(w, `{"TotalCount":2,"DomainRecords":{"Record":[
				{"RecordID":"old1","Value":"9.9.9.9","TTL":600},
				{"RecordID":"keep","Value":"1.1.1.1","TTL":600}]}}`)
		case "AddDomainRecord":
			added = append(added, q.Get("Value"))
			io.WriteString(w, `{"RecordID":"new"}`)
		case "DeleteDomainRecord":
			deleted = append(deleted, q.Get("RecordId"))
			io.WriteString(w, `{}`)
		default:
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
	if err := p.EnsureRecords("cf.example.com", []string{"1.1.1.1", "2.2.2.2"}, RecordOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(added) != 1 || added[0] != "2.2.2.2" {
		t.Errorf("只该补 2.2.2.2，实际新增 %v", added)
	}
	if len(deleted) != 1 || deleted[0] != "old1" {
		t.Errorf("只该删 old1，实际删除 %v", deleted)
	}
}

// DNSPod：补齐缺失的、删掉多余的。
func TestDNSPodEnsureRecords(t *testing.T) {
	var created, deleted int
	var createdValues []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("X-TC-Action") {
		case "DescribeRecordList":
			io.WriteString(w, `{"Response":{"RecordCountInfo":{"TotalCount":1},"RecordList":[
				{"RecordId":7,"Value":"9.9.9.9","TTL":600}]}}`)
		case "CreateRecord":
			created++
			var m map[string]any
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &m)
			if v, ok := m["Value"].(string); ok {
				createdValues = append(createdValues, v)
			}
			io.WriteString(w, `{"Response":{}}`)
		case "DeleteRecord":
			deleted++
			io.WriteString(w, `{"Response":{}}`)
		default:
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
	if err := p.EnsureRecords("cf.example.com", []string{"1.1.1.1", "2.2.2.2"}, RecordOptions{}); err != nil {
		t.Fatal(err)
	}
	if created != 2 {
		t.Errorf("应新建 2 条，实际 %d（%v）", created, createdValues)
	}
	if deleted != 1 {
		t.Errorf("应删除 1 条旧记录，实际 %d", deleted)
	}
}

// 华为云：一次 PUT 把 records 整体换掉，不需要逐条删。
func TestHuaweiEnsureRecordsMultiple(t *testing.T) {
	var putBody map[string]any
	var writes int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			io.WriteString(w, `{"recordsets":[{"id":"rs1","name":"cf.example.com.","zone_id":"z","type":"A","ttl":300,"records":["9.9.9.9"]}]}`)
			return
		}
		writes++
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &putBody)
		io.WriteString(w, `{"id":"rs1","records":[]}`)
	}))
	defer srv.Close()
	old := huaweiAPIBase
	huaweiAPIBase = srv.URL
	defer func() { huaweiAPIBase = old }()

	p, _ := newHuawei("cf.example.com", map[string]string{
		"HUAWEI_AK": "ak", "HUAWEI_SK": "sk", "HUAWEI_ZONE_ID": "z",
	})
	if err := p.EnsureRecords("cf.example.com", []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"}, RecordOptions{}); err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Errorf("华为云一次 PUT 就该搞定，实际写了 %d 次", writes)
	}
	recs, ok := putBody["records"].([]any)
	if !ok || len(recs) != 3 {
		t.Fatalf("records 应为 3 条，实际 %v", putBody["records"])
	}
	if recs[0] != "1.1.1.1" || recs[2] != "3.3.3.3" {
		t.Errorf("顺序要按排名保留，实际 %v", recs)
	}
}
