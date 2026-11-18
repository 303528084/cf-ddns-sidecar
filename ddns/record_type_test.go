package ddns

// 「记录类型」相关测试（2026-11-18 起支持写 AAAA）。
//
// 这一组盯的是本方案里**最容易翻车**的一件事：A 和 AAAA 是同一域名下
// 互相独立的两族记录，能同时存在。写 AAAA 时如果顺手删了 A（或反过来），
// 用户正在用的解析会安静地断掉——没有任何报错，只有访问突然变慢或打不开。
//
// 所以这里不是测「能不能写 AAAA」，而是测「写 AAAA 的时候有没有碰到 A」：
// 用会**按 type 过滤**的假服务端（照各家的真实行为建模），再看写请求落到哪。

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizeRecordType(t *testing.T) {
	ok := map[string]string{
		"":         TypeA, // 老配置零值：必须还是 A
		"A":        TypeA,
		"a":        TypeA,
		"AAAA":     TypeAAAA,
		"aaaa":     TypeAAAA,
		"  AAAA  ": TypeAAAA,
	}
	for in, want := range ok {
		got, err := NormalizeRecordType(in)
		if err != nil || got != want {
			t.Errorf("%q 应归一成 %q，实际 %q（err=%v）", in, want, got, err)
		}
	}
	// 不认识的值必须报错，**不能**回落成 A：回落就等于「用户以为在写 v6，
	// 实际写了 v4」，这种错不会有任何地方提示。
	for _, bad := range []string{"CNAME", "TXT", "AAAAA", "A6", "6"} {
		if got, err := NormalizeRecordType(bad); err == nil {
			t.Errorf("%q 应该报错，实际被当成 %q", bad, got)
		}
	}
}

// 地址族把关：类型和地址对不上时一条都不许写。
func TestPrepareIPsFamilyGuard(t *testing.T) {
	v4 := []string{"1.1.1.1", "2.2.2.2"}
	v6 := []string{"2606:4700::1", "2606:4700::2"}

	if got, err := prepareIPs(v4, TypeA); err != nil || len(got) != 2 {
		t.Fatalf("A + v4 应通过，实际 %v（err=%v）", got, err)
	}
	if got, err := prepareIPs(v6, TypeAAAA); err != nil || len(got) != 2 {
		t.Fatalf("AAAA + v6 应通过，实际 %v（err=%v）", got, err)
	}
	// 错配：必须报错，绝不能把 v4 当 AAAA 写出去。
	if _, err := prepareIPs(v4, TypeAAAA); err == nil {
		t.Error("AAAA + v4 应该报错")
	}
	if _, err := prepareIPs(v6, TypeA); err == nil {
		t.Error("A + v6 应该报错")
	}
	// 4-in-6 不是合法的 AAAA 值。
	if _, err := prepareIPs([]string{"::ffff:1.2.3.4"}, TypeAAAA); err == nil {
		t.Error("::ffff:1.2.3.4 不该被当成合法 AAAA")
	}
	// 根本不是 IP 的串也要拦住。
	if _, err := prepareIPs([]string{"not-an-ip"}, TypeA); err == nil {
		t.Error("非 IP 串应该报错")
	}
}

// cfTypedServer 是照 Cloudflare 真实行为建模的假服务端：GET 按 type 过滤。
//
// 用「按 type 过滤」而不是把全部记录都吐回去，是因为后者会掩盖 bug——
// 真实接口是过滤的，我们的代码也确实依赖这一点来保证不跨类型误删。
// 但「依赖对端」本身就是风险，所以 provider 里还额外比对了 rec.Type，
// 这个测试同时把那条兜底也覆盖了。
type cfTypedServer struct {
	records []cfRecord
	gets    []string // 每次 GET 的 type 参数
	creates []map[string]any
	deletes []string // 删掉的记录 id
}

func newCFTypedServer(t *testing.T, records []cfRecord) (*httptest.Server, *cfTypedServer) {
	t.Helper()
	fs := &cfTypedServer{records: records}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			rtype := r.URL.Query().Get("type")
			fs.gets = append(fs.gets, rtype)
			out := make([]cfRecord, 0, len(fs.records))
			for _, rec := range fs.records {
				if rec.Type == rtype {
					out = append(out, rec)
				}
			}
			b, _ := json.Marshal(map[string]any{"success": true, "result": out})
			_, _ = w.Write(b)
		case http.MethodPost:
			var m map[string]any
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &m)
			fs.creates = append(fs.creates, m)
			io.WriteString(w, `{"success":true,"result":{}}`)
		case http.MethodPut:
			io.WriteString(w, `{"success":true,"result":{}}`)
		case http.MethodDelete:
			fs.deletes = append(fs.deletes, r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:])
			io.WriteString(w, `{"success":true,"result":{}}`)
		}
	}))
	return srv, fs
}

// 写 AAAA 时：只动 AAAA，A 一条都不许碰。
func TestCloudflareWriteAAAADoesNotTouchA(t *testing.T) {
	srv, fs := newCFTypedServer(t, []cfRecord{
		{ID: "a1", Name: "cf.example.com", Type: "A", Content: "1.1.1.1"},
		{ID: "a2", Name: "cf.example.com", Type: "A", Content: "9.9.9.9"},
		{ID: "q1", Name: "cf.example.com", Type: "AAAA", Content: "2606:4700::1"},
	})
	defer srv.Close()
	p := withCF(t, srv)

	err := p.EnsureRecords("cf.example.com", []string{"2606:4700::2"}, RecordOptions{Type: TypeAAAA})
	if err != nil {
		t.Fatal(err)
	}

	// 查询必须查 AAAA，不能查 A——否则后面「删多余」删的就是 A 记录。
	for _, g := range fs.gets {
		if g != TypeAAAA {
			t.Errorf("写 AAAA 时查询用的类型应是 AAAA，实际 %q", g)
		}
	}
	if len(fs.creates) != 1 {
		t.Fatalf("该只新建 1 条，实际 %d 条：%v", len(fs.creates), fs.creates)
	}
	if fs.creates[0]["type"] != TypeAAAA || fs.creates[0]["content"] != "2606:4700::2" {
		t.Errorf("新建的应是 AAAA 2606:4700::2，实际 %v", fs.creates[0])
	}
	// 只有过期的 AAAA（q1）能被删。
	if len(fs.deletes) != 1 || fs.deletes[0] != "q1" {
		t.Errorf("该只删过期的 AAAA（q1），实际删了 %v", fs.deletes)
	}
}

// 反过来：写 A 时也不能碰 AAAA。
func TestCloudflareWriteADoesNotTouchAAAA(t *testing.T) {
	srv, fs := newCFTypedServer(t, []cfRecord{
		{ID: "a1", Name: "cf.example.com", Type: "A", Content: "9.9.9.9"},
		{ID: "q1", Name: "cf.example.com", Type: "AAAA", Content: "2606:4700::1"},
	})
	defer srv.Close()
	p := withCF(t, srv)

	if err := p.EnsureRecords("cf.example.com", []string{"1.1.1.1"}, RecordOptions{}); err != nil {
		t.Fatal(err)
	}
	if fs.creates[0]["type"] != TypeA {
		t.Errorf("默认（零值）应写 A，实际 %v", fs.creates[0]["type"])
	}
	if len(fs.deletes) != 1 || fs.deletes[0] != "a1" {
		t.Errorf("该只删过期的 A（a1），实际删了 %v", fs.deletes)
	}
	for _, id := range fs.deletes {
		if id == "q1" {
			t.Error("写 A 时删掉了 AAAA 记录——这会让 v6 解析直接断掉")
		}
	}
}

// 华为云的写法是「整集覆盖」，所以查错类型等于把另一族整个盖掉——这条最危险。
func TestHuaweiWriteAAAAOverwritesOnlyAAAARecordset(t *testing.T) {
	var putPath string
	var putBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// 照真实行为按 type 过滤：A 和 AAAA 是两个不同的记录集。
			if r.URL.Query().Get("type") == TypeAAAA {
				io.WriteString(w, `{"recordsets":[{"id":"rsAAAA","name":"cf.example.com.","zone_id":"z","type":"AAAA","ttl":300,"records":["2606:4700::9"]}]}`)
				return
			}
			io.WriteString(w, `{"recordsets":[{"id":"rsA","name":"cf.example.com.","zone_id":"z","type":"A","ttl":300,"records":["1.1.1.1"]}]}`)
			return
		}
		putPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &putBody)
		io.WriteString(w, `{"id":"rsAAAA","records":[]}`)
	}))
	defer srv.Close()
	old := huaweiAPIBase
	huaweiAPIBase = srv.URL
	defer func() { huaweiAPIBase = old }()

	p, _ := newHuawei("cf.example.com", map[string]string{
		"HUAWEI_AK": "ak", "HUAWEI_SK": "sk", "HUAWEI_ZONE_ID": "z",
	})
	if err := p.EnsureRecords("cf.example.com", []string{"2606:4700::2", "2606:4700::3"}, RecordOptions{Type: TypeAAAA}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(putPath, "/rsAAAA") {
		t.Fatalf("必须改 AAAA 的记录集 rsAAAA，实际改的是 %s（改到 rsA 就把 A 记录整族盖掉了）", putPath)
	}
	if putBody["type"] != TypeAAAA {
		t.Errorf("PUT 的类型应是 AAAA，实际 %v", putBody["type"])
	}
	recs, _ := putBody["records"].([]any)
	if len(recs) != 2 || recs[0] != "2606:4700::2" {
		t.Errorf("records 应换成新的两条 v6 地址，实际 %v", putBody["records"])
	}
}

// 阿里云 / DNSPod 靠「查询参数带类型」来保证不跨类型：查 AAAA 就只回 AAAA，
// 后面的删多余自然删不到 A。这里只钉住「参数确实带对了」。
func TestAliyunAndDNSPodQueryCarryRecordType(t *testing.T) {
	var aliyunType string
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("Action") == "DescribeSubDomainRecords" {
			aliyunType = r.URL.Query().Get("Type")
			io.WriteString(w, `{"DomainRecords":{"Record":[]}}`)
			return
		}
		io.WriteString(w, `{}`)
	}))
	defer srvA.Close()
	oldA := aliyunAPIBase
	aliyunAPIBase = srvA.URL
	defer func() { aliyunAPIBase = oldA }()

	pa, _ := newAliyun("cf.example.com", map[string]string{
		"ALIYUN_ACCESS_KEY_ID": "id", "ALIYUN_ACCESS_KEY_SECRET": "secret",
	})
	if err := pa.EnsureRecords("cf.example.com", []string{"2606:4700::2"}, RecordOptions{Type: TypeAAAA}); err != nil {
		t.Fatal(err)
	}
	if aliyunType != TypeAAAA {
		t.Errorf("阿里云查询 TYPE 应为 AAAA，实际 %q", aliyunType)
	}

	var dnspodType string
	srvD := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &m)
		if r.Header.Get("X-TC-Action") == "DescribeRecordList" {
			dnspodType, _ = m["RecordType"].(string)
			io.WriteString(w, `{"Response":{"RecordList":[]}}`)
			return
		}
		io.WriteString(w, `{"Response":{}}`)
	}))
	defer srvD.Close()
	oldD := dnspodAPIBase
	dnspodAPIBase = srvD.URL
	defer func() { dnspodAPIBase = oldD }()

	pd, _ := newDNSPod("cf.example.com", map[string]string{
		"TENCENT_SECRET_ID": "id", "TENCENT_SECRET_KEY": "key",
	})
	if err := pd.EnsureRecords("cf.example.com", []string{"2606:4700::2"}, RecordOptions{Type: TypeAAAA}); err != nil {
		t.Fatal(err)
	}
	if dnspodType != TypeAAAA {
		t.Errorf("DNSPod 查询 RecordType 应为 AAAA，实际 %q", dnspodType)
	}
}

// TestNormalizeRecordMode：用户选的「同步模式」必须收敛成三种之一。
//
// 和 NormalizeRecordType 的区别要钉死：后者只认单族（服务商那边没有
// 「A+AAAA」这种记录），前者才认「两个都写」。混用会让校验对自己说谎。
func TestNormalizeRecordMode(t *testing.T) {
	ok := map[string]string{
		"":          TypeA, // 老配置没有这个字段
		"A":         TypeA,
		"a":         TypeA,
		"AAAA":      TypeAAAA,
		" aaaa ":    TypeAAAA,
		"A+AAAA":    ModeBoth,
		"a+aaaa":    ModeBoth,
		"AAAA+A":    ModeBoth, // 顺序反了也认
		" A + AAAA": ModeBoth, // 带空格也认
	}
	for in, want := range ok {
		got, err := NormalizeRecordMode(in)
		if err != nil {
			t.Fatalf("NormalizeRecordMode(%q) 不该报错，实际 %v", in, err)
		}
		if got != want {
			t.Errorf("NormalizeRecordMode(%q) 应得到 %q，实际 %q", in, want, got)
		}
	}

	// 非法值必须报错，不能回落成 A：用户以为在写 v6、实际写了 v4，
	// 这件事不会在任何日志里露头。
	for _, bad := range []string{"CNAME", "AAAAA", "A+", "A+AAAA+AAAA", "MX"} {
		if got, err := NormalizeRecordMode(bad); err == nil {
			t.Errorf("NormalizeRecordMode(%q) 应报错，实际返回 %q", bad, got)
		}
	}

	// 关键的一条：ModeBoth 是「同步模式」，不是记录类型，必须被单族那层拒绝。
	if _, err := NormalizeRecordType(ModeBoth); err == nil {
		t.Errorf("NormalizeRecordType(%q) 应报错——它只认 A / AAAA，"+
			"放过去就会有人拿它去查服务商的记录", ModeBoth)
	}
}

// TestFamiliesOf：展开结果决定「这一轮到底写几张表」。
//
// 展开错了的后果不是报错，是**少写一族而没人知道**——日志里只有一行
// 「已更新」，用户以为两个都写了。
func TestFamiliesOf(t *testing.T) {
	cases := []struct {
		mode string
		want []string
	}{
		{TypeA, []string{TypeA}},
		{TypeAAAA, []string{TypeAAAA}},
		{ModeBoth, []string{TypeA, TypeAAAA}}, // A 在前：日志先说 IPv4
		{"", []string{TypeA}},                 // 认不出来按 A（读配置的路径不该报错）
		{"AAAA+A", []string{TypeA, TypeAAAA}},
	}
	for _, c := range cases {
		got := FamiliesOf(c.mode)
		if len(got) != len(c.want) {
			t.Fatalf("FamiliesOf(%q) 应得到 %v，实际 %v", c.mode, c.want, got)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("FamiliesOf(%q) 应得到 %v，实际 %v", c.mode, c.want, got)
			}
		}
	}
}
