package ddns

// TTL 与云朵开关的测试。
//
// 这两项是 2026-11-17 从「写死在代码里」改成「用户可配」的。改的时候有两件
// 事必须钉死，否则升级会悄悄改坏用户线上已有的解析：
//
//  ① 老配置（没有 ttl / proxied 字段）读出来是零值，写出去必须和升级前
//     一模一样：Cloudflare 自动、DNSPod 600、华为云 300、阿里云不传。
//  ② 「IP 相同就跳过」这条捷径不能只看 IP。用户刚把云朵打开时 IP 一个字
//     没变，只看 IP 就会跳过写入，界面显示保存成功、线上却毫无变化。

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCfTTL 云朵打开时 Cloudflare 只接受「自动」，填别的值接口会报错。
func TestCfTTL(t *testing.T) {
	cases := []struct {
		opt  RecordOptions
		want int
	}{
		{RecordOptions{}, 1},           // 没填 → 自动，等于升级前的行为
		{RecordOptions{TTL: -5}, 1},    // 脏数据也不该传出负数
		{RecordOptions{TTL: 600}, 600}, // 正常指定
		{RecordOptions{TTL: 3600}, 3600},
		{RecordOptions{TTL: 600, Proxied: true}, 1}, // 开云朵 → 只能自动
		{RecordOptions{Proxied: true}, 1},
	}
	for _, c := range cases {
		if got := c.opt.cfTTL(); got != c.want {
			t.Errorf("cfTTL(%+v) = %d，期望 %d", c.opt, got, c.want)
		}
	}
}

// TestCloudflareCreateCarriesTTLAndProxied 新建记录时两项都要递上去。
//
// 特意分成两个子测试：只测「开云朵」那一种是不够的——开云朵时 ttl 恰好
// 也是 1，跟写死的旧值一模一样，就算代码根本没读配置也会「通过」。
// 必须有一条「关云朵 + 自定义 TTL」，才能真正验到配置生效。
func TestCloudflareCreateCarriesTTLAndProxied(t *testing.T) {
	for _, c := range []struct {
		name    string
		opt     RecordOptions
		wantTTL float64
		wantPx  bool
	}{
		{"自定义TTL且不开云朵", RecordOptions{TTL: 3600}, 3600, false},
		{"开云朵时TTL强制自动", RecordOptions{TTL: 3600, Proxied: true}, 1, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var body map[string]any
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					io.WriteString(w, `{"success":true,"result":[]}`)
					return
				}
				raw, _ := io.ReadAll(r.Body)
				json.Unmarshal(raw, &body)
				io.WriteString(w, `{"success":true,"result":{}}`)
			}))
			defer srv.Close()
			old := cloudflareAPIBase
			cloudflareAPIBase = srv.URL
			defer func() { cloudflareAPIBase = old }()

			p, _ := newCloudflare("cf.example.com", map[string]string{"CF_API_TOKEN": "tok", "CF_ZONE_ID": "z1"})
			if err := p.EnsureARecord("cf.example.com", "1.2.3.4", c.opt); err != nil {
				t.Fatal(err)
			}
			if body["ttl"] != c.wantTTL {
				t.Errorf("ttl 应为 %v，实际 %v", c.wantTTL, body["ttl"])
			}
			if body["proxied"] != c.wantPx {
				t.Errorf("proxied 应为 %v，实际 %v", c.wantPx, body["proxied"])
			}
		})
	}
}

// TestCloudflareSkipsWhenNothingToDo 三样全对上时不发任何写请求。
func TestCloudflareSkipsWhenNothingToDo(t *testing.T) {
	var writes int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			io.WriteString(w, `{"success":true,"result":[{"id":"r1","name":"cf.example.com","type":"A","content":"1.2.3.4","ttl":1,"proxied":false}]}`)
			return
		}
		writes++
		io.WriteString(w, `{"success":true,"result":{}}`)
	}))
	defer srv.Close()
	old := cloudflareAPIBase
	cloudflareAPIBase = srv.URL
	defer func() { cloudflareAPIBase = old }()

	p, _ := newCloudflare("cf.example.com", map[string]string{"CF_API_TOKEN": "tok", "CF_ZONE_ID": "z1"})
	if err := p.EnsureARecord("cf.example.com", "1.2.3.4", RecordOptions{}); err != nil {
		t.Fatal(err)
	}
	if writes != 0 {
		t.Fatalf("已经符合期望时不该写记录，实际写了 %d 次", writes)
	}
}

// TestCloudflareWritesWhenOnlyProxiedDiffers 这条是整个改动的核心回归：
// IP 没变、只有云朵变了，也必须真的写一次。
func TestCloudflareWritesWhenOnlyProxiedDiffers(t *testing.T) {
	var put map[string]any
	var putCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			io.WriteString(w, `{"success":true,"result":[{"id":"r1","name":"cf.example.com","type":"A","content":"1.2.3.4","ttl":1,"proxied":false}]}`)
			return
		}
		putCount++
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &put)
		io.WriteString(w, `{"success":true,"result":{}}`)
	}))
	defer srv.Close()
	old := cloudflareAPIBase
	cloudflareAPIBase = srv.URL
	defer func() { cloudflareAPIBase = old }()

	p, _ := newCloudflare("cf.example.com", map[string]string{"CF_API_TOKEN": "tok", "CF_ZONE_ID": "z1"})
	if err := p.EnsureARecord("cf.example.com", "1.2.3.4", RecordOptions{Proxied: true}); err != nil {
		t.Fatal(err)
	}
	if putCount != 1 {
		t.Fatalf("只改了云朵也必须写一次，实际写了 %d 次", putCount)
	}
	if put["proxied"] != true {
		t.Errorf("写出去的 proxied 应为 true，实际 %v", put["proxied"])
	}
}

// TestCloudflareWritesWhenOnlyTTLDiffers 同理，只改 TTL 也要写。
func TestCloudflareWritesWhenOnlyTTLDiffers(t *testing.T) {
	var put map[string]any
	var putCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			io.WriteString(w, `{"success":true,"result":[{"id":"r1","name":"cf.example.com","type":"A","content":"1.2.3.4","ttl":1,"proxied":false}]}`)
			return
		}
		putCount++
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &put)
		io.WriteString(w, `{"success":true,"result":{}}`)
	}))
	defer srv.Close()
	old := cloudflareAPIBase
	cloudflareAPIBase = srv.URL
	defer func() { cloudflareAPIBase = old }()

	p, _ := newCloudflare("cf.example.com", map[string]string{"CF_API_TOKEN": "tok", "CF_ZONE_ID": "z1"})
	if err := p.EnsureARecord("cf.example.com", "1.2.3.4", RecordOptions{TTL: 600}); err != nil {
		t.Fatal(err)
	}
	if putCount != 1 {
		t.Fatalf("只改了 TTL 也必须写一次，实际写了 %d 次", putCount)
	}
	if put["ttl"] != float64(600) {
		t.Errorf("写出去的 ttl 应为 600，实际 %v", put["ttl"])
	}
}

// dnspodTTL 跑一次「记录不存在 → 新建」，返回写出去的那份 body。
func dnspodTTL(t *testing.T, opt RecordOptions) map[string]any {
	t.Helper()
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-TC-Action") == "DescribeRecordList" {
			io.WriteString(w, `{"Response":{"RecordCountInfo":{"TotalCount":0},"RecordList":[]}}`)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &body)
		io.WriteString(w, `{"Response":{}}`)
	}))
	defer srv.Close()
	old := dnspodAPIBase
	dnspodAPIBase = srv.URL
	defer func() { dnspodAPIBase = old }()

	p, _ := newDNSPod("cf.example.com", map[string]string{
		"TENCENT_SECRET_ID": "id", "TENCENT_SECRET_KEY": "key",
	})
	if err := p.EnsureARecord("cf.example.com", "1.2.3.4", opt); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestDNSPodTTL(t *testing.T) {
	// 没填 → 600，和升级前写死的一样（免费版要求 ≥600）
	if got := dnspodTTL(t, RecordOptions{})["TTL"]; got != float64(600) {
		t.Errorf("默认 TTL 应为 600，实际 %v", got)
	}
	if got := dnspodTTL(t, RecordOptions{TTL: 3600})["TTL"]; got != float64(3600) {
		t.Errorf("指定 TTL 应为 3600，实际 %v", got)
	}
}

func TestHuaweiTTL(t *testing.T) {
	for _, c := range []struct {
		opt  RecordOptions
		want float64
	}{{RecordOptions{}, 300}, {RecordOptions{TTL: 1800}, 1800}} {
		var body map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				io.WriteString(w, `{"recordsets":[]}`)
				return
			}
			raw, _ := io.ReadAll(r.Body)
			json.Unmarshal(raw, &body)
			io.WriteString(w, `{"id":"x","records":["1.2.3.4"]}`)
		}))
		old := huaweiAPIBase
		huaweiAPIBase = srv.URL
		p, _ := newHuawei("cf.example.com", map[string]string{
			"HUAWEI_AK": "ak", "HUAWEI_SK": "sk", "HUAWEI_ZONE_ID": "z",
		})
		if err := p.EnsureARecord("cf.example.com", "1.2.3.4", c.opt); err != nil {
			t.Fatal(err)
		}
		srv.Close()
		huaweiAPIBase = old
		if body["ttl"] != c.want {
			t.Errorf("opt=%+v 时 ttl 应为 %v，实际 %v", c.opt, c.want, body["ttl"])
		}
	}
}

// TestAliyunTTLSentOnlyWhenSet 阿里云不传 TTL 就是账号默认值，
// 升级前的行为正是「不传」，所以零值必须一个字都不带。
func TestAliyunTTLSentOnlyWhenSet(t *testing.T) {
	for _, c := range []struct {
		opt     RecordOptions
		wantTTL string
	}{
		{RecordOptions{}, ""},
		{RecordOptions{TTL: 3600}, "3600"},
	} {
		var gotTTL string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			if q.Get("Action") == "DescribeSubDomainRecords" {
				io.WriteString(w, `{"TotalCount":0,"DomainRecords":{"Record":[]}}`)
				return
			}
			gotTTL = q.Get("TTL")
			io.WriteString(w, `{"RecordID":"new"}`)
		}))
		old := aliyunAPIBase
		aliyunAPIBase = srv.URL
		p, _ := newAliyun("cf.example.com", map[string]string{
			"ALIYUN_ACCESS_KEY_ID": "id", "ALIYUN_ACCESS_KEY_SECRET": "secret",
		})
		if err := p.EnsureARecord("cf.example.com", "1.2.3.4", c.opt); err != nil {
			t.Fatal(err)
		}
		srv.Close()
		aliyunAPIBase = old
		if gotTTL != c.wantTTL {
			t.Errorf("opt=%+v 时 TTL 参数应为 %q，实际 %q", c.opt, c.wantTTL, gotTTL)
		}
	}
}

// TestZeroOptionsKeepLegacyDefaults 把「零值 = 升级前的样子」这条契约单独钉
// 一遍：以后谁想动默认值，这里会先红。四家的默认分别是 Cloudflare 自动(1)、
// DNSPod 600、华为云 300、阿里云不传（后三个在上面的三个测试里）。
func TestZeroOptionsKeepLegacyDefaults(t *testing.T) {
	if got := (RecordOptions{}).cfTTL(); got != 1 {
		t.Errorf("Cloudflare 零值应为自动（1），实际 %d", got)
	}
	if got := dnspodTTL(t, RecordOptions{})["TTL"]; got != float64(600) {
		t.Errorf("DNSPod 零值应为 600，实际 %v", got)
	}
}
