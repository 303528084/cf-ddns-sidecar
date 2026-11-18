package config

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// TestRewriteDomainsExpandsWildcard 验证「包含子域」会把 `*.域名` 紧跟在本体后面。
//
// 顺序是有意义的：AdGuard 的重写表按顺序显示，用户看到的应该是
// 「openai.com / *.openai.com / example.com」而不是把通配符全堆到最后。
func TestRewriteDomainsExpandsWildcard(t *testing.T) {
	c := Default()
	c.Domains = []string{"openai.com", "example.com", "a.b.com"}
	c.DomainMeta = map[string]DomainMeta{
		"openai.com":  {Wildcard: true},
		"a.b.com":     {Wildcard: true},
		"example.com": {},
	}

	got := c.RewriteDomains()
	want := []string{"openai.com", "*.openai.com", "example.com", "a.b.com", "*.a.b.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RewriteDomains() = %v，期望 %v", got, want)
	}
}

// TestRewriteDomainsWithoutMeta 验证老配置（没有 domain_meta）照样能读：
// 没有元信息就等于「不含子域」，不该报错、也不该凭空多出通配符。
func TestRewriteDomainsWithoutMeta(t *testing.T) {
	c := Default()
	c.Domains = []string{"openai.com"}
	c.DomainMeta = nil

	got := c.RewriteDomains()
	if !reflect.DeepEqual(got, []string{"openai.com"}) {
		t.Fatalf("RewriteDomains() = %v，期望只有本体", got)
	}
}

// TestRewriteDomainsEmpty 验证没有域名时返回空切片而不是 nil。
//
// 调用方会拿它去判断 len(...) > 0，nil 和空切片结果一样；但返回 nil 时
// JSON 序列化成 null，界面上会变成「域名列表是 null」——这里钉死成 []。
func TestRewriteDomainsEmpty(t *testing.T) {
	c := Default()
	if got := c.RewriteDomains(); got == nil || len(got) != 0 {
		t.Fatalf("RewriteDomains() = %#v，期望空切片", got)
	}
}

// TestPruneDomainMeta 验证删掉的域名不会把元信息留下来。
//
// 不清理的后果很具体：用户把 openai.com 删掉、过两天又加回来，会直接
// 继承上一次的「包含子域」和添加时间——看着像程序记错了。
func TestPruneDomainMeta(t *testing.T) {
	c := Default()
	c.Domains = []string{"keep.com"}
	c.DomainMeta = map[string]DomainMeta{
		"keep.com":  {Wildcard: true, AddedAt: "2026-11-01 10:00:00"},
		"gone.com":  {Wildcard: true, AddedAt: "2026-10-01 10:00:00"},
		"other.com": {},
	}

	c.PruneDomainMeta()

	if len(c.DomainMeta) != 1 {
		t.Fatalf("清理后应只剩 1 条，实际 %d 条：%v", len(c.DomainMeta), c.DomainMeta)
	}
	if m, ok := c.DomainMeta["keep.com"]; !ok || !m.Wildcard || m.AddedAt == "" {
		t.Fatalf("keep.com 的元信息被误删或改动了：%v", c.DomainMeta)
	}
}

// TestPruneDomainMetaNil 验证没有域名时把整张表清空（而不是留个空 map）。
// 留空 map 会让 config.json 里多一个 "domain_meta": {}，看着像有配置。
func TestPruneDomainMetaNil(t *testing.T) {
	c := Default()
	c.Domains = nil
	c.DomainMeta = map[string]DomainMeta{"x.com": {Wildcard: true}}

	c.PruneDomainMeta()

	if c.DomainMeta != nil {
		t.Fatalf("没有域名时元信息应整张表置 nil，实际 %v", c.DomainMeta)
	}
}

// TestDomainMetaJSONRoundTrip 验证元信息能存下来、读回来。
func TestDomainMetaJSONRoundTrip(t *testing.T) {
	c := Default()
	c.Domains = []string{"openai.com"}
	c.DomainMeta = map[string]DomainMeta{
		"openai.com": {Wildcard: true, AddedAt: "2026-11-18 09:30:00"},
	}
	blob, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}

	var back Config
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}
	m := back.DomainMeta["openai.com"]
	if !m.Wildcard || m.AddedAt != "2026-11-18 09:30:00" {
		t.Fatalf("读回来的元信息不对：%+v", m)
	}
}

// TestDomainMetaOmittedWhenEmpty 验证没有元信息时 JSON 里干脆不出现这个字段。
// 老版本看到不认识的字段会忽略，但多一坨空对象会让 config.json 变脏。
func TestDomainMetaOmittedWhenEmpty(t *testing.T) {
	c := Default()
	blob, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(blob, &raw); err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}
	if _, ok := raw["domain_meta"]; ok {
		t.Fatalf("没有元信息时不该写出 domain_meta：%s", blob)
	}
}

// TestCloneCopiesDomainMeta 验证 Clone 是深拷贝。
//
// 浅拷贝的后果：后台 goroutine 拿到 Clone 之后改 DomainMeta，会直接改到
// 正在被界面读的那一份，两个请求并发时 map 还会直接 panic（Go 的 map 不是
// 并发安全的）。
func TestCloneCopiesDomainMeta(t *testing.T) {
	c := Default()
	c.Domains = []string{"openai.com"}
	c.DomainMeta = map[string]DomainMeta{"openai.com": {Wildcard: true}}

	cp := c.Clone()
	cp.DomainMeta["openai.com"] = DomainMeta{Wildcard: false}
	cp.DomainMeta["new.com"] = DomainMeta{Wildcard: true}

	if !c.DomainMeta["openai.com"].Wildcard {
		t.Fatalf("改副本影响到了原对象")
	}
	if _, ok := c.DomainMeta["new.com"]; ok {
		t.Fatalf("往副本里加键影响到了原对象")
	}
}

// TestCloneCopiesRewrittenDomains 账本也是切片，同样必须各存一份。
//
// 它比 DomainMeta 更容易漏：写成「一个字符串列表，拷不拷无所谓」。实际上
// 测速成功后那一轮会整段替换它，而域名页同时在遍历它判断哪些旧域名该清，
// 共享底层数组就是边读边改。
func TestCloneCopiesRewrittenDomains(t *testing.T) {
	c := Default()
	c.RewrittenDomains = []string{"a.com", "*.a.com"}

	cp := c.Clone()
	cp.RewrittenDomains[0] = "changed.com"
	cp.RewrittenDomains = append(cp.RewrittenDomains, "b.com")

	if c.RewrittenDomains[0] != "a.com" {
		t.Fatalf("改副本影响到了原对象：%v", c.RewrittenDomains)
	}
	if len(c.RewrittenDomains) != 2 {
		t.Fatalf("往副本里 append 影响到了原对象的长度：%v", c.RewrittenDomains)
	}
}

// TestLoadPrunesStaleDomainMeta 验证 Load 会顺手清理元信息。
//
// 场景：用户手工编辑 config.json 删掉了一个域名，但 domain_meta 里还留着它。
// 不清的话，下次同名域名加回来会继承旧设置。
func TestLoadPrunesStaleDomainMeta(t *testing.T) {
	p := setPath(t)
	body := `{"domains":["keep.com"],"domain_meta":{"keep.com":{"wildcard":true},"gone.com":{"wildcard":true}}}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("写测试配置失败: %v", err)
	}

	c, err := Load()
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if _, ok := c.DomainMeta["gone.com"]; ok {
		t.Fatalf("Load 之后 stale 的元信息还在：%v", c.DomainMeta)
	}
	if !c.DomainMeta["keep.com"].Wildcard {
		t.Fatalf("keep.com 的元信息被误删：%v", c.DomainMeta)
	}
}
