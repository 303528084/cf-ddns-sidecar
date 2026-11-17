package web

// 域名「是不是走 Cloudflare 边缘」这道检查的测试。
//
// 这一层的错误方向不对称，两种错都要防：
//   - 把走 Cloudflare 的域名判成不是 → 用户加不进去，会觉得「这软件坏了」；
//   - 把不走的域名放过去 → 保存成功、日志也没有异常，直到某天浏览器打不开
//     网页，用户根本联想不到是域名没接 Cloudflare。
// 所以下面既验「该放过的放过」，也验「该拦的拦下并说清原因」，还验
// 「查不出来」这一种既不能当通过、也不能当拒绝的第三种情况。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
)

// stubProbe 把第二层的 HTTP 探测换掉。默认「没探测到 Cloudflare」，
// 这样凡是只关心第一层的用例都不会意外去连真网络。
func stubProbe(t *testing.T, fn func(ctx context.Context, domain string) (bool, string, error)) {
	t.Helper()
	old := probeHeadersFunc
	if fn == nil {
		fn = func(context.Context, string) (bool, string, error) { return false, "", nil }
	}
	probeHeadersFunc = fn
	t.Cleanup(func() { probeHeadersFunc = old })
}

// stubLookup 把 DNS 查询换成一张表，跑完自动还原。
func stubLookup(t *testing.T, table map[string][]string, errs map[string]error) {
	t.Helper()
	old := lookupIPFunc
	lookupIPFunc = func(_ context.Context, host string) ([]net.IP, error) {
		if err, ok := errs[host]; ok {
			return nil, err
		}
		var out []net.IP
		for _, s := range table[host] {
			out = append(out, net.ParseIP(s))
		}
		if len(out) == 0 {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return out, nil
	}
	t.Cleanup(func() { lookupIPFunc = old })
}

func TestIsCloudflareIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
		why  string
	}{
		{"104.16.132.229", true, "官方段 104.16.0.0/13 内"},
		{"172.64.229.179", true, "官方段 172.64.0.0/13 内"},
		{"2606:4700:10::6816:100", true, "Cloudflare 的 IPv6 段"},
		{"220.181.38.148", false, "百度"},
		{"8.8.8.8", false, "Google DNS"},
		{"1.1.1.1", false, "Cloudflare 的公共 DNS，但不是边缘节点的段"},
		{"2606:4700::1", true, "v6 段起点"},
		{"2001:4860:4860::8888", false, "Google 的 v6"},
	}
	for _, c := range cases {
		got := isCloudflareIP(net.ParseIP(c.ip))
		if got != c.want {
			t.Errorf("%s（%s）: 期望 %v，实际 %v", c.ip, c.why, c.want, got)
		}
	}
	if isCloudflareIP(nil) {
		t.Error("nil 必须当成「不是」，否则一个空的解析结果会被放过去")
	}
}

func TestCheckDomainEdgePassesOnDNS(t *testing.T) {
	stubLookup(t, map[string][]string{
		"openrouter.ai": {"104.18.2.1", "172.64.2.1"},
	}, nil)
	// 第一层就能下结论，不该再发 HTTP 请求。
	stubProbe(t, func(context.Context, string) (bool, string, error) {
		t.Error("第一层已经确认是 Cloudflare，不该再发 HTTP 探测")
		return false, "", nil
	})

	r := checkDomainEdge(context.Background(), "openrouter.ai")
	if !r.OK || r.Unknown {
		t.Fatalf("应该通过，实际 ok=%v unknown=%v reason=%q", r.OK, r.Unknown, r.Reason)
	}
	if len(r.IPs) != 2 {
		t.Errorf("解析到的 IP 要一起带回去给用户看，实际 %v", r.IPs)
	}
	if !strings.Contains(r.Reason, "边缘") {
		t.Errorf("通过时也要说清依据，实际 %q", r.Reason)
	}
}

// 第一层说「不是」，但第二层探测到 cf-ray —— 这正是「段表过期」或
// 「解析结果不在 CF 段、实际仍由 CF 代理」时该放过的情形。
func TestCheckDomainEdgePassesOnHTTPFallback(t *testing.T) {
	stubLookup(t, map[string][]string{
		"weird.example.com": {"203.0.113.9"},
	}, nil)
	stubProbe(t, func(_ context.Context, d string) (bool, string, error) {
		return true, "FRA", nil
	})

	r := checkDomainEdge(context.Background(), "weird.example.com")
	if !r.OK {
		t.Fatalf("第二层认出来了就该通过，实际 %+v", r)
	}
	if r.Colo != "FRA" {
		t.Errorf("机房代码要带回去，实际 %q", r.Colo)
	}
	if !strings.Contains(r.Reason, "FRA") {
		t.Errorf("说明里要写机房，实际 %q", r.Reason)
	}
}

func TestCheckDomainEdgeRejectsNonCloudflare(t *testing.T) {
	stubLookup(t, map[string][]string{
		"baidu.com": {"220.181.38.148"},
	}, nil)
	stubProbe(t, nil) // 两层都不认

	r := checkDomainEdge(context.Background(), "baidu.com")
	if r.OK || r.Unknown {
		t.Fatalf("应该被拒，实际 ok=%v unknown=%v", r.OK, r.Unknown)
	}
	// 原因里必须带上解析到的 IP：只说「不是 Cloudflare」，用户没法自己核对。
	if !strings.Contains(r.Reason, "220.181.38.148") {
		t.Errorf("原因里要写明解析到哪个 IP，实际 %q", r.Reason)
	}
}

// 探测本身出错（超时、连不上）时，仍然按「不是」处理，但要把探测的失败
// 原因也写进去——否则用户只看到「不是 Cloudflare」，而他那边其实是网站挂了。
func TestCheckDomainEdgeRejectMentionsProbeError(t *testing.T) {
	stubLookup(t, map[string][]string{
		"down.example.com": {"203.0.113.7"},
	}, nil)
	stubProbe(t, func(context.Context, string) (bool, string, error) {
		return false, "", errors.New(`Get "https://down.example.com": dial tcp: connect: connection refused`)
	})

	r := checkDomainEdge(context.Background(), "down.example.com")
	if r.OK || r.Unknown {
		t.Fatalf("应该被拒，实际 %+v", r)
	}
	if !strings.Contains(r.Reason, "connection refused") {
		t.Errorf("要把探测失败的原因也写进去，实际 %q", r.Reason)
	}
}

// 一个域名有多个 A 记录时，只要有一个落在 Cloudflare 段里就算走 Cloudflare。
// 现实中同一个站同时返回 CF 和源站 IP 的情况很少，但「只要有一个」比
// 「必须全是」更符合「请求会不会经过边缘」这个问题。
func TestCheckDomainEdgeAnyIPCounts(t *testing.T) {
	stubLookup(t, map[string][]string{
		"mixed.example.com": {"203.0.113.9", "104.16.132.229"},
	}, nil)
	stubProbe(t, nil)

	r := checkDomainEdge(context.Background(), "mixed.example.com")
	if !r.OK {
		t.Fatalf("有一条是 Cloudflare 就该通过，实际 %+v", r)
	}
}

func TestCheckDomainEdgeUnknownOnDNSError(t *testing.T) {
	stubLookup(t, nil, map[string]error{
		"nosuch.example":  &net.DNSError{Err: "no such host", Name: "nosuch.example", IsNotFound: true},
		"timeout.example": &net.DNSError{Err: "i/o timeout", Name: "timeout.example", IsTimeout: true},
	})
	// 解析不出来时不该再发 HTTP 请求：那一步同样要靠 DNS，必然一起失败。
	stubProbe(t, func(context.Context, string) (bool, string, error) {
		t.Error("DNS 都查不到时不该再发 HTTP 探测，白等 6 秒")
		return false, "", nil
	})

	r := checkDomainEdge(context.Background(), "nosuch.example")
	if r.OK || !r.Unknown {
		t.Fatalf("查不到域名要归到「没验成」，实际 %+v", r)
	}
	if !strings.Contains(r.Reason, "拼错") {
		t.Errorf("域名不存在要说「拼错了」，实际 %q", r.Reason)
	}

	r = checkDomainEdge(context.Background(), "timeout.example")
	if r.OK || !r.Unknown {
		t.Fatalf("DNS 超时也要归到「没验成」，实际 %+v", r)
	}
	if !strings.Contains(r.Reason, "没响应") {
		t.Errorf("超时要说「DNS 服务器没响应」，实际 %q", r.Reason)
	}
}

// 查不了 ≠ 不是：这条是整段代码里最要紧的一条。DNS 抖一下就把用户的域名
// 从配置里删掉，比放过去糟得多——用户什么都没做错。
func TestScreenDomainsKeepsUnknownButRejectsNonCF(t *testing.T) {
	stubLookup(t, map[string][]string{
		"good.com": {"104.16.132.229"},
		"bad.com":  {"220.181.38.148"},
	}, map[string]error{
		"slow.com": &net.DNSError{Err: "i/o timeout", Name: "slow.com", IsTimeout: true},
	})
	stubProbe(t, nil)

	kept, rejected, unknown := screenDomains(context.Background(),
		[]string{"good.com", "bad.com", "slow.com"})

	if len(kept) != 2 {
		t.Fatalf("通过的 + 没验成的都该保留，期望 2 个，实际 %v", kept)
	}
	if len(rejected) != 1 || rejected[0].Domain != "bad.com" {
		t.Fatalf("只该拒 bad.com，实际 %+v", rejected)
	}
	if len(unknown) != 1 || unknown[0].Domain != "slow.com" {
		t.Fatalf("只该把 slow.com 归到没验成，实际 %+v", unknown)
	}
	// 保留的顺序要和用户输入一致，否则保存一次域名顺序就乱了。
	if kept[0] != "good.com" || kept[1] != "slow.com" {
		t.Errorf("保留顺序应和输入一致，实际 %v", kept)
	}
}

func TestScreenDomainsEmpty(t *testing.T) {
	kept, rejected, unknown := screenDomains(context.Background(), nil)
	if kept == nil {
		t.Error("空输入要返回空切片而不是 nil，否则 config.json 里会是 null")
	}
	if len(kept)+len(rejected)+len(unknown) != 0 {
		t.Errorf("空输入不该有结果，实际 %v %v %v", kept, rejected, unknown)
	}
}

func TestDNSErrText(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{&net.DNSError{Err: "no such host", IsNotFound: true}, "拼错"},
		{&net.DNSError{Err: "server misbehaving"}, "没响应"},
		{&net.DNSError{Err: "i/o timeout", IsTimeout: true}, "没响应"},
		{&net.DNSError{Err: "deadline exceeded"}, "超时"},
		{errors.New("something odd"), "something odd"},
	}
	for _, c := range cases {
		if got := dnsErrText(c.err); !strings.Contains(got, c.want) {
			t.Errorf("%v 应包含 %q，实际 %q", c.err, c.want, got)
		}
	}
}

func TestHTTPErrText(t *testing.T) {
	if got := httpErrText(nil); got != "" {
		t.Errorf("nil 应返回空串，实际 %q", got)
	}
	// 只留最后一段原因：前面那串 `Get "https://...": dial tcp 1.2.3.4:443: `
	// 对用户没有意义，还会把界面那一行撑得很长。注意这里连 `connect:` 也一并
	// 去掉——它只是 Go 在给错误分层，人读到「connection refused」就够了。
	got := httpErrText(errors.New(`Get "https://a.com": dial tcp 1.2.3.4:443: connect: connection refused`))
	if got != "connection refused" {
		t.Errorf("应只留最后一段原因，实际 %q", got)
	}
	// 证书类错误的最后一段是真正的病因，不能被截成空串或只剩冒号。
	got = httpErrText(errors.New(`Get "https://a.com": tls: failed to verify certificate: ` +
		`x509: certificate signed by unknown authority`))
	if got != "certificate signed by unknown authority" {
		t.Errorf("证书错误应保留病因那一段，实际 %q", got)
	}
	// 没有冒号分隔、也不在翻译表里的错误原样返回，别把它截成空串。
	if got := httpErrText(errors.New("something very odd")); got != "something very odd" {
		t.Errorf("认不出来的错误应原样返回，实际 %q", got)
	}
	// 超时类错误也要翻，不然界面上是 `context deadline exceeded`。
	if got := httpErrText(errors.New("context deadline exceeded")); got != "等太久没响应" {
		t.Errorf("超时应翻成「等太久没响应」，实际 %q", got)
	}
	// `EOF` 摆到界面上等于什么都没说，必须翻成人话。
	//
	// 这里一定要按**真实形状**造错误：http.Client 返回的是被 url.Error 包过的
	// `Get "https://xxx": EOF`，不是裸 io.EOF。用裸 io.EOF 测会漏掉包装，
	// 代码里写成 `msg == "EOF"` 也能过测试，但线上照样显示 `EOF`——这个坑
	// 真踩过一次（端到端截图里看到界面上还写着 EOF）。
	wrapped := fmt.Errorf(`Get "https://a.com": %w`, io.EOF)
	if got := httpErrText(wrapped); got != "连接被中断" {
		t.Errorf("包过的 EOF 应翻成「连接被中断」，实际 %q", got)
	}
	if got := httpErrText(io.EOF); got != "连接被中断" {
		t.Errorf("裸 EOF 也应翻成「连接被中断」，实际 %q", got)
	}
	if got := httpErrText(fmt.Errorf(`Get "https://a.com": %w`,
		errors.New("unexpected EOF"))); got != "连接被中断" {
		t.Errorf("unexpected EOF 也应翻成「连接被中断」，实际 %q", got)
	}
}

func TestJoinIPs(t *testing.T) {
	if got := joinIPs(nil); got != "" {
		t.Errorf("空列表应返回空串，实际 %q", got)
	}
	if got := joinIPs([]string{"1.1.1.1"}); got != "1.1.1.1" {
		t.Errorf("单个地址应原样返回，实际 %q", got)
	}
	// 三条以内全列出来。
	if got := joinIPs([]string{"a", "b", "c"}); got != "a / b / c" {
		t.Errorf("三条应全列，实际 %q", got)
	}
	// 超过三条只列前三条 + 个数：全列出来会把界面那一行撑成三行。
	got := joinIPs([]string{"a", "b", "c", "d", "e"})
	if got != "a / b / c 等 5 个" {
		t.Errorf("超过三条应截断并说个数，实际 %q", got)
	}
}
