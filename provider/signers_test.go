package provider

import (
	"net/http"
	"net/url"
	"testing"
)

func TestTencentCloudSignDeterministic(t *testing.T) {
	// 固定 payload 与密钥，签名结构应稳定（时间戳为动态量，故只校验关键头的存在与结构）
	req, _ := http.NewRequest(http.MethodPost, dnspodAPIBase, nil)
	TencentCloudSign("SID", "SKEY", req, "CreateRecord", `{"Domain":"x"}`, "dnspod")
	auth := req.Header.Get("Authorization")
	if auth == "" || !contains(auth, "Credential=SID/") || !contains(auth, "/dnspod/tc3_request") {
		t.Fatalf("鉴权头结构错误: %s", auth)
	}
	wantHeaders := []string{"Host", "X-TC-Action", "X-TC-Timestamp", "X-TC-Version", "Content-Type"}
	for _, h := range wantHeaders {
		if req.Header.Get(h) == "" {
			t.Errorf("缺少头 %s", h)
		}
	}
	if req.Header.Get("X-TC-Action") != "CreateRecord" {
		t.Errorf("Action 错误: %s", req.Header.Get("X-TC-Action"))
	}
}

func TestHuaweiSignHeaders(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, huaweiAPIBase+"/v2.1/recordsets?type=A&name=x", nil)
	req.Host = "dns.myhuaweicloud.com"
	if err := HuaweiSign("AK", "SK", req); err != nil {
		t.Fatal(err)
	}
	auth := req.Header.Get("Authorization")
	if !contains(auth, "SDK-HMAC-SHA256 Access=AK") || !contains(auth, "SignedHeaders=") || !contains(auth, "Signature=") {
		t.Fatalf("华为云鉴权头结构错误: %s", auth)
	}
	if req.Header.Get("X-Sdk-Date") == "" {
		t.Error("缺少 X-Sdk-Date")
	}
}

func TestAliyunSignDeterministic(t *testing.T) {
	params := url.Values{}
	params.Set("Action", "AddDomainRecord")
	AliyunSign("id", "secret", &params, http.MethodGet, "2015-01-09")
	for _, k := range []string{"Signature", "SignatureNonce", "Timestamp", "AccessKeyId", "SignatureMethod", "Version"} {
		if params.Get(k) == "" {
			t.Errorf("缺少参数 %s", k)
		}
	}
	if params.Get("Version") != "2015-01-09" {
		t.Errorf("Version 错误: %s", params.Get("Version"))
	}
	// 同样输入下签名算法应确定（排除 nonce/timestamp 的干扰，直接验底层函数）
	h1 := HmacSignToB64("HMAC-SHA1", http.MethodGet, "secret", params)
	h2 := HmacSignToB64("HMAC-SHA1", http.MethodGet, "secret", params)
	if h1 != h2 {
		t.Error("签名算法非确定性")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
