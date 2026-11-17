package provider

// 本文件的签名算法移植自 MIT 许可项目 jeessy2/ddns-go (https://github.com/jeessy2/ddns-go)
// Copyright (c) 2020 jeessy，依据 MIT License 使用，特此保留版权声明。
// 华为云签名器原始来源: github.com/datastream/aws (Copyright 2014 Xianjie, MIT)。

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------- 阿里云 HMAC-SHA1 RPC 签名 ----------

var signMethodMap = map[string]func() hash.Hash{
	"HMAC-SHA1": sha1.New,
}

// AliyunSign 为阿里云 RPC 请求添加公共参数与 Signature。
func AliyunSign(accessKeyID, accessKeySecret string, params *url.Values, method, apiVersion string) {
	params.Set("Format", "JSON")
	params.Set("Version", apiVersion)
	params.Set("AccessKeyId", accessKeyID)
	params.Set("SignatureMethod", "HMAC-SHA1")
	params.Set("SignatureVersion", "1.0")
	params.Set("SignatureNonce", strconv.FormatInt(time.Now().UnixNano(), 10))
	params.Set("Timestamp", time.Now().UTC().Format("2006-01-02T15:04:05Z"))

	params.Set("Signature", HmacSignToB64("HMAC-SHA1", method, accessKeySecret, *params))
}

// HmacSignToB64 计算阿里云风格的 HMAC 签名并返回 base64。
func HmacSignToB64(signMethod, httpMethod, appKeySecret string, vals url.Values) string {
	key := []byte(appKeySecret + "&")
	fn, ok := signMethodMap[signMethod]
	if !ok {
		fn = sha1.New
	}
	h := hmac.New(fn, key)
	makeDataToSign(h, httpMethod, vals)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

type strToEnc struct {
	s string
	e bool
}

func makeDataToSign(w io.Writer, httpMethod string, vals url.Values) {
	in := make(chan *strToEnc, 5)
	in <- &strToEnc{s: httpMethod}
	in <- &strToEnc{s: "&"}
	in <- &strToEnc{s: "/", e: true}
	in <- &strToEnc{s: "&"}
	in <- &strToEnc{s: vals.Encode(), e: true}
	close(in)
	specialURLEncode(in, w)
}

func specialURLEncode(in <-chan *strToEnc, w io.Writer) {
	for s := range in {
		if !s.e {
			io.WriteString(w, s.s)
			continue
		}
		l := len(s.s)
		for i := 0; i < l; {
			ch := s.s[i]
			switch ch {
			case '%':
				if len(s.s) >= i+3 && s.s[i:i+3] == "%7E" {
					w.Write([]byte("~"))
					i += 3
					continue
				}
				fallthrough
			case '*', '/', '&', '=':
				fmt.Fprintf(w, "%%%02X", ch)
			case '+':
				w.Write([]byte("%20"))
			default:
				fmt.Fprintf(w, "%c", ch)
			}
			i++
		}
	}
}

// ---------- 腾讯云 TC3-HMAC-SHA256 签名 ----------

func sha256hex(s string) string {
	b := sha256.Sum256([]byte(s))
	return hex.EncodeToString(b[:])
}

func tcHmac256(s, key string) []byte {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(s))
	return h.Sum(nil)
}

// TencentCloudSign 为腾讯云 API v3 请求添加鉴权头。service 如 "dnspod"。
func TencentCloudSign(secretID, secretKey string, r *http.Request, action, payload, service string) {
	algorithm := "TC3-HMAC-SHA256"
	host := service + ".tencentcloudapi.com"
	timestamp := time.Now().Unix()
	ts := strconv.FormatInt(timestamp, 10)

	canonicalHeaders := "content-type:application/json\nhost:" + host + "\nx-tc-action:" + strings.ToLower(action) + "\n"
	signedHeaders := "content-type;host;x-tc-action"
	canonicalRequest := "POST\n/\n\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + sha256hex(payload)

	date := time.Unix(timestamp, 0).UTC().Format("2006-01-02")
	credentialScope := date + "/" + service + "/tc3_request"
	string2sign := algorithm + "\n" + ts + "\n" + credentialScope + "\n" + sha256hex(canonicalRequest)

	secretDate := tcHmac256(date, "TC3"+secretKey)
	secretService := tcHmac256(service, string(secretDate))
	secretSigning := tcHmac256("tc3_request", string(secretService))
	signature := hex.EncodeToString(tcHmac256(string2sign, string(secretSigning)))

	authorization := algorithm + " Credential=" + secretID + "/" + credentialScope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature
	r.Header.Set("Authorization", authorization)
	r.Header.Set("Host", host)
	r.Header.Set("X-TC-Action", action)
	r.Header.Set("X-TC-Timestamp", ts)
	r.Header.Set("X-TC-Version", "2021-03-23")
	r.Header.Set("Content-Type", "application/json")
}

// ---------- 华为云 SDK-HMAC-SHA256 签名 ----------

const (
	hwBasicDate   = "20060102T150405Z"
	hwAlgorithm   = "SDK-HMAC-SHA256"
	hwHeaderXDate = "X-Sdk-Date"
)

func hwHmac256(key []byte, data string) ([]byte, error) {
	h := hmac.New(sha256.New, key)
	if _, err := h.Write([]byte(data)); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func hwEscape(s string) string {
	return url.QueryEscape(s)
}

func hwCanonicalRequest(r *http.Request, signedHeaders []string) (string, error) {
	var hexStr string
	if h := r.Header.Get("X-Sdk-Content-Sha256"); h != "" {
		hexStr = h
	} else {
		var data []byte
		if r.Body != nil {
			var err error
			data, err = io.ReadAll(r.Body)
			if err != nil {
				return "", err
			}
			r.Body = io.NopCloser(bytes.NewBuffer(data))
		}
		b := sha256.Sum256(data)
		hexStr = hex.EncodeToString(b[:])
	}

	uriParts := strings.Split(r.URL.Path, "/")
	for i, v := range uriParts {
		uriParts[i] = hwEscape(v)
	}
	path := strings.Join(uriParts, "/")
	if path == "" || path[len(path)-1] != '/' {
		path += "/"
	}

	keys := make([]string, 0, len(r.URL.Query()))
	for k := range r.URL.Query() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var qs []string
	for _, k := range keys {
		vals := append([]string(nil), r.URL.Query()[k]...)
		sort.Strings(vals)
		for _, v := range vals {
			qs = append(qs, hwEscape(k)+"="+hwEscape(v))
		}
	}
	r.URL.RawQuery = strings.Join(qs, "&")

	header := make(map[string][]string)
	for k, v := range r.Header {
		header[strings.ToLower(k)] = v
	}
	var ch []string
	for _, k := range signedHeaders {
		v := header[k]
		if k == "host" {
			v = []string{r.Host}
		}
		sort.Strings(v)
		for _, vv := range v {
			ch = append(ch, k+":"+strings.TrimSpace(vv))
		}
	}
	canonicalHeaders := strings.Join(ch, "\n") + "\n"

	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		r.Method, path, r.URL.RawQuery, canonicalHeaders, strings.Join(signedHeaders, ";"), hexStr), nil
}

// HuaweiSign 为华为云 API 请求添加 Authorization 头。
func HuaweiSign(ak, sk string, r *http.Request) error {
	t := time.Now().UTC()
	r.Header.Set(hwHeaderXDate, t.Format(hwBasicDate))

	signed := make([]string, 0, len(r.Header))
	for k := range r.Header {
		signed = append(signed, strings.ToLower(k))
	}
	sort.Strings(signed)

	canonical, err := hwCanonicalRequest(r, signed)
	if err != nil {
		return err
	}
	b := sha256.Sum256([]byte(canonical))
	stringToSign := hwAlgorithm + "\n" + t.Format(hwBasicDate) + "\n" + hex.EncodeToString(b[:])
	sig, err := hwHmac256([]byte(sk), stringToSign)
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", fmt.Sprintf("%s Access=%s, SignedHeaders=%s, Signature=%x",
		hwAlgorithm, ak, strings.Join(signed, ";"), sig))
	return nil
}
