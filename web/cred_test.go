package web

// 这个文件守的是「两份手写清单会不会走散」这一类问题。
//
// 2026-11-18 修备份漏导六项时才看清：这个项目里凡是「手写清单」的地方
// 都有同一类风险——**加东西时忘了一边，不报错、不打日志，只是某个值静静
// 地不再出现**。备份漏了六项就是这么来的（`bundleConfig` 是显式字段表）。
// 密钥这块有两处清单：
//   - 后端 `config.RequiredEnvByProvider` / `OptionalEnvByProvider`
//   - 前端 `PROVIDERS`（index.html 里写死的输入框）
// 两边一旦不同步，表现是「后端支持这家服务商，但界面上根本没有那个输入框」，
// 用户会以为是不支持。这里把它钉成一条测试。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/303528084/cf-ddns-sidecar/config"
)

// TestFrontendProviderKeysMatchBackend 前端画密钥输入框用的键，必须和后端
// 认的键一模一样。
func TestFrontendProviderKeysMatchBackend(t *testing.T) {
	src, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatalf("读不到前端文件: %v", err)
	}
	s := string(src)
	i := strings.Index(s, "const PROVIDERS = {")
	if i < 0 {
		t.Fatal("index.html 里找不到 `const PROVIDERS = {`——改名了就同步改这条测试")
	}
	rest := s[i:]
	end := strings.Index(rest, "\n};")
	if end < 0 {
		t.Fatal("PROVIDERS 块的结尾找不到")
	}
	block := rest[:end]

	re := regexp.MustCompile(`key:\s*"([A-Z0-9_]+)"`)
	front := make(map[string]bool)
	for _, m := range re.FindAllStringSubmatch(block, -1) {
		front[m[1]] = true
	}
	if len(front) == 0 {
		t.Fatal("没从 PROVIDERS 里解析出任何 key——正则和实际写法对不上了")
	}

	back := make(map[string]bool)
	for _, k := range config.AllCredentialKeys() {
		back[k] = true
	}

	var onlyBack, onlyFront []string
	for k := range back {
		if !front[k] {
			onlyBack = append(onlyBack, k)
		}
	}
	for k := range front {
		if !back[k] {
			onlyFront = append(onlyFront, k)
		}
	}
	sort.Strings(onlyBack)
	sort.Strings(onlyFront)
	if len(onlyBack) > 0 {
		t.Errorf("后端认、界面上却没有输入框（用户没法填）：%v", onlyBack)
	}
	if len(onlyFront) > 0 {
		t.Errorf("界面有输入框、后端却不认（填了会被拒）：%v", onlyFront)
	}
}

// TestSaveCredentialsRejectsUnknownKey 只收白名单里的密钥名。
//
// ddns.env 会被宿主机的生命周期脚本当环境文件整个读进去，所以这个接口不能
// 变成「往那个文件里塞任意变量」的入口。导入备份那条路早就有这个白名单。
func TestSaveCredentialsRejectsUnknownKey(t *testing.T) {
	s, _ := newPasswordTestServer(t, "")
	tok := s.signToken()

	envPath := config.EnvFilePath()
	if err := os.WriteFile(envPath, []byte("CF_API_TOKEN=keep-me\n"), 0o644); err != nil {
		t.Fatalf("准备 ddns.env 失败: %v", err)
	}

	body := `{"CF_API_TOKEN":"new-token","CFDDNS_PORT":"9999","EVIL":"x"}`
	req := httptest.NewRequest(http.MethodPost, "/api/credentials", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("带未知项应 400，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	for _, want := range []string{"CFDDNS_PORT", "EVIL"} {
		if !strings.Contains(resp["error"], want) {
			t.Errorf("提示里应点名 %q，实际 %q", want, resp["error"])
		}
	}
	// 整单退回：连认识的键也不写，避免「一半生效」这种最难交代的状态。
	if kv := config.LoadEnvFile(envPath); kv["CF_API_TOKEN"] != "keep-me" {
		t.Errorf("退回时不应写入任何一项，实际 %v", kv)
	}
}

// TestSaveCredentialsKeepsEnvComments 保存密钥不能冲掉 ddns.env 里用户自己
// 写的注释和被注释掉的备用密钥。
//
// 原来是整份重写，一保存就只剩一行固定注释 + 各家密钥。UpdateEnvFile 顶部
// 那段注释写的正是这件事，只是保存密钥这条路径当时没走它。
func TestSaveCredentialsKeepsEnvComments(t *testing.T) {
	s, _ := newPasswordTestServer(t, "")
	tok := s.signToken()

	envPath := config.EnvFilePath()
	original := "# 我的备注：这行是给以后的自己看的\n" +
		"#CF_API_TOKEN=旧的备用令牌\n" +
		"CF_API_TOKEN=old-token\n" +
		"CFDDNS_PORT=8080\n"
	if err := os.WriteFile(envPath, []byte(original), 0o644); err != nil {
		t.Fatalf("准备 ddns.env 失败: %v", err)
	}

	body := `{"CF_API_TOKEN":"new-token"}`
	req := httptest.NewRequest(http.MethodPost, "/api/credentials", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("保存密钥应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}

	after, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("读回 ddns.env 失败: %v", err)
	}
	got := string(after)
	for _, want := range []string{
		"# 我的备注：这行是给以后的自己看的",
		"#CF_API_TOKEN=旧的备用令牌",
		"CFDDNS_PORT=8080",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("保存密钥后丢了 %q，现在的内容：\n%s", want, got)
		}
	}
	if kv := config.LoadEnvFile(envPath); kv["CF_API_TOKEN"] != "new-token" {
		t.Errorf("新值没写进去，实际 %v", kv)
	}
}
