package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/303528084/cf-ddns-sidecar/config"
)

func TestWeakPasswordReason(t *testing.T) {
	cases := []struct {
		pw     string
		ok     bool
		reason string // 只检查关键词，避免测试跟措辞一起碎
	}{
		{"", false, "不能为空"},
		{"abc123", false, "太短了"},
		{"Test1234", true, ""},       // 8 位、有字母有数字、不连续
		{"Kx7-mango-Q", true, ""},    // 更长的随机串
		{"12345678", false, "弱密码"},   // 连续 + 在黑名单里
		{"abcdefgh", false, "连续"},    // 纯连续字母
		{"88888888", false, "弱密码"},   // 重复 + 黑名单
		{"aaaaaaaa", false, "同一个字符"}, // 重复字母
		{"hijklmno", false, "连续"},    // 中间一段连续
		{"98765432", false, "连续"},    // 连续下降
		{"zabcdefg", false, "连续"},    // 首尾相接也算连续
		{"password", false, "弱密码"},
		{"admin123", false, "弱密码"},
		{"13800138000", true, ""},   // 纯数字但够长（手机号级别）
		{"123456789", false, "弱密码"}, // 黑名单明确收录，优先于「纯数字不够长」
		{"7391846", false, "太短了"},
		{"  Test1234  ", true, ""}, // 前后空格先去掉
	}
	for _, c := range cases {
		got := WeakPasswordReason(c.pw)
		if c.ok && got != "" {
			t.Errorf("WeakPasswordReason(%q) 应当通过，却返回 %q", c.pw, got)
		}
		if !c.ok {
			if got == "" {
				t.Errorf("WeakPasswordReason(%q) 应当被拒绝，却通过了", c.pw)
				continue
			}
			if c.reason != "" && !strings.Contains(got, c.reason) {
				t.Errorf("WeakPasswordReason(%q) 原因应包含 %q，实际 %q", c.pw, c.reason, got)
			}
		}
	}
}

// newPasswordTestServer 造一个带临时数据目录的 Server。
func newPasswordTestServer(t *testing.T, passEnv string) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	passFile := filepath.Join(dir, "dashboard-password")
	if err := os.WriteFile(passFile, []byte("OldPass123"), 0o644); err != nil {
		t.Fatalf("准备密码文件失败: %v", err)
	}
	cfg := config.Default()
	s := New(cfg, filepath.Join(dir, "config.json"), "", dir, Auth{
		Env:      passEnv,
		File:     passFile,
		Fallback: "OldPass123",
	}, "http://127.0.0.1:8080", nil)
	return s, passFile
}

// postJSON 以「已登录」身份发一个 POST（/api/password 在 auth 后面，
// 不带令牌会被 401 挡在门外，那样测的就不是改密码逻辑了）。
func postJSON(s *Server, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.RemoteAddr = "192.168.1.10:5000"
	req.Header.Set("Authorization", "Bearer "+s.signToken())
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// TestHandlePasswordRejectsWeak 弱密码必须被挡，而且不能改动文件。
func TestHandlePasswordRejectsWeak(t *testing.T) {
	s, passFile := newPasswordTestServer(t, "")
	before, _ := os.ReadFile(passFile)

	rec := postJSON(s, "/api/password", `{"old_password":"OldPass123","new_password":"12345678"}`)
	if rec.Code != 400 {
		t.Fatalf("弱密码应返回 400，实际 %d，body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "弱密码") && !strings.Contains(rec.Body.String(), "连续") {
		t.Fatalf("错误信息没说清原因: %s", rec.Body.String())
	}
	after, _ := os.ReadFile(passFile)
	if string(before) != string(after) {
		t.Fatal("被拒绝的请求居然改了密码文件")
	}
}

// TestHandlePasswordRejectsWrongOld 当前密码不对时必须拒绝，且走限流计数。
func TestHandlePasswordRejectsWrongOld(t *testing.T) {
	s, _ := newPasswordTestServer(t, "")
	rec := postJSON(s, "/api/password", `{"old_password":"nope","new_password":"Brand-New-1"}`)
	if rec.Code != 401 {
		t.Fatalf("当前密码错应返回 401，实际 %d", rec.Code)
	}
}

// TestHandlePasswordSuccess 正常改密码：文件被原子替换，旧令牌失效、新令牌可用。
func TestHandlePasswordSuccess(t *testing.T) {
	s, passFile := newPasswordTestServer(t, "")
	oldToken := s.signToken() // 用旧密码签出来的令牌

	rec := postJSON(s, "/api/password", `{"old_password":"OldPass123","new_password":"Brand-New-1"}`)
	if rec.Code != 200 {
		t.Fatalf("应成功，实际 %d，body=%s", rec.Code, rec.Body.String())
	}
	got, err := os.ReadFile(passFile)
	if err != nil {
		t.Fatalf("读密码文件失败: %v", err)
	}
	if string(got) != "Brand-New-1" {
		t.Fatalf("密码文件内容不对: %q", got)
	}
	// 权限要和生命周期脚本写出来的一致，否则另一身份的进程读不到。
	// Windows 上 chmod 只切只读属性，Mode().Perm() 恒为 0666，这条在那边没法成立；
	// 产品只跑在飞牛的 Linux 容器里，断言保留在非 Windows 上。
	if runtime.GOOS != "windows" {
		if st, serr := os.Stat(passFile); serr == nil && st.Mode().Perm() != 0o644 {
			t.Fatalf("密码文件权限应为 0644，实际 %v", st.Mode().Perm())
		}
	}

	newToken := extractToken(t, rec.Body.String())
	if !s.validToken(newToken) {
		t.Fatal("换发的令牌不可用，用户改完密码会被踢下线")
	}
	// 签名密钥由密码派生，旧令牌必须失效——否则「改密码」等于没吊销任何会话。
	if s.validToken(oldToken) {
		t.Fatal("改完密码后旧令牌仍然有效")
	}
}

// TestHandlePasswordBlockedByEnv 密码来自环境变量时要明确拒绝，别写成假成功。
func TestHandlePasswordBlockedByEnv(t *testing.T) {
	s, passFile := newPasswordTestServer(t, "FromEnv-Pass")
	before, _ := os.ReadFile(passFile)
	rec := postJSON(s, "/api/password", `{"old_password":"FromEnv-Pass","new_password":"Brand-New-1"}`)
	if rec.Code != 400 {
		t.Fatalf("应由环境变量接管而返回 400，实际 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "DSA_PASSWORD") {
		t.Fatalf("错误信息应指出是环境变量: %s", rec.Body.String())
	}
	after, _ := os.ReadFile(passFile)
	if string(before) != string(after) {
		t.Fatal("环境变量模式下不应改动密码文件")
	}
}

func extractToken(t *testing.T, body string) string {
	t.Helper()
	const marker = `"token":"`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("body 里没有 token: %s", body)
	}
	rest := body[i+len(marker):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		t.Fatalf("token 格式不对: %s", body)
	}
	return rest[:j]
}
