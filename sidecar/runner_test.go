package sidecar

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stone/cf-ddns-sidecar/config"
)

type fakeProvider struct {
	mu    sync.Mutex
	calls []struct{ domain, ip string }
	err   error
}

func (f *fakeProvider) Name() string { return "fake" }
func (f *fakeProvider) EnsureARecord(domain, ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, struct{ domain, ip string }{domain, ip})
	return f.err
}
func (f *fakeProvider) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func newTestRunner(t *testing.T, subjectIP string) (*Runner, *fakeProvider, string) {
	t.Helper()
	dir := t.TempDir()
	subject := filepath.Join(dir, "config.json")
	if subjectIP != "" {
		os.WriteFile(subject, []byte(`{"last_result_ip":"`+subjectIP+`"}`), 0o644)
	}
	cfg := &config.Config{
		Domain:            "cf.example.com",
		SubjectConfigPath: subject,
		StatePath:         filepath.Join(dir, "state", "state.json"),
	}
	fp := &fakeProvider{}
	r, err := NewRunner(cfg, fp)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	return r, fp, subject
}

func TestTickInitThenNoDuplicate(t *testing.T) {
	r, fp, subject := newTestRunner(t, "1.1.1.1")
	r.Tick()
	if fp.count() != 1 {
		t.Fatalf("首次应推送 1 次，实际 %d", fp.count())
	}
	r.Tick()
	if fp.count() != 1 {
		t.Fatalf("相同 IP 不应重复推送，实际 %d 次", fp.count())
	}

	os.WriteFile(subject, []byte(`{"last_result_ip":"2.2.2.2"}`), 0o644)
	r.Tick()
	if fp.count() != 2 {
		t.Fatalf("IP 变化应再推送 1 次，实际 %d", fp.count())
	}
}

func TestStateSurvivesRestart(t *testing.T) {
	r, fp, _ := newTestRunner(t, "3.3.3.3")
	r.Tick()
	if fp.count() != 1 {
		t.Fatalf("首次应推送 1 次，实际 %d", fp.count())
	}

	// 用同一状态路径重建 Runner（模拟重启）
	r2, fp2, _ := newTestRunner(t, "3.3.3.3")
	r2.statePath = r.statePath
	r2.st = state{}
	if err := r2.loadState(); err != nil {
		t.Fatal(err)
	}
	r2.observer.Seed(r2.st.LastPushedIP)
	r2.Tick()
	if fp2.count() != 0 {
		t.Fatalf("重启后相同 IP 不应重复推送，实际 %d 次", fp2.count())
	}
}

func TestProviderErrorNoStateSaved(t *testing.T) {
	r, fp, _ := newTestRunner(t, "4.4.4.4")
	fp.err = os.ErrPermission
	r.Tick()
	if _, err := os.Stat(r.statePath); !os.IsNotExist(err) {
		t.Fatal("推送失败时不应保存状态")
	}
	if r.healthy {
		t.Fatalf("推送失败后健康状态应为 false")
	}
}

// B1 回归：推送失败后，相同 IP 在下一轮必须重试（而非静默跳过）。
func TestRetryAfterProviderFailure(t *testing.T) {
	r, fp, _ := newTestRunner(t, "5.5.5.5")
	fp.err = os.ErrPermission
	r.Tick()
	if fp.count() != 1 {
		t.Fatalf("失败轮应已尝试 1 次，实际 %d", fp.count())
	}

	fp.err = nil // 网络恢复
	r.Tick()
	if fp.count() != 2 {
		t.Fatalf("失败后同 IP 下一轮应重试，实际 %d 次", fp.count())
	}
	if got := r.st.LastPushedIP; got != "5.5.5.5" {
		t.Fatalf("重试成功后应保存状态，得到 %q", got)
	}
	if !r.healthy {
		t.Fatal("重试成功后健康状态应为 true")
	}

	// 成功确认后，相同 IP 不再重复推送。
	r.Tick()
	if fp.count() != 2 {
		t.Fatalf("确认后相同 IP 不应重复推送，实际 %d 次", fp.count())
	}
}

func TestHealthzHandler(t *testing.T) {
	r, fp, _ := newTestRunner(t, "6.6.6.6")
	r.Tick() // 成功推送 → healthy=true

	code, body := doGet(t, r)
	if code != http.StatusOK || body != "ok" {
		t.Fatalf("健康时 /healthz 应返回 200/ok，得到 %d/%q", code, body)
	}

	fp.err = os.ErrPermission
	os.WriteFile(r.cfg.SubjectConfigPath, []byte(`{"last_result_ip":"7.7.7.7"}`), 0o644)
	r.Tick()
	code, body = doGet(t, r)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("失败后 /healthz 应返回 503，得到 %d/%q", code, body)
	}
}

func doGet(t *testing.T, r *Runner) (int, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	r.healthMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	return rec.Code, rec.Body.String()
}
