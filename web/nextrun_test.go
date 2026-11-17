package web

// 「下次测速还剩多久」这一个字段的测试。
//
// 为什么值得单测：界面把它显示成「还剩 58 分钟」，是给人做决定的——要不要
// 现在手动点一次。算错了（比如跨天算成负的、或者把「没开定时」说成「还剩
// 0 秒」）比不显示更糟：用户会以为定时坏了。

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// TestSecsUntil 三种情形：正常未来时刻、已经过点、没开定时（零值）。
func TestSecsUntil(t *testing.T) {
	if got := secsUntil(time.Time{}); got != 0 {
		t.Errorf("没开定时应返回 0，实际 %d", got)
	}
	if got := secsUntil(time.Now().Add(-2 * time.Minute)); got != 0 {
		t.Errorf("已经过点应返回 0，实际 %d", got)
	}

	// 未来 90 秒。函数内部会再取一次 time.Now()，所以允许 1 秒误差。
	got := secsUntil(time.Now().Add(90 * time.Second))
	if got < 88 || got > 90 {
		t.Errorf("未来 90 秒应约等于 90，实际 %d", got)
	}
}

// TestStatusHasNextRunInSec /api/status 里得真有这个字段，而且和
// next_run_at 说的是同一件事——两个字段各算各的，界面就会自相矛盾。
func TestStatusHasNextRunInSec(t *testing.T) {
	s := newToolsTestServer(t, nil)
	s.mu.Lock()
	s.nextRunAt = time.Now().Add(30 * time.Minute)
	s.mu.Unlock()

	rec := call(s, http.MethodGet, "/api/status")
	if rec.Code != 200 {
		t.Fatalf("状态接口失败: %d %s", rec.Code, rec.Body.String())
	}
	var got struct {
		NextRunAt    string `json:"next_run_at"`
		NextRunInSec int    `json:"next_run_in_sec"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.NextRunAt == "" {
		t.Error("next_run_at 不该为空")
	}
	// 30 分钟 = 1800 秒，留 5 秒余量。
	if got.NextRunInSec < 1795 || got.NextRunInSec > 1800 {
		t.Errorf("next_run_in_sec 应约等于 1800，实际 %d", got.NextRunInSec)
	}
}

// TestStatusNoTimerMeansZero 没开定时的时候必须是 0，而不是负数或者
// 「距 1970 年还有多少秒」那种荒唐数——零值时间最容易在这里出事。
func TestStatusNoTimerMeansZero(t *testing.T) {
	s := newToolsTestServer(t, nil)
	s.mu.Lock()
	s.nextRunAt = time.Time{}
	s.mu.Unlock()

	rec := call(s, http.MethodGet, "/api/status")
	var got struct {
		NextRunInSec int `json:"next_run_in_sec"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.NextRunInSec != 0 {
		t.Errorf("没开定时应返回 0，实际 %d", got.NextRunInSec)
	}
}
