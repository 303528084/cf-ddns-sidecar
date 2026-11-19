package web

// 第 7 项缺口（测速失败自动重试一次）的测试。
//
// 测速本身要跑 python3 和真实网络，这里不去碰它：把 enginePath 指向一个
// 不存在的文件，engine.Run 会在「准备测速引擎」那一步立刻失败。这样测的
// 正是我们新加的那层壳——失败一次、重试一次、最后如实记录失败次数。

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/303528084/cf-ddns-sidecar/config"
)

func TestRunOnceRetriesExactlyOnce(t *testing.T) {
	old := retryDelay
	retryDelay = 0 // 别让测试真的等 10 秒
	defer func() { retryDelay = old }()

	s := newToolsTestServer(t, func(c *config.Config) {
		// 别让这一轮去拉内置链接：测试不联网。给一段官方段，解析和采样都在本地。
		c.Speed.SourceMode = config.SourceCustom
		c.Speed.ExtraSources = []string{"104.16.0.0/13"}
	})
	// 指向不存在的路径：引擎一定起不来
	s.enginePath = filepath.Join(t.TempDir(), "no-such-main.py")

	err := s.runOnce(s.cfg.Clone(), triggerTimer)
	if err == nil {
		t.Fatal("引擎路径不存在时必须返回错误，不能假装成功")
	}

	s.mu.Lock()
	logs := strings.Join(s.logs, "\n")
	failCount := s.failCount
	lastOK := s.lastOK
	lastErr := s.lastErr
	s.mu.Unlock()

	if !strings.Contains(logs, "开始重试") {
		t.Fatalf("日志里没有重试记录：\n%s", logs)
	}
	// 只重试一次：出现两次「开始重试」说明退化成死循环了
	if n := strings.Count(logs, "开始重试"); n != 1 {
		t.Fatalf("应当只重试 1 次，实际 %d 次：\n%s", n, logs)
	}
	if failCount != 1 {
		t.Fatalf("一次 runOnce 最终失败应记 1 次失败，实际 %d", failCount)
	}
	if lastOK {
		t.Fatal("失败了却把 last_ok 记成 true，界面会显示「成功」")
	}
	if lastErr == "" {
		t.Fatal("失败了却没留错误信息，用户看不到失败原因")
	}
}

// TestFailCountAccumulates 连续两次都失败时次数要累加——
// 界面上「失败（连续 N 次）」这句话就是靠它。
func TestFailCountAccumulates(t *testing.T) {
	old := retryDelay
	retryDelay = 0
	defer func() { retryDelay = old }()

	s := newToolsTestServer(t, func(c *config.Config) {
		c.Speed.SourceMode = config.SourceCustom
		c.Speed.ExtraSources = []string{"104.16.0.0/13"}
	})
	s.enginePath = filepath.Join(t.TempDir(), "no-such-main.py")

	_ = s.runOnce(s.cfg.Clone(), triggerTimer)
	_ = s.runOnce(s.cfg.Clone(), triggerTimer)

	s.mu.Lock()
	n := s.failCount
	s.mu.Unlock()
	if n != 2 {
		t.Fatalf("连续失败两次应记 2，实际 %d", n)
	}
}

// TestSchedulerRecalculatesOnWake 改完间隔后「下次测速」必须马上跟着变。
//
// 没有 schedWake 时，调度器按旧周期睡在那儿：把 60 分钟改成 10 分钟，
// 界面会继续显示一小时之后，用户以为设置没生效。
func TestSchedulerRecalculatesOnWake(t *testing.T) {
	s := newToolsTestServer(t, func(c *config.Config) { c.Speed.IntervalMinutes = 30 })
	s.StartScheduler()

	// 等到它算出「下次什么时候跑」
	if !waitCond(func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return !s.nextRunAt.IsZero()
	}) {
		t.Fatal("调度器起来了却一直没算出 next_run_at，界面会永远显示「—」")
	}

	// 改成「不自动测速」并叫醒它：下次时间要立刻变空（界面显示「未开启」）
	s.mu.Lock()
	s.cfg.Speed.IntervalMinutes = 0
	s.mu.Unlock()
	s.wakeScheduler()

	if !waitCond(func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.nextRunAt.IsZero()
	}) {
		t.Fatal("改成 0 之后 next_run_at 没被清掉，说明调度器还按旧周期在睡")
	}

	// 叫醒只是重算，不许顺手跑一轮
	s.mu.Lock()
	running := s.running
	fails := s.failCount
	s.mu.Unlock()
	if running || fails != 0 {
		t.Fatalf("叫醒不该触发测速（running=%v, failCount=%d）", running, fails)
	}
}

// waitCond 在 2 秒内轮询条件，用于等 goroutine 把状态改过来。
func waitCond(cond func() bool) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// TestDelayText 日志里那句「10 秒后自动重试一次」的措辞。
func TestDelayText(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "马上"},
		{-time.Second, "马上"},
		{10 * time.Second, "10 秒后"},
		{59 * time.Second, "59 秒后"},
		{2 * time.Minute, "2 分钟后"},
		{3 * time.Hour, "3 小时后"},
	}
	for _, c := range cases {
		if got := delayText(c.d); got != c.want {
			t.Errorf("delayText(%v) = %q，期望 %q", c.d, got, c.want)
		}
	}
}

// TestFormatRunTime 今天只给时分（省地方），跨天带月日，零值留空。
func TestFormatRunTime(t *testing.T) {
	if got := formatRunTime(time.Time{}); got != "" {
		t.Fatalf("零值应为空串，实际 %q（界面靠这个判断「未开启」）", got)
	}
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 14, 30, 0, 0, now.Location())
	if got := formatRunTime(today); got != "14:30" {
		t.Fatalf("今天应显示 14:30，实际 %q", got)
	}
	tomorrow := today.AddDate(0, 0, 1)
	if got := formatRunTime(tomorrow); got != tomorrow.Format("01-02 15:04") {
		t.Fatalf("跨天应带月日，实际 %q", got)
	}
}
