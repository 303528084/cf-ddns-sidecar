package web

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/303528084/cf-ddns-sidecar/config"
)

func newHistoryServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	return New(config.Default(), filepath.Join(dir, "config.json"), "", dir,
		Auth{Fallback: "Test-Pass-123"}, "", nil)
}

// 保留条数封顶：超了丢最旧的，最新的永远在最后。
func TestHistoryKeepsNewestRounds(t *testing.T) {
	s := newHistoryServer(t)
	total := historyKeep + 5
	for i := 0; i < total; i++ {
		s.appendHistory(roundRecord{
			At:      fmt.Sprintf("11-19 10:%02d:00", i),
			Trigger: triggerTimer,
			OK:      true,
		})
	}

	s.mu.Lock()
	got := append([]roundRecord(nil), s.history...)
	s.mu.Unlock()

	if len(got) != historyKeep {
		t.Fatalf("应只留 %d 轮，实际 %d 轮", historyKeep, len(got))
	}
	if want := fmt.Sprintf("11-19 10:%02d:00", total-1); got[len(got)-1].At != want {
		t.Fatalf("最新那条应是 %s，实际 %s", want, got[len(got)-1].At)
	}
	if want := fmt.Sprintf("11-19 10:%02d:00", total-historyKeep); got[0].At != want {
		t.Fatalf("最旧那条应是 %s（前面 5 条要被挤掉），实际 %s", want, got[0].At)
	}
}

// 历史要能跨重启：重启后「昨天凌晨那轮为什么失败」还得查得到。
func TestHistorySurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	s := New(config.Default(), cfgPath, "", dir, Auth{Fallback: "pw"}, "", nil)
	s.appendHistory(roundRecord{
		At: "11-19 11:26:30", Trigger: triggerManual, OK: true,
		Best: "1.2.3.4", Written: 2,
		Nodes: []config.NodeStat{{IP: "1.2.3.4", Speed: 12.5, Delay: 80, Place: "日本·东京(NRT)"}},
	})

	s2 := New(config.Default(), cfgPath, "", dir, Auth{Fallback: "pw"}, "", nil)
	s2.mu.Lock()
	n := len(s2.history)
	var rec roundRecord
	if n > 0 {
		rec = s2.history[0]
	}
	s2.mu.Unlock()

	if n != 1 {
		t.Fatalf("重启后应读到 1 轮，实际 %d 轮", n)
	}
	if rec.Best != "1.2.3.4" || rec.Written != 2 || rec.Trigger != triggerManual {
		t.Fatalf("读回来的字段不对: %+v", rec)
	}
	if len(rec.Nodes) != 1 || rec.Nodes[0].Speed != 12.5 {
		t.Fatalf("节点明细没读回来: %+v", rec.Nodes)
	}
}

// 文件坏了就当没有历史，不能因此起不来，也不能因此再也写不进去。
func TestHistoryIgnoresBrokenFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(filepath.Join(dir, historyFile), []byte("{ this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := New(config.Default(), cfgPath, "", dir, Auth{Fallback: "pw"}, "", nil)
	if len(s.history) != 0 {
		t.Fatalf("坏文件应被忽略，实际读到 %d 轮", len(s.history))
	}

	// 追加一次就该把坏文件覆盖掉，之后的记录正常可读。
	s.appendHistory(roundRecord{At: "11-19 12:00:00", Trigger: triggerTimer, OK: true})
	s2 := New(config.Default(), cfgPath, "", dir, Auth{Fallback: "pw"}, "", nil)
	if len(s2.history) != 1 {
		t.Fatalf("坏文件之后应能重新写入，实际读到 %d 轮", len(s2.history))
	}
}

// 接口给的是「最新的在前」，界面直接从上往下画。
func TestHistoryAPINewestFirst(t *testing.T) {
	s := newHistoryServer(t)
	s.appendHistory(roundRecord{At: "older", Trigger: triggerTimer, OK: true})
	s.appendHistory(roundRecord{At: "newer", Trigger: triggerManual, OK: false, Err: "引擎起不来"})

	rec := call(s, "GET", "/api/history")
	if rec.Code != 200 {
		t.Fatalf("应返回 200，实际 %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		OK     bool          `json:"ok"`
		Keep   int           `json:"keep"`
		Rounds []roundRecord `json:"rounds"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("返回的不是 JSON: %v", err)
	}
	if !resp.OK || resp.Keep != historyKeep {
		t.Fatalf("响应头字段不对: %+v", resp)
	}
	if len(resp.Rounds) != 2 || resp.Rounds[0].At != "newer" || resp.Rounds[0].Err == "" {
		t.Fatalf("应最新的在前且带上失败原因，实际 %+v", resp.Rounds)
	}
}

// 两族都设成「关闭」时这一轮什么都没做，不该占历史名额，也不该记成失败。
func TestBothFamiliesOffRecordsNoHistory(t *testing.T) {
	s := newToolsTestServer(t, func(c *config.Config) {
		c.Speed.SourceMode = config.SourceOff
		c.IPv6SourceMode = config.SourceOff
	})
	s.enginePath = filepath.Join(t.TempDir(), "no-such-main.py")

	if err := s.runOnce(s.cfg.Clone(), triggerTimer); err != nil {
		t.Fatalf("两族都关闭不算失败，实际返回 %v", err)
	}
	s.mu.Lock()
	n := len(s.history)
	s.mu.Unlock()
	if n != 0 {
		t.Fatalf("没测速就不该记历史，实际记了 %d 条", n)
	}
}

// 失败的一轮也要留一条：否则「从几点开始坏的」永远看不出来。
func TestFailedRoundIsRecorded(t *testing.T) {
	old := retryDelay
	retryDelay = 0
	defer func() { retryDelay = old }()

	s := newToolsTestServer(t, func(c *config.Config) {
		c.Speed.SourceMode = config.SourceCustom
		c.Speed.ExtraSources = []string{"104.16.0.0/13"}
	})
	// 引擎路径不存在：必然在「准备测速引擎」那一步失败。
	s.enginePath = filepath.Join(t.TempDir(), "no-such-main.py")

	if err := s.runOnce(s.cfg.Clone(), triggerManual); err == nil {
		t.Fatal("引擎起不来时必须返回错误")
	}

	s.mu.Lock()
	rounds := append([]roundRecord(nil), s.history...)
	s.mu.Unlock()

	if len(rounds) != 1 {
		t.Fatalf("失败应记 1 条，实际 %d 条", len(rounds))
	}
	if rounds[0].OK || rounds[0].Err == "" {
		t.Fatalf("这条应是失败并带原因，实际 %+v", rounds[0])
	}
	if rounds[0].Trigger != triggerManual {
		t.Fatalf("触发来源应是手动，实际 %q", rounds[0].Trigger)
	}
}
