package sidecar

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, dir, content string) string {
	t.Helper()
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("写测试配置失败: %v", err)
	}
	return p
}

func TestReadIsPureUntilAck(t *testing.T) {
	dir := t.TempDir()
	p := writeConfig(t, dir, `{"last_result_ip":"1.1.1.1","last_result_time":"x"}`)
	o := NewObserver(p)

	e1 := o.Read()
	if e1.Kind != EventInit || e1.IP != "1.1.1.1" {
		t.Fatalf("首次读取应为 EventInit/1.1.1.1，得到 %v/%q", e1.Kind, e1.IP)
	}

	// 关键语义：未 Ack 前重复 Read 返回相同事件（失败重试的基础）。
	e2 := o.Read()
	if e2.Kind != EventInit || e2.IP != "1.1.1.1" {
		t.Fatalf("未 Ack 时应重复返回事件，得到 %v/%q", e2.Kind, e2.IP)
	}

	o.Ack("1.1.1.1")
	if e := o.Read(); e.Kind != EventNone {
		t.Fatalf("Ack 后相同 IP 应为 EventNone，得到 %v", e.Kind)
	}

	_ = writeConfig(t, dir, `{"last_result_ip":"9.9.9.9"}`)
	e3 := o.Read()
	if e3.Kind != EventChanged || e3.IP != "9.9.9.9" {
		t.Fatalf("变化后应为 EventChanged/9.9.9.9，得到 %v/%q", e3.Kind, e3.IP)
	}
	// 未 Ack 的新 IP 重复出现仍触发事件（待重试）。
	if e := o.Read(); e.Kind != EventChanged {
		t.Fatalf("未 Ack 的新 IP 应持续触发 EventChanged，得到 %v", e.Kind)
	}
}

func TestReadMissingAndBroken(t *testing.T) {
	o := NewObserver(filepath.Join(t.TempDir(), "nope.json"))
	if e := o.Read(); e.Kind != EventNone {
		t.Fatalf("文件缺失应为 EventNone，得到 %v", e.Kind)
	}

	dir := t.TempDir()
	p := writeConfig(t, dir, `{broken json`)
	o2 := NewObserver(p)
	if e := o2.Read(); e.Kind != EventNone {
		t.Fatalf("损坏 JSON 应为 EventNone，得到 %v", e.Kind)
	}
}

func TestReadEmptyAndInvalid(t *testing.T) {
	dir := t.TempDir()

	p := writeConfig(t, dir, `{"last_result_ip":""}`)
	if e := NewObserver(p).Read(); e.Kind != EventNone {
		t.Fatalf("空 IP 应为 EventNone，得到 %v", e.Kind)
	}

	p = writeConfig(t, dir, `{"last_result_ip":"999.1.1.1"}`)
	if e := NewObserver(p).Read(); e.Kind != EventNone {
		t.Fatalf("非法 IP 应为 EventNone，得到 %v", e.Kind)
	}
}

func TestSeedPreventsDuplicate(t *testing.T) {
	dir := t.TempDir()
	p := writeConfig(t, dir, `{"last_result_ip":"1.1.1.1"}`)
	o := NewObserver(p)
	o.Seed("1.1.1.1")
	if e := o.Read(); e.Kind != EventNone {
		t.Fatalf("Seed 后相同 IP 不应产生事件，得到 %v", e.Kind)
	}
}

func TestAckRejectsInvalid(t *testing.T) {
	dir := t.TempDir()
	p := writeConfig(t, dir, `{"last_result_ip":"1.1.1.1"}`)
	o := NewObserver(p)
	o.Ack("")
	o.Ack("999.1.1.1")
	if e := o.Read(); e.Kind != EventInit {
		t.Fatalf("非法 Ack 不应推进状态，仍应为 EventInit，得到 %v", e.Kind)
	}
}
