package applog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newLog(t *testing.T, maxBytes int64) (*Log, string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "app.log")
	l, err := Open(p, maxBytes)
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, p
}

func TestWriteAndTail(t *testing.T) {
	l, p := newLog(t, 0)
	l.Line("第一行")
	l.Line("第二行\n") // 调用方带换行也不能出现空行

	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("读日志文件失败: %v", err)
	}
	if got := string(raw); got != "第一行\n第二行\n" {
		t.Fatalf("文件内容不对: %q", got)
	}

	lines := l.Tail(10)
	if len(lines) != 2 || lines[0] != "第一行" || lines[1] != "第二行" {
		t.Fatalf("Tail 结果不对: %#v", lines)
	}
	if got := l.Tail(1); len(got) != 1 || got[0] != "第二行" {
		t.Fatalf("Tail(1) 应只返回最后一行，实际 %#v", got)
	}
}

// TestRotate 验证超过上限会轮转，并且旧内容没有丢。
func TestRotate(t *testing.T) {
	l, p := newLog(t, 64)

	for i := 0; i < 20; i++ {
		l.Line(strings.Repeat("x", 20))
	}

	cur, err := os.Stat(p)
	if err != nil {
		t.Fatalf("当前日志文件不见了: %v", err)
	}
	if cur.Size() > 64 {
		t.Fatalf("当前文件应不超过 64 字节，实际 %d", cur.Size())
	}

	old, err := os.ReadFile(p + historySuffix)
	if err != nil {
		t.Fatalf("轮转后没有历史文件: %v", err)
	}
	if len(old) == 0 {
		t.Fatal("历史文件是空的，轮转把日志弄丢了")
	}
}

// TestTailSkipsTruncatedFirstLine 验证从文件中间开始读时，丢掉被截断的半行。
func TestTailSkipsTruncatedFirstLine(t *testing.T) {
	l, p := newLog(t, 0)
	_ = l.Close()

	// 手工造一个比 tailReadBytes 更大的文件，确保 Tail 会从中间开始读。
	var b strings.Builder
	b.WriteString("这是一行会被截断的开头\n")
	for b.Len() < int(tailReadBytes)+1024 {
		b.WriteString("填充行 0123456789\n")
	}
	b.WriteString("最后一行\n")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("准备文件失败: %v", err)
	}
	l2, err := Open(p, 0)
	if err != nil {
		t.Fatalf("重新打开失败: %v", err)
	}
	defer l2.Close()

	lines := l2.Tail(1)
	if len(lines) != 1 || lines[0] != "最后一行" {
		t.Fatalf("Tail(1) 应为最后一行，实际 %#v", lines)
	}
	for _, ln := range l2.Tail(50) {
		if !strings.Contains(ln, "填充行") {
			// 只允许最后一行是别的内容；出现被截断的残片就说明没丢干净。
			if ln != "最后一行" {
				t.Fatalf("出现了不该有的行: %q", ln)
			}
		}
	}
}

// TestOpenCreatesDirMissing 验证目录不存在时返回错误而不是 panic，
// 这样 main 可以降级成「只在内存里记日志」。
func TestOpenCreatesDirMissing(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(filepath.Join(dir, "no-such-sub", "app.log"), 0)
	if err == nil {
		_ = l.Close()
		t.Fatal("目录不存在时应当返回错误")
	}
}
