// Package applog 把进程日志写进数据目录下的文件，按大小自动轮转。
//
// 为什么需要它：界面上那份运行日志只存在内存里（最多 300 行），容器一重启
// 就全没了。2026-11-17 排查「升级后配置丢光」时最要命的一点，就是出事那段
// 记录已经不存在了——只能靠用户手抄屏幕上的几行去推断。日志落盘之后，
// 重启之前发生过什么还翻得出来。
//
// 只留一份历史（app.log + app.log.1）是刻意的：这是个边车程序，日志量很小，
// 两份足够回看「上一次重启前后」，也不会把数据目录撑大。
package applog

import (
	"io"
	"os"
	"strings"
	"sync"
)

const (
	// DefaultMaxBytes 是单个日志文件的上限（2MB）。超了就轮转。
	DefaultMaxBytes int64 = 2 << 20

	// historySuffix 是轮转后保留的那份历史文件名后缀。
	historySuffix = ".1"

	// tailReadBytes 是 Tail 最多往回读多少字节。日志文件上限 2MB，
	// 全读进内存没必要——界面上最多也就显示几百行。
	tailReadBytes int64 = 256 << 10
)

// Log 是一个追加写、按大小轮转的文件日志。
//
// 并发安全：log.SetOutput 那条路（进程各处 log.Printf）和 web 包直接调 Line
// 那条路可能同时写，所以每次写入都在锁里完成。
type Log struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	size     int64
	f        *os.File
}

// Open 打开（或创建）日志文件。maxBytes <= 0 时用 DefaultMaxBytes。
//
// 返回错误时调用方应当继续跑，只是退回「日志只在内存里」的老样子——
// 日志写不了绝不能拖垮主功能。
func Open(path string, maxBytes int64) (*Log, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	l := &Log{path: path, maxBytes: maxBytes}
	if err := l.reopen(); err != nil {
		return nil, err
	}
	return l, nil
}

// Write 实现 io.Writer，可以直接挂到 log.SetOutput 上。
//
// 写失败一律返回「全部写成功、无错误」：日志是附带品，任何调用方都不该
// 因为日志写不进去而改变自己的行为。
func (l *Log) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.f == nil {
		// 上一次轮转时新文件没打开成功（磁盘满、目录被删等）。每次写都重试
		// 一次，条件恢复后日志就能接着记，而不是从此永久静默丢失。
		if err := l.reopen(); err != nil {
			return len(p), nil
		}
	}
	// size > 0 才轮转：单条就超过上限时让它照写，免得无限轮转。
	if l.size > 0 && l.size+int64(len(p)) > l.maxBytes {
		l.rotate()
	}
	n, err := l.f.Write(p)
	l.size += int64(n)
	if err != nil {
		return len(p), nil
	}
	return n, nil
}

// Line 写一行（自动补换行，并去掉调用方可能带上的换行）。
func (l *Log) Line(s string) {
	_, _ = l.Write([]byte(strings.TrimRight(s, "\r\n") + "\n"))
}

// Tail 返回文件最后 n 行（不含换行符），用于重启后把历史回填到界面。
func (l *Log) Tail(n int) []string {
	if n <= 0 {
		return nil
	}

	// 只读文件、不碰写入句柄，所以不必和 Write 抢同一把锁去管 l.f，
	// 但仍要锁：避免读到轮转过程中的半截。
	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.Open(l.path)
	if err != nil {
		return nil
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil
	}
	size := st.Size()
	if size == 0 {
		return nil
	}
	start := int64(0)
	if size > tailReadBytes {
		start = size - tailReadBytes
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil
	}
	buf, err := io.ReadAll(f)
	if err != nil {
		return nil
	}

	lines := strings.Split(strings.TrimRight(string(buf), "\r\n"), "\n")
	// 从中间开始读的话，第一行大概率是被截断的半行，丢掉。
	if start > 0 && len(lines) > 0 {
		lines = lines[1:]
	}

	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		out = append(out, ln)
	}
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}

// Close 关闭文件句柄。之后仍可 Write（会重新打开）。
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// reopen 重新打开当前日志文件（追加模式）并同步 size。调用方必须已持锁或独占访问。
func (l *Log) reopen() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	if l.f != nil {
		_ = l.f.Close()
	}
	l.f = f
	l.size = 0
	if st, serr := f.Stat(); serr == nil {
		l.size = st.Size()
	}
	return nil
}

// rotate 把当前文件改名成 app.log.1（覆盖上一份历史），再新建一个空文件。
// 调用方必须已持锁。
func (l *Log) rotate() {
	if l.f != nil {
		_ = l.f.Close()
		l.f = nil
	}
	_ = os.Remove(l.path + historySuffix)
	_ = os.Rename(l.path, l.path+historySuffix)
	// 打开失败也不报错：l.f 留 nil，下一次 Write 会再试。
	_ = l.reopen()
}
