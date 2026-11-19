package web

import (
	"errors"
	"testing"

	"github.com/303528084/cf-ddns-sidecar/config"
	"github.com/303528084/cf-ddns-sidecar/ddns"
)

// fakeDDNS 只记账，不出网。ClearRecords 被调到时把类型记下来，
// 用来确认「写 A 的时候清的是 AAAA」，不是反过来。
type fakeDDNS struct {
	cleared []string
	err     error
}

func (f *fakeDDNS) EnsureRecords(string, []string, ddns.RecordOptions) error { return nil }
func (f *fakeDDNS) Verify(string, string) (ddns.RecordState, error)          { return ddns.RecordState{}, nil }
func (f *fakeDDNS) Name() string                                             { return "fake" }
func (f *fakeDDNS) ClearRecords(domain, rtype string) (int, error) {
	f.cleared = append(f.cleared, rtype)
	if f.err != nil {
		return 0, f.err
	}
	return 2, nil
}

func TestPruneOtherFamilyFollowsWrittenFamily(t *testing.T) {
	s := New(config.Default(), "", "", t.TempDir(), Auth{}, "", nil)
	cases := []struct{ written, want string }{
		{ddns.TypeA, ddns.TypeAAAA},
		{ddns.TypeAAAA, ddns.TypeA},
	}
	for _, c := range cases {
		f := &fakeDDNS{}
		if !s.pruneOtherFamily(f, "cf.example.com", c.written) {
			t.Fatalf("%s 写成功时应该清理另一族", c.written)
		}
		if len(f.cleared) != 1 || f.cleared[0] != c.want {
			t.Fatalf("写了 %s 该清 %s，实际清了 %v", c.written, c.want, f.cleared)
		}
	}
}

// 一族都没写上去时不能清：服务商那头一坏就把另一族删空，域名会两头都没有记录。
func TestPruneOtherFamilySkipsWhenNothingWritten(t *testing.T) {
	s := New(config.Default(), "", "", t.TempDir(), Auth{}, "", nil)
	f := &fakeDDNS{}
	if s.pruneOtherFamily(f, "cf.example.com", "") {
		t.Fatal("没写成功时不该报告清成功")
	}
	if len(f.cleared) != 0 {
		t.Fatalf("没写成功时不该清任何记录，实际清了 %v", f.cleared)
	}
}

// 清理失败不能把这一轮算成成功，下一轮会再试一次。
func TestPruneOtherFamilyReportsFailure(t *testing.T) {
	s := New(config.Default(), "", "", t.TempDir(), Auth{}, "", nil)
	f := &fakeDDNS{err: errors.New("boom")}
	if s.pruneOtherFamily(f, "cf.example.com", ddns.TypeA) {
		t.Fatal("清理失败不该报告成功")
	}
}
