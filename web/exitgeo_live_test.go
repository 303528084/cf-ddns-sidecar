package web

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLiveTraceColo 真连 Cloudflare 验一次「穿过候选 IP 读机房代码」。
//
// 平时跳过：它要能连上 cloudflare-ech.com 的 443，在隔离网络/被墙的环境里
// 必然失败，不能拖累常规回归。需要时手动开：
//
//	LIVE_TRACE=1 go test ./web/ -run TestLiveTraceColo -v
//
// 保留它的理由：exitgeo 的假服务器单测只能证明「我方逻辑对」，证明不了
// 「Cloudflare 真的按我们这条路径返回 colo」。而这一行日志的全部价值就是
// 它说的一定是真话，所以必须有一次真连的凭据。
func TestLiveTraceColo(t *testing.T) {
	if os.Getenv("LIVE_TRACE") == "" {
		t.Skip("跳过：需要真实网络，LIVE_TRACE=1 才跑")
	}
	ips := []string{"172.64.229.179", "162.159.5.114", "108.162.196.99"}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	got := 0
	for _, ip := range ips {
		loc, colo, err := traceThroughIP(ctx, ip, 443)
		if err != nil {
			t.Logf("%-16s 探测失败: %v", ip, err)
			continue
		}
		got++
		t.Logf("%-16s loc=%-3s colo=%-3s → 显示为 %s", ip, loc, colo, exitInfo(colo))
		if len(colo) != 3 {
			t.Errorf("%s 的 colo 不是 3 位：%q", ip, colo)
		}
		if strings.TrimSpace(exitInfo(colo)) == "" {
			t.Errorf("%s 的显示文本为空", ip)
		}
	}
	if got == 0 {
		t.Skip("这条网络连不上 cloudflare-ech.com，跳过（与实现无关）")
	}
}
