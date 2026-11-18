package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 这一组用例守的是 v1.6.2 修掉的一个小瑕疵：真机日志里连着出现
//
//	[信息] 数据目录：/vol1/@appdata/cf-ddns-sidecar（容器内 /app/data）
//	[信息] 数据放在 /vol1/@appdata/cf-ddns-sidecar
//
// 同一句话说了两遍。前一句来自 compose 传进来的 CFDDNS_DATA_HOST（一手事实），
// 后一句来自宿主机脚本写的账本（v1.3.2～v1.4.1 时代靠它传递路径）。
// v1.5.1 起两套来源并存，于是重复。
//
// 去重很容易做过头，所以这里同时钉住三条：
//  1. 宿主机路径已知 → 账本那句不再念；
//  2. 拿不到环境变量 → 账本必须照念（它是唯一来源，删了就成了「什么都不说」）；
//  3. 警告类的话（数据没搬成、备份写不进去）**任何情况都不许被吞**。
//
// 为什么三个场景挤在一个测试函数里：config.resolvePath() 用 sync.Once 缓存
// CFDDNS_CONFIG，一个进程只认第一次读到的值。拆成三个测试函数的话，后两个
// 的 t.Setenv 根本不生效，会去读第一个测试已经被删掉的临时目录——症状是
// 「测试莫名报找不到账本」，比不写测试更浪费时间。

// writeLedger 在数据目录里摆一份账本，模拟飞牛宿主机脚本的产物。
func writeLedger(t *testing.T, dir, body string) {
	t.Helper()
	p := filepath.Join(dir, "location-status.txt")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("写账本 %s 失败: %v", p, err)
	}
}

// captureLog 把标准库 log 接到内存里，返回那块缓冲区；测试结束自动还原。
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	oldOut, oldFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0) // 去掉时间戳，断言才好写
	t.Cleanup(func() {
		log.SetOutput(oldOut)
		log.SetFlags(oldFlags)
	})
	return &buf
}

// ledgerDataOK 是一份「数据在官方目录、备份写不进去」的账本。
// 故意让备份这一半是坏的：这样才能验证去重只删了重复的数据那一句，
// 备份的告警还活着。
const ledgerDataOK = "time=2026-11-18 08:31:00\n" +
	"volume_root=/vol1\n" +
	"data_host=/vol1/@appdata/cf-ddns-sidecar\n" +
	"data_kind=real\n" +
	"data_real=/vol1/@appdata/cf-ddns-sidecar\n" +
	"backup_host=/var/apps/cf-ddns-sidecar-backup\n" +
	"backup_kind=real\n" +
	"backup_real=/var/apps/cf-ddns-sidecar-backup\n" +
	"backup_error=权限或只读挂载\n"

func TestReportLocation(t *testing.T) {
	dir := t.TempDir()
	// 账本读的是「配置文件所在目录」里的 location-status.txt。
	t.Setenv("CFDDNS_CONFIG", filepath.Join(dir, "config.json"))

	t.Run("宿主机路径已知时不再重复念账本", func(t *testing.T) {
		writeLedger(t, dir, ledgerDataOK)

		buf := captureLog(t)
		reportLocation(true)
		got := buf.String()

		if strings.Contains(got, "数据放在") {
			t.Fatalf("宿主机路径已知时不该再念一遍账本，实际日志：\n%s", got)
		}
		// 但备份的告警必须还在——去重不是「少说点话」，是「别重复说同一件事」。
		if !strings.Contains(got, "备份目录没在存储卷上") {
			t.Fatalf("备份告警被一起吞掉了，实际日志：\n%s", got)
		}
	})

	t.Run("拿不到环境变量时回退念账本", func(t *testing.T) {
		writeLedger(t, dir, ledgerDataOK)

		buf := captureLog(t)
		reportLocation(false)
		got := buf.String()

		if !strings.Contains(got, "数据放在 /vol1/@appdata/cf-ddns-sidecar") {
			t.Fatalf("没有环境变量时账本是唯一来源，必须照念，实际日志：\n%s", got)
		}
	})

	// 守住最容易被顺手删掉的那部分：「数据没搬到存储卷」是警告，即使宿主机
	// 路径已知也必须说。真机上这情况意味着「程序读得到数据，但那个位置不安全」
	// ——沉默等于骗人。
	t.Run("警告不被去重吞掉", func(t *testing.T) {
		writeLedger(t, dir, "time=2026-11-18 08:31:00\n"+
			"volume_root=/vol1\n"+
			"data_host=/var/apps/cf-ddns-sidecar-data\n"+
			"data_kind=real\n"+
			"data_real=/var/apps/cf-ddns-sidecar-data\n"+
			"data_error=Permission denied\n")

		buf := captureLog(t)
		reportLocation(true)
		got := buf.String()

		if !strings.Contains(got, "数据目录没搬到存储卷上") {
			t.Fatalf("警告被去重逻辑吞了，实际日志：\n%s", got)
		}
		if !strings.Contains(got, "Permission denied") {
			t.Fatalf("原始错误原因丢了，实际日志：\n%s", got)
		}
	})

	// 「不是用安装包装的」这条静默路径：自己写 compose 跑的人没有账本，
	// 不该每次启动都刷一条警告。
	t.Run("没有账本时完全沉默", func(t *testing.T) {
		if err := os.Remove(filepath.Join(dir, "location-status.txt")); err != nil {
			t.Fatalf("删账本失败: %v", err)
		}

		buf := captureLog(t)
		reportLocation(true)
		if s := buf.String(); s != "" {
			t.Fatalf("没有账本时不该有任何输出，实际：\n%s", s)
		}
	})
}
