package config

// 这个文件守的是 ddns.env 的读写语义。
//
// 它被两条完全不同的路径写：后台（`web` 包调 UpdateEnvFile）和宿主机生命周期
// 脚本（`config_callback` / `main` 里的 sed/cat）。文件里还有用户手写的注释、
// 被注释掉的备用密钥。写坏一次的后果特别隐晦——界面说「已保存」，实际生效的
// 还是旧值，因为「最后一行生效」这条语义没被尊重。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempEnv(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ddns.env")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("准备 ddns.env 失败: %v", err)
	}
	return p
}

// TestUpdateEnvFileTakesLastUncommented 同一个 key 有多个未注释行时，改最后一行。
//
// 最后一行的值才是生效值（LoadEnvFile 后写覆盖先写）。改中间那行等于写进一个
// 不生效的位置：界面说保存成功，实际用的还是旧令牌。
func TestUpdateEnvFileTakesLastUncommented(t *testing.T) {
	p := writeTempEnv(t, "CF_API_TOKEN=first\nCF_API_TOKEN=second\n")
	if err := UpdateEnvFile(p, map[string]string{"CF_API_TOKEN": "new"}); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if got := LoadEnvFile(p)["CF_API_TOKEN"]; got != "new" {
		t.Fatalf("生效值应为 new，实际 %q（内容：%s）", got, mustRead(t, p))
	}
	if n := strings.Count(mustRead(t, p), "CF_API_TOKEN="); n != 2 {
		t.Errorf("不该多出一行同名 key，实际 %d 行：\n%s", n, mustRead(t, p))
	}
}

// TestUpdateEnvFileLeavesCommentedLines 被注释掉的备用密钥是用户自己留的备份，
// 一个字符都不能动；而且它不参与生效，去「接管」它只会让新值写进一个不生效的位置。
func TestUpdateEnvFileLeavesCommentedLines(t *testing.T) {
	p := writeTempEnv(t,
		"# 我的备注\n#CF_API_TOKEN=旧的备用令牌\nCF_API_TOKEN=old\nCFDDNS_PORT=8080\n")
	if err := UpdateEnvFile(p, map[string]string{"CF_API_TOKEN": "new"}); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	got := mustRead(t, p)
	for _, want := range []string{"# 我的备注", "#CF_API_TOKEN=旧的备用令牌", "CFDDNS_PORT=8080"} {
		if !strings.Contains(got, want) {
			t.Errorf("丢了 %q，现在的内容：\n%s", want, got)
		}
	}
	if kv := LoadEnvFile(p); kv["CF_API_TOKEN"] != "new" {
		t.Errorf("生效值应为 new，实际 %q", kv["CF_API_TOKEN"])
	}
}

// TestUpdateEnvFileKeepsFileEnding 反复保存不能让文件越攒越长（以前每写一次
// 末尾就多一个空行）。
func TestUpdateEnvFileKeepsFileEnding(t *testing.T) {
	p := writeTempEnv(t, "CF_API_TOKEN=a\n")
	for i := 0; i < 5; i++ {
		if err := UpdateEnvFile(p, map[string]string{"CF_API_TOKEN": "b"}); err != nil {
			t.Fatalf("第 %d 次写入失败: %v", i+1, err)
		}
	}
	got := mustRead(t, p)
	if strings.Count(got, "\n") != 1 || !strings.HasSuffix(got, "CF_API_TOKEN=b\n") {
		t.Fatalf("写了 5 次后末尾应只有一行，实际：%q", got)
	}
}

// TestUpdateEnvFileAppendsMissingKey 文件里没有的 key 追加到末尾（新装时的
// 模板里密钥全是注释掉的占位，走的就是这条路）。
func TestUpdateEnvFileAppendsMissingKey(t *testing.T) {
	p := writeTempEnv(t, "#CF_API_TOKEN=\nCFDDNS_PORT=8080\n")
	if err := UpdateEnvFile(p, map[string]string{"CF_API_TOKEN": "tok"}); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	got := mustRead(t, p)
	if !strings.Contains(got, "#CF_API_TOKEN=") {
		t.Errorf("模板里的注释占位不该被吃掉：\n%s", got)
	}
	if kv := LoadEnvFile(p); kv["CF_API_TOKEN"] != "tok" {
		t.Errorf("新 key 没写进去：%v", kv)
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("读 %s 失败: %v", p, err)
	}
	return string(b)
}
