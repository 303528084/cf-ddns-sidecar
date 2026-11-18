package config

import "testing"

// IPv6SourceURLs 是「v6 段一行一个链接」的唯一解析入口。
//
// 为什么要单独钉：判断「用户到底填没填」分散在好几处（自动流程跑不跑 v6、
// 探测去不去拉、界面提示怎么写）。每处自己 strings.Split 一次，迟早会出现
// 「这里认为填了、那里认为没填」的分歧——最坏的表现是「AAAA 永远不写，
// 界面却显示已经配好了」。
func TestIPv6SourceURLs(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"空", "", nil},
		{"只有空白", "  \n\t\n", nil},
		{"一行（老配置的形态）", "https://a.example/v6.txt", []string{"https://a.example/v6.txt"}},
		{"两行", "https://a/1\nhttps://b/2", []string{"https://a/1", "https://b/2"}},
		{"前后空白和空行都忽略", "\n  https://a/1  \n\n https://b/2 \n", []string{"https://a/1", "https://b/2"}},
		{"# 注释行跳过", "# 这是注释\nhttps://a/1\n#https://b/2", []string{"https://a/1"}},
		{"CRLF（Windows 记事本编辑过）", "https://a/1\r\nhttps://b/2\r\n",
			[]string{"https://a/1", "https://b/2"}},
	}
	for _, c := range cases {
		cfg := &Config{IPv6ProbeURL: c.raw}
		got := cfg.IPv6SourceURLs()
		if len(got) != len(c.want) {
			t.Fatalf("%s: 拆出 %d 条（%v），应为 %d 条（%v）",
				c.name, len(got), got, len(c.want), c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("%s: 第 %d 条是 %q，应为 %q", c.name, i+1, got[i], c.want[i])
			}
		}
	}
}
