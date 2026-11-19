package config

// 来源模式（内置 / 自定义 / 关闭）的默认值和取值。
//
// 这两个默认值是升级兼容的开关，写错一次就是「所有人都受影响」：
//   · v4 缺字段必须按内置。按关闭读的话，所有人升级后一轮都测不出 v4，
//     解析记录停在原地，而界面上看着一切正常。
//   · v6 缺字段必须按关闭。按内置读的话，以前从没填过 v6 的人会突然开始跑
//     IPv6 测速，等于替用户改了行为。

import "testing"

func TestEffectiveSourceModeDefaults(t *testing.T) {
	cases := []struct {
		name  string
		field string
		want  string
	}{
		{"v4 缺字段按内置", "", SourceBuiltin},
		{"v4 内置", SourceBuiltin, SourceBuiltin},
		{"v4 自定义", SourceCustom, SourceCustom},
		{"v4 关闭", SourceOff, SourceOff},
		{"v4 写坏的值按内置", "on", SourceBuiltin},
	}
	for _, c := range cases {
		cfg := &Config{}
		cfg.Speed.SourceMode = c.field
		if got := cfg.EffectiveSourceMode(); got != c.want {
			t.Errorf("%s：应为 %q，实际 %q", c.name, c.want, got)
		}
	}

	v6 := []struct {
		name  string
		field string
		want  string
	}{
		{"v6 缺字段按关闭", "", SourceOff},
		{"v6 内置", SourceBuiltin, SourceBuiltin},
		{"v6 自定义", SourceCustom, SourceCustom},
		{"v6 关闭", SourceOff, SourceOff},
		{"v6 写坏的值按关闭", "on", SourceOff},
	}
	for _, c := range v6 {
		cfg := &Config{}
		cfg.IPv6SourceMode = c.field
		if got := cfg.EffectiveIPv6SourceMode(); got != c.want {
			t.Errorf("%s：应为 %q，实际 %q", c.name, c.want, got)
		}
	}
}

// 三种模式各自给出什么来源。内置模式必须忽略用户框里留着的旧内容——
// 否则「切到内置」之后测的还是上次那份，界面和实际对不上。
func TestSourcesByMode(t *testing.T) {
	cfg := &Config{}
	cfg.Speed.ExtraSources = []string{"104.16.0.0/13"}
	cfg.IPv6ProbeURL = "https://example.com/v6.txt\n# 注释\nhttps://example.com/v6-2.txt"

	// 缺字段：v4 内置、v6 关闭
	if got := cfg.IPv4Sources(); len(got) != 1 || got[0] != BuiltinV4Source {
		t.Fatalf("v4 默认应给内置链接，实际 %v", got)
	}
	if got := cfg.IPv6Sources(); len(got) != 0 {
		t.Fatalf("v6 默认应关闭（不给来源），实际 %v", got)
	}

	cfg.Speed.SourceMode = SourceCustom
	if got := cfg.IPv4Sources(); len(got) != 1 || got[0] != "104.16.0.0/13" {
		t.Fatalf("自定义应给用户填的内容，实际 %v", got)
	}

	cfg.Speed.SourceMode = SourceOff
	if got := cfg.IPv4Sources(); len(got) != 0 {
		t.Fatalf("关闭应不给来源，实际 %v", got)
	}

	cfg.IPv6SourceMode = SourceBuiltin
	if got := cfg.IPv6Sources(); len(got) != 1 || got[0] != BuiltinV6Source {
		t.Fatalf("v6 内置应给内置链接，实际 %v", got)
	}

	cfg.IPv6SourceMode = SourceCustom
	got := cfg.IPv6Sources()
	if len(got) != 2 || got[1] != "https://example.com/v6-2.txt" {
		t.Fatalf("v6 自定义应跳过注释行，实际 %v", got)
	}
}

// 内置链接是写死在程序里的，绝不能出现在配置里：谁把它存进 config.json，
// 「不暴露」这件事就自动失效了（导出备份、发截图都会带出去）。
func TestBuiltinLinkIsConstantNotConfig(t *testing.T) {
	cfg := &Config{}
	cfg.Speed.SourceMode = SourceBuiltin
	cfg.IPv6SourceMode = SourceBuiltin
	// 模式字段只该是三个词之一，不含地址。
	if _, err := NormalizeSourceMode(cfg.Speed.SourceMode); err != nil {
		t.Fatalf("内置模式的取值本身不合法：%v", err)
	}
	if cfg.Speed.ExtraSources != nil || cfg.IPv6ProbeURL != "" {
		t.Fatal("新配置不该被内置链接填满：链接只来自 IPv4Sources/IPv6Sources()")
	}
}

func TestNormalizeSourceMode(t *testing.T) {
	for _, ok := range []string{SourceBuiltin, SourceCustom, SourceOff, " off "} {
		if _, err := NormalizeSourceMode(ok); err != nil {
			t.Errorf("%q 应被接受，实际报错 %v", ok, err)
		}
	}
	for _, bad := range []string{"", "on", "BUILTIN", "https://example.com/x.txt"} {
		if _, err := NormalizeSourceMode(bad); err == nil {
			t.Errorf("%q 应被拒绝", bad)
		}
	}
}
