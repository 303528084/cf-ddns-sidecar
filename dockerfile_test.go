package main

// Dockerfile 是逐个目录 COPY 的（为了让改动只失效对应那一层缓存）。
// 好处是构建快，代价是**新增一个包就必须在 Dockerfile 里加一行**，
// 而漏掉的那一行在本地几乎发现不了：
//   平时验证是 `docker run -v 工作区:/w go build ./...`，整个工作区都挂进去，
//   什么都不缺；只有真走 `docker build` 时才会报
//   「no required module provides package ...」。
//
// 这条测试是用一次真实翻车换来的：v1.2.0 第一波加了 applog 包，忘了加
// `COPY applog/ applog/`，本地全绿、推到 CI 才在「构建并推送镜像」那步炸掉。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDockerfileCopiesEveryGoPackage(t *testing.T) {
	raw, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatalf("读不到 Dockerfile: %v", err)
	}
	dockerfile := string(raw)

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("读工作目录失败: %v", err)
	}

	checked := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		// third_party 里是 Python（打包时另外 COPY），点开头的目录被 Go 工具链忽略
		if strings.HasPrefix(name, ".") || name == "third_party" || name == "dist-fpk" {
			continue
		}
		// 目录里没有任何 .go 文件就不是一个包，不用管
		goFiles, _ := filepath.Glob(filepath.Join(name, "*.go"))
		if len(goFiles) == 0 {
			continue
		}
		checked++
		want := "COPY " + name + "/ " + name + "/"
		if !strings.Contains(dockerfile, want) {
			t.Errorf("Dockerfile 少了 `%s`：包 %q 没被拷进构建镜像，"+
				"本地挂载整个工作区照样能编过，但 docker build 会失败", want, name)
		}
	}

	if checked == 0 {
		t.Fatal("一个 Go 包都没扫到，说明这个测试本身失效了（工作目录不对？）")
	}
}
