package main

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/stone/cf-ddns-sidecar/config"
	"github.com/stone/cf-ddns-sidecar/provider"
	"github.com/stone/cf-ddns-sidecar/sidecar"
)

// version 由构建时注入：-ldflags "-X main.version=v1.0.0"
var version = "dev"

func main() {
	// 统一日志流：所有阶段（含下面的 Fatal 与 Runner 内日志）都走 stdout，
	// 便于容器日志采集。
	log.SetOutput(os.Stdout)

	configPath := flag.String("c", "/app/config.yaml", "配置文件路径")
	flag.Parse()

	log.Printf("cf-ddns-sidecar %s 启动中", version)

	// 配置未就绪（用户尚未填写 ddns.env / config.yaml）时等待重试，
	// 而不是崩溃进入重启循环——首次安装体验：日志会持续提示缺什么。
	var cfg *config.Config
	for {
		c, err := config.Load(*configPath)
		if err == nil {
			cfg = c
			break
		}
		log.Printf("[等待] 配置未就绪: %v（10 秒后重试；请填写 ddns.env 并重启应用）", err)
		time.Sleep(10 * time.Second)
	}

	p, err := provider.New(cfg.Provider, cfg.Domain, cfg.Credentials)
	if err != nil {
		log.Fatalf("初始化服务商失败: %v", err)
	}

	runner, err := sidecar.NewRunner(cfg, p)
	if err != nil {
		log.Fatalf("初始化运行器失败: %v", err)
	}

	if err := runner.Run(); err != nil {
		log.Fatalf("运行失败: %v", err)
	}
}
