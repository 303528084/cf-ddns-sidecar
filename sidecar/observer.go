// Package sidecar 实现从主体容器共享的 config.json 读取最优 IP 并检测变化。
package sidecar

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// subjectConfig 只包含我们关心的字段；对主体 config.json 的其它字段不敏感。
// 字段名 last_result_ip 已对照 cf-dns-select 源码 config/config.go 核实一致。
type subjectConfig struct {
	LastResultIP   string `json:"last_result_ip"`
	LastResultTime string `json:"last_result_time"`
}

// Event 表示一次读取产生的事件。
type Event struct {
	// IP 是本次读到的有效最优 IP；为空表示无可用的最优 IP。
	IP string
	// Kind 事件类型。
	Kind EventKind
	// Detail 供日志使用的人类可读说明。
	Detail string
}

// EventKind 事件类型。
type EventKind int

const (
	// EventNone 未读到有效 IP、文件问题或 IP 与已确认值相同；不应触发推送。
	EventNone EventKind = iota
	// EventInit 读到有效 IP 且观测器尚无已确认值。
	EventInit
	// EventChanged 读到的 IP 与已确认值不同（含上次推送失败待重试的情形）。
	EventChanged
)

// Observer 读取主体 config.json 并跟踪已确认（成功推送过）的 IP。
//
// 关键语义：Read 是纯读取，不推进内部状态；只有 Runner 在推送成功后
// 调用 Ack 确认。这样推送失败时下一轮 Read 仍会返回事件，实现重试。
// Observer 仅在主循环所在 goroutine 内使用，未做并发保护。
type Observer struct {
	path     string
	knownIP  string
	hasKnown bool
}

// NewObserver 创建一个读取指定路径的观测器。
func NewObserver(path string) *Observer {
	return &Observer{path: path}
}

// Read 读取一次配置文件并返回一个事件。它不会推进内部状态，
// 也不会因文件缺失/损坏而 panic。
func (o *Observer) Read() Event {
	data, err := os.ReadFile(o.path)
	if err != nil {
		if os.IsNotExist(err) {
			return Event{Kind: EventNone, Detail: fmt.Sprintf("主体配置文件尚不存在: %s", o.path)}
		}
		return Event{Kind: EventNone, Detail: fmt.Sprintf("读取主体配置文件失败: %v", err)}
	}

	var sc subjectConfig
	if err := json.Unmarshal(data, &sc); err != nil {
		return Event{Kind: EventNone, Detail: fmt.Sprintf("主体配置文件格式异常: %v", err)}
	}

	ip := strings.TrimSpace(sc.LastResultIP)
	if ip == "" {
		return Event{Kind: EventNone, Detail: "主体尚无最优 IP（last_result_ip 为空），等待测速完成"}
	}
	if net.ParseIP(ip) == nil {
		return Event{Kind: EventNone, Detail: fmt.Sprintf("主体最优 IP 格式非法: %q", ip)}
	}

	if !o.hasKnown {
		return Event{Kind: EventInit, IP: ip, Detail: fmt.Sprintf("待推送：获取最优 IP %s", ip)}
	}
	if o.knownIP == ip {
		return Event{Kind: EventNone, Detail: fmt.Sprintf("最优 IP 未变化: %s", ip)}
	}
	return Event{Kind: EventChanged, IP: ip, Detail: fmt.Sprintf("最优 IP 已变化: %s -> %s", o.knownIP, ip)}
}

// Ack 确认给定 IP 已成功推送，推进内部已知状态。
// 只有推送（及状态持久化）成功后才应调用；失败时跳过，下一轮自然重试。
func (o *Observer) Ack(ip string) {
	ip = strings.TrimSpace(ip)
	if ip != "" && net.ParseIP(ip) != nil {
		o.knownIP = ip
		o.hasKnown = true
	}
}

// Seed 用给定的 IP 播种已知状态（从持久化状态恢复时使用），
// 使重启后相同 IP 不被当作新变化重复推送。
func (o *Observer) Seed(ip string) {
	o.Ack(ip)
}
