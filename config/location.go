package config

import (
	"os"
	"path/filepath"
	"strings"
)

// 这个文件解决 2026-11-17 真机验收时发现的问题：脚本说「已搬到存储卷」，其实压根没搬，
// 而日志里一个字都没提。
//
// 事实经过：v1.3.2、v1.4.0、v1.4.1 的 cmd/main 里都写着「数据目录已搬到存储卷：
// /var/apps/<app>-data -> /vol1/<app>-data」，用户按这句话翻文件管理器，那两个目录
// 在 /vol1 根、@appcenter、@appshare 里都没有。真因是 /vol1 根属于 root，宿主机脚本
// 以 run-as: package 的普通用户跑，mkdir 直接被拒，那里写着 2>/dev/null 把错误吞了，
// 于是走了「用真实目录」的兜底分支。一个正确的兜底 + 一句不存在的解释，比报错更难查。
//
// 从 v1.4.2 起改成两段式：宿主机脚本把真相写进数据目录里的 location-status.txt，
// 程序启动时读出来打进运行日志。这里的代码只做第二段，只转述、不推断：文件里写什么
// 就说什么，没读到就承认没读到，上一版的错误正是「照着想象打印」。

// locationFile 是宿主机脚本写的账本文件名，落在数据目录里。
// 必须和 fpk/template/cmd/main 里 record_location() 的文件名保持一致。
const locationFile = "location-status.txt"

// LocationStatus 是一次「目录安置」的结果快照。字段名对应账本里的 key，全是字符串：
// 账本是 shell 拼出来的纯文本，强行转 bool/数字只会多一层「解析失败怎么办」。
type LocationStatus struct {
	File  string // 账本文件路径（找不到时也能告诉用户该去哪儿找）
	Found bool   // 读到了没有；false 表示不是用飞牛安装包装的，或脚本没跑到

	Time       string // 脚本写下这份账本的时刻
	VolumeRoot string // 探测到的存储卷根，例如 /vol1；空表示没探到

	DataHost  string // 宿主机上的数据目录路径（容器里 /app/data 就是挂的它）
	DataKind  string // 恒为 "real"。v1.6.4 删掉建软链的代码后不再可能出现 "symlink"；
	// 字段保留只为兼容旧账本（v1.3.2～v1.4.1 写的文件里可能是 symlink）
	DataReal  string // 解析软链之后的真实路径；没软链时等于 DataHost
	DataError string // 非空 = 数据目录建不出来 / 容器用户写不进去（含原始错误）

	BackupHost  string
	BackupKind  string
	BackupReal  string
	BackupError string
}

// InspectLocation 读一次账本。只读，不改任何东西，读不到也不报错。
//
// 为什么读不到要静默：不是所有人都用飞牛安装包（有人自己写 compose 跑），
// 那种部署本来就没有这个文件，每次都打一条警告只会变成噪音。
func InspectLocation() LocationStatus {
	p := filepath.Join(filepath.Dir(resolvePath()), locationFile)
	st := LocationStatus{File: p}

	b, err := os.ReadFile(p)
	if err != nil {
		return st
	}
	st.Found = true

	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		// 用第一个 "=" 切：错误信息里带 "="（比如 base64、路径里的 =）也不会被切坏。
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "time":
			st.Time = v
		case "volume_root":
			st.VolumeRoot = v
		case "data_host":
			st.DataHost = v
		case "data_kind":
			st.DataKind = v
		case "data_real":
			st.DataReal = v
		case "data_error":
			st.DataError = v
		case "backup_host":
			st.BackupHost = v
		case "backup_kind":
			st.BackupKind = v
		case "backup_real":
			st.BackupReal = v
		case "backup_error":
			st.BackupError = v
		}
	}
	return st
}

// DataWhere 返回「数据现在实际在哪个目录」，用于日志里那句「数据实际在 X」。
// 优先用解析软链后的真实路径，没有就退回宿主机上的挂载路径。
//
// 只提供这一个是刻意的：这里不提供「本该在卷上的路径」，因为曾经想过用它在
// 日志里拼一条 `mkdir` 命令让用户复制粘贴，实测发现那条命令会把目录属主改成
// 容器用户、反过来让宿主机脚本写不进去，**一条建议换来一条永远消不掉的告警**。
// 所以这里只回答「现在在哪」，不回答「你该敲什么」。
func (s LocationStatus) DataWhere() string {
	if s.DataReal != "" {
		return s.DataReal
	}
	return s.DataHost
}
