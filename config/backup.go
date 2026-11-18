package config

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"
)

// 这个文件解决 2026-11-17 深夜暴露的第四个漏洞：备份整条链路都押在「飞牛会执行
// upgrade_init」上，而它没执行。
//
// 事实经过：v1.3.1 装上去之后后台里 AdGuard 地址、域名、密钥全空了，顶上没有恢复红条，
// 运行日志里也没有「已从升级前的自动备份恢复」，只有「已把安装向导里填的端口写入
// ddns.env」这种首次启动才打的行。翻译成人话：升级前那一刻备份目录是空的，宿主机脚本
// 压根没跑（或跑了但写不进去），程序手里没有可捡的东西。
//
// 结论不是「恢复逻辑写错了」，而是「不该把唯一一份备份的生成权交给别人」。从 v1.3.2 起
// 程序自己在每次保存配置之后立刻备一份：用户点过一次「保存全部设置」，备份目录里就有
// 最新的，不依赖 upgrade_init 跑不跑、跑得早晚、有没有权限。升级脚本那份仍然保留，
// 它覆盖「装完之后一次都没保存过」的情况，两边写同一个目录、同一套目录名，恢复时按
// 名字取最新，不冲突。
//
// 三条硬约束，缺一条就会变成「看起来有备份、其实没用」：
//  1. 写不进去就算了。备份是加分项，绝不能因为它失败而让用户存不了配置。
//  2. 内容没变就不重复备。测速每跑一次都会改 lastIP，不判重的话三份历史会被几分钟内
//     刷光，真出事时反而没有「几小时前那份」。
//  3. 只保留最新 3 份，和升级脚本一致。

// snapshotPattern 认「备份目录名」：20261117-190500。必须和 upgrade_init 里
// `date +%Y%m%d-%H%M%S` 的格式一致：两边的备份混在同一个目录里，恢复时靠目录名的
// 字典序取最新，格式不一样就排错了。
var snapshotPattern = regexp.MustCompile(`^\d{8}-\d{6}$`)

// snapshotKeep 只保留最近几份。和 upgrade_init 的 `tail -n +4` 对齐。
const snapshotKeep = 3

// snapshotFileMode 决定备份副本的权限。
// config.json 里有 AdGuard 密码、ddns.env 里有各家 DNS 密钥，不该对同机
// 其他用户可读；dashboard-password 和标记文件按常规 0644。
func snapshotFileMode(name string) os.FileMode {
	if name == "config.json" {
		return 0o600
	}
	return 0o644
}

// writeSnapshot 在 config.json 成功落盘之后调用，把现在的 4 个配置文件
// 复制一份到备份根目录下的 <时间> 子目录。返回新建的目录；没做事时返回空。
//
// 刻意**不**自己创建备份根目录：根目录不存在就说明这个部署没有把备份目录
// 挂进来（比如用户自己写的 docker-compose 没加那一行），此时在容器里凭空
// 建一个 /app/backup 只会写进容器自己的临时层，容器一重建就没了，
// 却让启动日志显示「有 3 份备份」，那是更坏的误导。
func writeSnapshot() string {
	root := BackupDir()
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return ""
	}

	dataDir := filepath.Dir(resolvePath())
	if snapshotSignature(dataDir) == snapshotSignature(newestSnapshot(root)) {
		// 内容一模一样，没必要再占一份。
		return ""
	}

	dst := filepath.Join(root, time.Now().Format("20060102-150405"))
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return ""
	}

	copied := 0
	for _, f := range restoreFiles {
		from := filepath.Join(dataDir, f)
		if !fileExists(from) {
			continue
		}
		if err := copyFile(from, filepath.Join(dst, f), snapshotFileMode(f)); err == nil {
			copied++
		}
	}
	if copied == 0 {
		// 一个都没搬成（多半是权限问题），别留一个空目录冒充备份。
		_ = os.RemoveAll(dst)
		return ""
	}
	pruneSnapshots(root)
	return dst
}

// snapshotSignature 算出「这 4 个文件合起来长什么样」的指纹，用来判断
// 当前状态和某份备份是否等价。读不到的文件按空处理，缺文件和空文件在
// 这个用途上等价，都不该被当成「有变化」。
func snapshotSignature(dir string) string {
	if dir == "" {
		return ""
	}
	var buf []byte
	for _, f := range restoreFiles {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			b = nil
		}
		buf = append(buf, f...)
		buf = append(buf, 0)
		buf = append(buf, b...)
		buf = append(buf, 0)
	}
	return string(buf)
}

// newestSnapshot 返回备份根目录里最新的那一份（按目录名倒序）；没有就返回空。
// 只认带 config.json 的目录，建到一半失败的目录不算备份。
func newestSnapshot(root string) string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() || !snapshotPattern.MatchString(e.Name()) {
			continue
		}
		if fileExists(filepath.Join(root, e.Name(), "config.json")) {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	return filepath.Join(root, names[0])
}

// pruneSnapshots 只留最新 snapshotKeep 份。
//
// 只删「名字长得像时间戳」的目录，别的东西一律不碰，用户可能自己往这个
// 目录里放过别的东西（比如手动导出的 json），不能连带清掉。
func pruneSnapshots(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() && snapshotPattern.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	if len(names) <= snapshotKeep {
		return
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	for _, n := range names[snapshotKeep:] {
		_ = os.RemoveAll(filepath.Join(root, n))
	}
}

// BackupStatus 是启动时打诊断日志用的快照。
//
// 为什么非要打这一行：这次事故里最耗时间的一步是「到底有没有备份」，
// 备份目录在宿主机上，用户在容器日志里看不到任何线索，只能一层层翻文件管理器。
// 现在开机就把「目录在不在、写不写得进去、里面几份、最新哪一份」写进日志，
// 下次一看就知道该修哪儿。
type BackupStatus struct {
	Dir      string // 备份目录路径
	Exists   bool   // 目录在不在
	Writable bool   // 容器里的程序能不能往里写
	Count    int    // 有几份可用备份（必须带 config.json）
	Newest   string // 最新一份的目录名（20261117-190500）
}

// InspectBackupDir 探一次备份目录现状。只读，不改任何东西。
func InspectBackupDir() BackupStatus {
	root := BackupDir()
	st := BackupStatus{Dir: root}

	fi, err := os.Stat(root)
	if err != nil || !fi.IsDir() {
		return st
	}
	st.Exists = true

	if entries, err := os.ReadDir(root); err == nil {
		for _, e := range entries {
			if !e.IsDir() || !snapshotPattern.MatchString(e.Name()) {
				continue
			}
			if !fileExists(filepath.Join(root, e.Name(), "config.json")) {
				continue
			}
			st.Count++
			if e.Name() > st.Newest {
				st.Newest = e.Name()
			}
		}
	}

	// 真的写一下才知道能不能写：目录权限、只读挂载、ACL 这三种情况光看
	// Stat 都看不出来，而「以为能写、其实写不进去」正是这次踩的坑。
	if f, err := os.CreateTemp(root, ".probe-*"); err == nil {
		name := f.Name()
		_ = f.Close()
		_ = os.Remove(name)
		st.Writable = true
	}
	return st
}
