package web

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/303528084/cf-ddns-sidecar/config"
)

// 历史测速：每轮测速结束留一条记录，最多二十条。
//
// 为什么单独一个文件、不塞进 config.json：那个文件每轮都写，写完还会生成一份
// 去重备份（内容没变就不备）。历史每轮都变，塞进去会让那条去重永远失效，
// 三份备份几分钟就被刷光——真出事时反而找不到「几小时前那份」。
// 同样地，history.json 不进恢复清单，也不进导出包：它是诊断数据，不是配置。
const historyKeep = 20

// historyFile 和 config.json 并排放在数据目录里。
const historyFile = "history.json"

// 三种触发来源。界面按这个上色，所以用固定三个词，别在这里拼字符串。
const (
	triggerManual = "手动"
	triggerTimer  = "定时"
	triggerBoot   = "开机"
)

// roundRecord 是一轮测速的结果摘要，外加这一轮的完整节点表。
//
// 字段刻意和 NodeStat 复用：界面画明细用的是同一套数据结构，
// 多造一个「历史节点」类型只会让两张表慢慢长歪。
type roundRecord struct {
	At      string  `json:"at"`      // 结束时刻，和 config.LastTime 同一个值
	Trigger string  `json:"trigger"` // 手动 / 定时 / 开机
	OK      bool    `json:"ok"`
	Err     string  `json:"err,omitempty"`
	DurSec  int     `json:"dur"` // 这一轮花了几秒
	Best    string  `json:"best,omitempty"`
	Speed   float64 `json:"speed,omitempty"`
	Delay   float64 `json:"delay,omitempty"`
	// Written 只算 DDNS 真正推上去的记录数（A / AAAA）。AdGuard 重写不算——
	// 两边的条数差一个数量级，加在一起没人看得懂那是什么。
	Written int               `json:"written"`
	Nodes   []config.NodeStat `json:"nodes,omitempty"`
	V6Nodes []config.NodeStat `json:"v6_nodes,omitempty"`
}

func (s *Server) historyPath() string {
	if s.configPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(s.configPath), historyFile)
}

// loadHistory 启动时把上次留下的记录读回来。
//
// 读不出来就当没有：历史坏了不能让程序起不来，也不能让测速停下。
func (s *Server) loadHistory() {
	p := s.historyPath()
	if p == "" {
		return
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var doc struct {
		Rounds []roundRecord `json:"rounds"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return
	}
	if len(doc.Rounds) > historyKeep {
		doc.Rounds = doc.Rounds[len(doc.Rounds)-historyKeep:]
	}
	s.mu.Lock()
	s.history = doc.Rounds
	s.mu.Unlock()
}

// recordRound 补全「什么时候、花了多久」再存。出错的分支只填了原因和触发来源，
// 那两个值在调用点上拿不到（或者拿到了也要重复一遍）。
func (s *Server) recordRound(startedAt time.Time, rec roundRecord) {
	if rec.At == "" {
		rec.At = time.Now().Format("2006-01-02 15:04:05")
	}
	if rec.DurSec == 0 {
		rec.DurSec = int(time.Since(startedAt).Seconds())
	}
	s.appendHistory(rec)
}

// appendHistory 追加一条、把最旧的挤出去，然后落盘。
//
// 落盘失败只写日志、不往上抛：这一轮测速本身是成功的，写不了历史不该让它变失败。
func (s *Server) appendHistory(rec roundRecord) {
	s.mu.Lock()
	s.history = append(s.history, rec)
	if len(s.history) > historyKeep {
		s.history = s.history[len(s.history)-historyKeep:]
	}
	snapshot := append([]roundRecord(nil), s.history...)
	s.mu.Unlock()

	p := s.historyPath()
	if p == "" {
		return
	}
	body, err := json.MarshalIndent(struct {
		Rounds []roundRecord `json:"rounds"`
	}{Rounds: snapshot}, "", "  ")
	if err != nil {
		return
	}
	// 和 config.Save 一样先写临时文件再改名：写一半断电不会留下半个 JSON，
	// 那会让下次启动读不出任何记录。
	dir := filepath.Dir(p)
	tmp, err := os.CreateTemp(dir, ".cfddns-history-*")
	if err != nil {
		s.appendLog("历史测速保存失败（这次的记录重启后会丢）: " + friendlyErr(err))
		return
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		s.appendLog("历史测速保存失败（这次的记录重启后会丢）: " + friendlyErr(err))
		return
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		s.appendLog("历史测速保存失败（这次的记录重启后会丢）: " + friendlyErr(err))
		return
	}
	if err := tmp.Close(); err != nil {
		s.appendLog("历史测速保存失败（这次的记录重启后会丢）: " + friendlyErr(err))
		return
	}
	if err := os.Chmod(name, 0o600); err != nil {
		s.appendLog("历史测速保存失败（这次的记录重启后会丢）: " + friendlyErr(err))
		return
	}
	if err := os.Rename(name, p); err != nil {
		s.appendLog("历史测速保存失败（这次的记录重启后会丢）: " + friendlyErr(err))
	}
}

// handleHistory 返回历史列表，最新的在前。
//
// 节点明细跟着列表一起给：二十轮、每轮十几条，总共几十 KB，比「点一行再请求
// 一次」省一次往返，也省掉「点开发现那一条没了」的界面状态。
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	rounds := make([]roundRecord, 0, len(s.history))
	for i := len(s.history) - 1; i >= 0; i-- {
		rounds = append(rounds, s.history[i])
	}
	s.mu.Unlock()

	writeJSON(w, 200, map[string]any{"ok": true, "keep": historyKeep, "rounds": rounds})
}
