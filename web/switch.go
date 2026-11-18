package web

// 「点一下开关就立刻生效」用的单项保存接口。
//
// 为什么不给 /api/config 加一个字段：那个接口是全量保存，前端要一次提交十几个
// 字段；而开关是点一下就存，若走全量接口，会把界面上别的改到一半、还没点保存的
// 输入框一起写进去。用户要的正是「只存这一个、别的别碰」，所以单独开一条路，
// 复用同一个 config.json 但只改请求里点名的那一个键。
//
// 两类开关都收：
//   - 高级设置的引擎开关：key 是 Schema 里的参数名，必须确实是 KindBool；
//   - DDNS 的两个：ddns_enabled / ddns_proxied；
//   - GitHub hosts 源的 hosts_enabled（见 web/hosts.go）。
//
// 其他任何 key 一律 400，不猜、不猜着存——否则一个拼错的名字会在 config.json
// 里留个垃圾键，而 NormalizeOverrides 下次保存时又会把它悄悄丢掉，前后不一致。

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/303528084/cf-ddns-sidecar/engine"
)

func (s *Server) handleSwitch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "只支持 POST"})
		return
	}
	var body struct {
		Key   string `json:"key"`
		Value bool   `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求格式错误"})
		return
	}
	key := strings.TrimSpace(body.Key)

	s.mu.Lock()
	cfg := s.cfg.Clone()
	s.mu.Unlock()

	switch {
	case key == "ddns_enabled":
		cfg.DDNS.Enabled = body.Value
	case key == "ddns_proxied":
		cfg.DDNS.Proxied = body.Value
	case key == "hosts_enabled":
		cfg.HostsEnabled = body.Value
	default:
		// 引擎开关：必须存在于参数表里、且确实是布尔开关。
		spec, ok := engine.Lookup(key)
		if !ok || spec.Kind != engine.KindBool {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "未知的开关"})
			return
		}
		overrides := make(map[string]any, len(cfg.Speed.EngineOverrides)+1)
		for k, v := range cfg.Speed.EngineOverrides {
			overrides[k] = v
		}
		overrides[key] = body.Value
		// 复用和全量保存一样的规整：和默认值相同的项会被去掉，
		// 所以点回默认不会在 config.json 里留下一个空壳键。
		cfg.Speed.EngineOverrides = engine.NormalizeOverrides(overrides)
	}

	// 先落盘再改内存：写失败时界面显示的还是旧值，不会"以为存上了"。
	if err := cfg.Save(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "保存失败: " + friendlyErr(err),
		})
		return
	}
	s.mu.Lock()
	s.cfg = &cfg
	s.mu.Unlock()

	// 打开 hosts 源时**当场**拉一次清单并写进 AdGuard，不等下一轮测速。
	//
	// 定时同步挂在测速那一轮（默认 60 分钟），用户点开开关后如果什么都不发生，
	// 就要盯着一个「开着但没效果」的开关干等——反过来也是同一个毛病：关掉要
	// 当刻收回，打开也要当刻写进去。
	if key == "hosts_enabled" && body.Value {
		note := s.enableHostsNow(cfg)
		s.appendLog(note)
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "key": key, "value": body.Value, "message": note,
		})
		return
	}

	// 关掉 hosts 源时立即把它写过的记录收回来，不等到下一轮测速。
	//
	// 为什么要专门加这一步：清理由 `mergeHostsWant` 顺手完成（账本里
	// 「不再归它管」的域名给空集合），而那条路只在测速结束、写 AdGuard 时
	// 走。用户关掉开关后如果看到几十条记录还在，合理的判断就是「开关没生效」，
	// 而日志里要等到下一次测速才会给出解释——中间这段时间的沉默本身就是 bug。
	if key == "hosts_enabled" && !body.Value {
		if len(cfg.HostsEntries) > 0 {
			s.appendLog("hosts 源已关闭：把 AdGuard 上由它写的 " +
				itoa(len(cfg.HostsEntries)) + " 条记录收回来")
		}
		note := s.syncRewrites(cfg)
		s.appendLog(note)
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "key": key, "value": body.Value, "message": note,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "key": key, "value": body.Value})
}
