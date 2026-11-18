package web

// 本机 IPv6 的只读检测接口（IPv6 阶段①）：读 /proc/net/if_inet6，把「这台机器有没有
// 能用的公网 v6」显示出来。不写配置、不写解析、不碰 AdGuard、不碰测速结果，调一百次
// 程序的任何状态都不会变。不塞进 /api/status 是因为它按需看一眼、不是 3 秒一刷的实时
// 指标，塞进去会让人以为它跟测速结果一样会自己变。需要登录：不写状态，但地址信息属于
// 本机细节，不该对匿名敞开。

import (
	"net/http"

	"github.com/303528084/cf-ddns-sidecar/ipv6"
)

// handleIPv6 返回本机 IPv6 检测报告。读不到 /proc 时（某些非 Linux 环境）返回 503 和
// 一句人话，而不是空列表，让用户分得清「没有 v6」和「这个环境根本读不到网卡」。
func (s *Server) handleIPv6(w http.ResponseWriter, r *http.Request) {
	rep, err := ipv6.ReadLocal()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":    false,
			"error": "读不到本机网卡信息（" + friendlyErr(err) + "）；这个检测要在 NAS 的 Linux 环境里才能跑。",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"report": rep,
	})
}
