package admin

import (
	_ "embed"
	"net/http"
)

//go:embed panel.html
var panelHTML string

// handlePanel 服务 M5 管理面板(M3 §4.4):聚焦的移动端 Web SPA,替代桌面版
// dashboard.html 作为手机用户访问 / 时的落点。见 panel.html。
func (s *Server) handlePanel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(panelHTML))
}
