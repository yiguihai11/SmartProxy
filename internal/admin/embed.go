package admin

import (
	_ "embed"
	"net/http"
)

//go:embed dashboard.html
var dashboardHTML string

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	doc := dashboardHTML
	if s.uiLang(r) == "zh" {
		doc = zhDashboardHTML
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Language variant + zh dict are chosen server-side per request.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(doc))
}
