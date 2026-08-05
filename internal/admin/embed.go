package admin

import (
	_ "embed"
	"net/http"
)

//go:embed dashboard.html
var dashboardHTML string

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(dashboardHTML))
}
