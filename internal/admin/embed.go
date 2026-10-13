package admin

import (
	_ "embed"
	"net/http"
)

//go:embed dashboard.html
var dashboardHTML string

// noFDBoot marks a document whose engine has no externally supplied TUN fd. The
// Connected Devices view is fed by TUN per-source-IP accounting (devices.go),
// which only exists when the TUN came from outside the core — Android
// VpnService, or the Shizuku hotspot core. In non-fd mode (the app's
// SOCKS5-only mode, a desktop core creating its own TUN) the list can never hold
// anything, so the sidebar drops the entry rather than offering a permanently
// empty view. The flag is read by the inline script that binds the sidebar items.
const noFDBoot = `<script>window.SP_FD_MODE=false;</script>`

// dashboardHTMLNoFD / zhDashboardHTMLNoFD are the non-fd variants of the two
// documents above. Built in lang.go's init, once the zh variant exists.
var (
	dashboardHTMLNoFD   string
	zhDashboardHTMLNoFD string
)

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	zh := s.uiLang(r) == "zh"
	doc := dashboardHTML
	if zh {
		doc = zhDashboardHTML
	}
	if !s.fdMode {
		doc = dashboardHTMLNoFD
		if zh {
			doc = zhDashboardHTMLNoFD
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Language variant + zh dict are chosen server-side per request.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(doc))
}
