package admin

import (
	_ "embed"
	"net/http"
)

//go:embed static/chart.umd.min.js
var chartJS []byte

func (s *Server) handleChartJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Write(chartJS)
}

//go:embed static/codemirror.min.js
var cmJS []byte

//go:embed static/codemirror.min.css
var cmCSS []byte

//go:embed static/json.min.js
var jsonJS []byte

//go:embed static/dracula.min.css
var draculaCSS []byte

func (s *Server) handleCMJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Write(cmJS)
}

func (s *Server) handleCMCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Write(cmCSS)
}

func (s *Server) handleJSONJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Write(jsonJS)
}

func (s *Server) handleDraculaCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Write(draculaCSS)
}

//go:embed static/simple.js
var simpleJS []byte

func (s *Server) handleSimpleJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Write(simpleJS)
}

//go:embed static/jsqr.min.js
var jsqrJS []byte

func (s *Server) handleJsqrJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Write(jsqrJS)
}
