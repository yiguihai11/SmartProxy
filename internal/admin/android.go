package admin

import (
	"encoding/json"
	"io"
	"net/http"
)

// androidBridge 是 Android 运行时桥的结构等价接口(M5,§4.4)。
// mobile.AndroidBridge 方法集与本接口相同,由 mobile.StartRouter 在引擎启动后
// 经 SetAndroidBridge 赋值(接口到接口,编译期检查)——admin 不能 import mobile
// 会成环(mobile→engine→admin),所以这里定义本地结构。
//
// 契约(全部由 Kotlin AndroidBridgeImpl 实现,string/bool 经 gobind 编组):
// §5 应用内化后,应用列表/图标已移入 App 内,不再经此桥。
//   - GetPrefs() 返回偏好 JSON 串(见 PrefsService.getJson)
//   - SetPrefs(json) 空串 = 成功,非空 = 错误描述
//   - IsRunning() 引擎/VpnService 是否在跑
//   - Vpn(action) "start"/"stop"/"restart",空串 = 成功,非空 = 错误描述
type androidBridge interface {
	GetPrefs() string
	SetPrefs(json string) string
	IsRunning() bool
	Vpn(action string) string
}

func (s *Server) SetAndroidBridge(b androidBridge) {
	s.androidBridge = b
}

// requireBridge 取桥接实例,未注册时写 503 并返回 nil(调用方提前 return)。
func (s *Server) requireBridge(w http.ResponseWriter) androidBridge {
	b := s.androidBridge
	if b == nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"桥接未注册"}`))
	}
	return b
}

// GET /api/prefs — 当前偏好 JSON(面板渲染用)。
func (s *Server) handleAPIPrefs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	b := s.requireBridge(w)
	if b == nil {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write([]byte(b.GetPrefs()))
}

// POST /api/prefs — 保存偏好。body 原样交给 Kotlin(部分字段合并,见 PrefsService.set);
// 返回非空 = 校验/存储错误 → 400 {error};空串 = 成功 → {ok:true}。
func (s *Server) handleAPIPrefsSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	b := s.requireBridge(w)
	if b == nil {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !json.Valid(body) {
		http.Error(w, `{"error":"不是合法 JSON"}`, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if msg := b.SetPrefs(string(body)); msg != "" {
		writeJSONErr(w, http.StatusBadRequest, msg)
		return
	}
	w.Write([]byte(`{"ok":true}`))
}

// GET /api/vpn — {"running":bool}。
func (s *Server) handleAPIVpn(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	b := s.requireBridge(w)
	if b == nil {
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write([]byte(`{"running":` + boolStr(b.IsRunning()) + `}`))
}

// POST /api/vpn — body {"action":"start"|"stop"|"restart"},启停只在安卓端(§4.4),
// 面板只会在"保存后重启"时调用。
func (s *Server) handleAPIVpnSet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	b := s.requireBridge(w)
	if b == nil {
		return
	}
	var req struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "body 解析失败: "+err.Error())
		return
	}
	switch req.Action {
	case "start", "stop", "restart":
	default:
		writeJSONErr(w, http.StatusBadRequest, `action 必须是 start/stop/restart`)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if msg := b.Vpn(req.Action); msg != "" {
		writeJSONErr(w, http.StatusBadRequest, msg)
		return
	}
	w.Write([]byte(`{"ok":true}`))
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func writeJSONErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	w.Write([]byte(`{"error":` + jsonString(msg) + `}`))
}

func jsonString(s string) string {
	data, _ := json.Marshal(s)
	return string(data)
}
