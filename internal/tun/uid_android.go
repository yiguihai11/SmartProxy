//go:build android

package tun

import (
	M "github.com/sagernet/sing/common/metadata"
)

// UIDResolverFunc asks the Android side which app UID owns a connection (per-app
// "禁止联网"). proto: 6=TCP, 17=UDP. Returns the UID, or -1 if unknown/unresolvable.
// mobile 包把 gomobile 的 UIDResolver 接口适配成这个函数闭包注入进来(见 mobile/bridge.go),
// 避免 internal 包反向依赖 mobile(gomobile 绑定包)。
type UIDResolverFunc func(proto int32, localIP string, localPort int32, remoteIP string, remotePort int32) int32

// SetUIDResolver 注入 UID 反查回调(mobile 包在 StartRouter 后调用一次)。nil 表示
// 未注册,isUIDBlocked 恒返回 false(功能关闭),不影响其它路径。
func (h *TUNHandler) SetUIDResolver(f UIDResolverFunc) {
	if f == nil {
		h.uidResolverFn.Store(nil)
		return
	}
	h.uidResolverFn.Store(&f)
}

// resolveUID 反查连接所属 app UID;-1 = 未知 / 不可解析。拦截与连接监控共用:
// 监控需要它在名单为空时也解析(联网状态页),所以独立成原语。
func (h *TUNHandler) resolveUID(proto int32, source, destination M.Socksaddr) int32 {
	fn := h.uidResolverFn.Load()
	if fn == nil {
		return -1
	}
	return (*fn)(proto, source.Addr.String(), int32(source.Port), destination.Addr.String(), int32(destination.Port))
}

// isUIDBlocked 判断连接是否属于被「禁止联网」的应用:先查 config.TUN.BlockedUIDs(空 = 关),
// 再经 Android 回调反查连接所属 UID。解析失败 / 无回调返回 false(放行),避免把系统或
// 引擎自身流量误拦;只有明确命中已配置 UID 才拦截。
func (h *TUNHandler) isUIDBlocked(proto int32, source, destination M.Socksaddr) bool {
	cfg := h.config.Load()
	if len(cfg.TUN.BlockedUIDs) == 0 {
		return false
	}
	uid := h.resolveUID(proto, source, destination)
	if uid <= 0 {
		return false // -1 未知 / 0 系统进程,不放行黑名单拦截语义下误伤
	}
	for _, b := range cfg.TUN.BlockedUIDs {
		if b == uid {
			return true
		}
	}
	return false
}
