//go:build !android

package tun

import (
	M "github.com/sagernet/sing/common/metadata"
)

// UIDResolverFunc on non-Android platforms is a no-op function stub.
type UIDResolverFunc func(proto int32, localIP string, localPort int32, remoteIP string, remotePort int32) int32

// SetUIDResolver is a no-op on non-Android platforms.
func (h *TUNHandler) SetUIDResolver(f UIDResolverFunc) {}

// resolveUID always returns -1 (unknown) on non-Android platforms.
func (h *TUNHandler) resolveUID(proto int32, source, destination M.Socksaddr) int32 {
	return -1
}

// isUIDBlocked always returns false on non-Android platforms.
func (h *TUNHandler) isUIDBlocked(proto int32, source, destination M.Socksaddr) bool {
	return false
}
