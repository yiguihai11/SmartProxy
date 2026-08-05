//go:build !linux

package tun

import "net/netip"

// installSelectiveRoutes is a no-op on non-Linux platforms:
// the rules only exist on Linux; on other platforms (Windows/Darwin/mobile fd mode) routing is managed
// by the OS or external mechanisms.
func (h *TUNHandler) installSelectiveRoutes(iface string, inet4, inet6 []netip.Prefix) {
}
