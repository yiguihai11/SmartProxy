//go:build !linux

package tun

// installSelfExclude is a no-op on non-Linux platforms: there is no ip rule / nftables mechanism,
// and auto_route on Windows/Darwin is handled by sing-tun in its own platform-specific way.
func installSelfExclude(mark int, excludePorts []int) (func(), error) {
	return func() {}, nil
}
