//go:build !android

package tun

import (
	"testing"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/assert"
	"smartproxy/internal/config"
)

func TestIsUIDBlocked_NonAndroid(t *testing.T) {
	h := NewHandler(&config.Config{TUN: config.TUNConfig{BlockedUIDs: []int32{10123}}}, nil, nil, nil, nil)
	src := M.ParseSocksaddr("192.168.1.5:43210")
	dst := M.ParseSocksaddr("8.8.8.8:443")

	h.SetUIDResolver(func(int32, string, int32, string, int32) int32 { return 10123 })
	assert.False(t, h.isUIDBlocked(6, src, dst))
	assert.Equal(t, int32(-1), h.resolveUID(6, src, dst))
}
