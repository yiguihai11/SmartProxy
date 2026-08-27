//go:build android

package tun

import (
	"testing"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/assert"
	"smartproxy/internal/config"
)

func TestIsUIDBlocked(t *testing.T) {
	newHandler := func(uids []int32) *TUNHandler {
		return NewHandler(&config.Config{TUN: config.TUNConfig{BlockedUIDs: uids}}, nil, nil, nil, nil)
	}
	src := M.ParseSocksaddr("192.168.1.5:43210")
	dst := M.ParseSocksaddr("8.8.8.8:443")

	t.Run("no blocked uids configured -> always allowed", func(t *testing.T) {
		h := newHandler(nil)
		h.SetUIDResolver(func(int32, string, int32, string, int32) int32 { return 10123 })
		assert.False(t, h.isUIDBlocked(6, src, dst))
	})

	t.Run("no resolver -> allowed", func(t *testing.T) {
		h := newHandler([]int32{10123})
		assert.False(t, h.isUIDBlocked(6, src, dst))
	})

	t.Run("resolver returns matching uid -> blocked", func(t *testing.T) {
		h := newHandler([]int32{10123})
		h.SetUIDResolver(func(proto int32, _ string, _ int32, _ string, _ int32) int32 {
			assert.Equal(t, int32(6), proto)
			return 10123
		})
		assert.True(t, h.isUIDBlocked(6, src, dst))
	})

	t.Run("resolver returns other uid -> allowed", func(t *testing.T) {
		h := newHandler([]int32{10123})
		h.SetUIDResolver(func(int32, string, int32, string, int32) int32 { return 999 })
		assert.False(t, h.isUIDBlocked(6, src, dst))
	})

	t.Run("resolver returns -1 unknown -> allowed (fail-open)", func(t *testing.T) {
		h := newHandler([]int32{10123})
		h.SetUIDResolver(func(int32, string, int32, string, int32) int32 { return -1 })
		assert.False(t, h.isUIDBlocked(17, src, dst))
	})

	t.Run("nil resolver clears previous one", func(t *testing.T) {
		h := newHandler([]int32{10123})
		h.SetUIDResolver(func(int32, string, int32, string, int32) int32 { return 10123 })
		h.SetUIDResolver(nil)
		assert.False(t, h.isUIDBlocked(6, src, dst))
	})
}
