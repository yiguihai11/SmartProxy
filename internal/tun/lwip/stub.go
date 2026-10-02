//go:build !with_lwip || !cgo

package lwip

import (
	"errors"
	"net"
)

// ErrNotImplemented is returned when the lwIP backend was not included in this build.
var ErrNotImplemented = errors.New("lwip backend is not included in this build, rebuild with -tags with_lwip")

// PacketConn stub when built without with_lwip tag.
type PacketConn struct{}

// Conn stub when built without with_lwip tag.
type Conn struct{}

func (c *Conn) SetLinger(sec int) error {
	return nil
}

func (c *Conn) SetNoDelay(noDelay bool) error {
	return nil
}

// Config configures the lwIP Engine.
type Config struct {
	IPv4       net.IP
	Mask       net.IP
	Gateway    net.IP
	MTU        uint16
	OutputFn   func(packet []byte)
	TCPHandler func(conn net.Conn)
	UDPHandler func(conn *PacketConn)
}

// Engine stub when built without with_lwip tag.
type Engine struct{}

// NewEngine returns ErrNotImplemented when with_lwip tag is absent.
func NewEngine(cfg Config) (*Engine, error) {
	return nil, ErrNotImplemented
}

// Input returns ErrNotImplemented when with_lwip tag is absent.
func (e *Engine) Input(packet []byte) error {
	return ErrNotImplemented
}

// Close is a no-op when with_lwip tag is absent.
func (e *Engine) Close() error {
	return nil
}
