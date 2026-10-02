//go:build with_lwip && cgo

package tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	singtun "github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"smartproxy/internal/safego"
	"smartproxy/internal/tun/lwip"
)

// LWIPStack implements singtun.Stack backed by the lwIP userspace network stack.
type LWIPStack struct {
	ctx        context.Context
	tun        singtun.Tun
	tunOptions singtun.Options
	handler    singtun.Handler
	logger     logger.Logger
	engine     *lwip.Engine
	closed     atomic.Bool
	doneChan   chan struct{}
	wg         sync.WaitGroup
}

// NewLWIPStack creates a new lwIP stack instance with the given stack options.
func NewLWIPStack(options singtun.StackOptions) (singtun.Stack, error) {
	if options.Tun == nil {
		return nil, errors.New("missing tun device for lwip stack")
	}

	s := &LWIPStack{
		ctx:        options.Context,
		tun:        options.Tun,
		tunOptions: options.TunOptions,
		handler:    options.Handler,
		logger:     options.Logger,
		doneChan:   make(chan struct{}),
	}
	return s, nil
}

// Start initializes the lwIP engine and starts the packet reader loop.
func (s *LWIPStack) Start() error {
	var ip4, mask4, gw4 net.IP

	if len(s.tunOptions.Inet4Address) > 0 {
		prefix := s.tunOptions.Inet4Address[0]
		ip4 = prefix.Addr().AsSlice()
		mask4 = net.IP(net.CIDRMask(prefix.Bits(), 32))
		gw4 = make([]byte, 4)
		copy(gw4, ip4)
		gw4[3] = 1
	} else {
		ip4 = net.IPv4(10, 0, 0, 2)
		mask4 = net.IPv4(255, 255, 255, 0)
		gw4 = net.IPv4(10, 0, 0, 1)
	}

	cfg := lwip.Config{
		IPv4:    ip4,
		Mask:    mask4,
		Gateway: gw4,
		MTU:     uint16(s.tunOptions.MTU),
		OutputFn: func(packet []byte) {
			if s.closed.Load() {
				return
			}
			if singtun.PacketOffset > 0 {
				out := make([]byte, singtun.PacketOffset+len(packet))
				singtun.PacketFillHeader(out, singtun.PacketIPVersion(packet))
				copy(out[singtun.PacketOffset:], packet)
				if _, err := s.tun.Write(out); err != nil {
					if !s.closed.Load() && s.logger != nil {
						s.logger.Trace(fmt.Errorf("lwip tun write: %w", err))
					}
				}
			} else {
				if _, err := s.tun.Write(packet); err != nil {
					if !s.closed.Load() && s.logger != nil {
						s.logger.Trace(fmt.Errorf("lwip tun write: %w", err))
					}
				}
			}
		},
		TCPHandler: func(conn net.Conn) {
			if s.closed.Load() || s.handler == nil {
				conn.Close()
				return
			}
			src := M.SocksaddrFromNet(conn.RemoteAddr())
			dst := M.SocksaddrFromNet(conn.LocalAddr())
			if s.handler != nil {
				verdict := s.handler.JudgeFlow(6, src.AddrPort(), dst.AddrPort(), nil)
				if verdict.Action == singtun.ActionDrop || verdict.Action == singtun.ActionReject {
					conn.Close()
					return
				}
			}
			s.handler.NewConnectionEx(s.ctx, conn, src, dst, nil)
		},
		UDPHandler: func(conn *lwip.PacketConn) {
			if s.closed.Load() || s.handler == nil {
				conn.Close()
				return
			}
			src := conn.Source()
			dst := conn.Destination()
			if s.handler != nil {
				verdict := s.handler.JudgeFlow(17, src.AddrPort(), dst.AddrPort(), nil)
				if verdict.Action == singtun.ActionDrop || verdict.Action == singtun.ActionReject {
					conn.Close()
					return
				}
			}
			s.handler.NewPacketConnectionEx(s.ctx, conn, src, dst, nil)
		},
	}

	eng, err := lwip.NewEngine(cfg)
	if err != nil {
		return fmt.Errorf("init lwip engine: %w", err)
	}
	s.engine = eng
	slog.Info("lwIP network stack engine initialized", "tun", s.tunOptions.Name, "mtu", s.tunOptions.MTU)

	s.wg.Add(1)
	safego.Go("tun.lwip.readLoop", func() {
		defer s.wg.Done()
		mtu := int(s.tunOptions.MTU)
		if mtu < 1500 {
			mtu = 1500
		}
		bufSize := mtu + 256 + singtun.PacketOffset
		if bufSize < 65536 {
			bufSize = 65536
		}
		buf := make([]byte, bufSize)
		for {
			n, err := s.tun.Read(buf)
			if err != nil {
				if s.closed.Load() || E.IsClosed(err) || errors.Is(err, os.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
					return
				}
				if s.logger != nil {
					s.logger.Error(fmt.Errorf("lwip tun read: %w", err))
				}
				return
			}
			if n <= singtun.PacketOffset {
				continue
			}
			pkt := buf[singtun.PacketOffset:n]
			if err := s.engine.Input(pkt); err != nil {
				if s.closed.Load() {
					return
				}
			}
		}
	})

	return nil
}

// ResetNetwork handles network state changes.
func (s *LWIPStack) ResetNetwork() {
}

// Close terminates the lwIP stack and waits for reader goroutine cleanup.
func (s *LWIPStack) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	slog.Info("lwIP network stack engine closing")
	close(s.doneChan)
	var errs []error
	if s.engine != nil {
		if err := s.engine.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	// Give the reader loop up to 500ms to exit (in case Tun.Read is blocked on an unclosed tun)
	waitDone := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
	case <-time.After(500 * time.Millisecond):
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}
