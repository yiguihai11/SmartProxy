//go:build !linux

package fwmark

import "syscall"

// DefaultMark is meaningless on non-Linux platforms (no SO_MARK / no mark-based routing rules).
const DefaultMark = 0

func Configure(m int) {}
func Enable()         {}
func Disable()        {}
func Mark() int       { return 0 }
func Enabled() bool   { return false }

// Control is a no-op on non-Linux platforms, ensuring cross-platform compilation and operation.
func Control(network, address string, conn syscall.RawConn) error { return nil }
