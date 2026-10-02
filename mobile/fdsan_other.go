//go:build !android

package mobile

// SetFdsanLevel is a no-op on non-Android platforms.
func SetFdsanLevel(level int32) {}
