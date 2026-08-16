//go:build windows

package admin

import (
	"syscall"
	"time"
	"unsafe"
)

var (
	modkernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetProcessTimes   = modkernel32.NewProc("GetProcessTimes")
	procGetCurrentProcess = modkernel32.NewProc("GetCurrentProcess")
)

// getProcessCPUTime returns the cumulative CPU time (user + system) consumed by the current process on Windows.
func getProcessCPUTime() (time.Duration, error) {
	handle, _, _ := procGetCurrentProcess.Call()
	var creationTime, exitTime, kernelTime, userTime syscall.Filetime
	r, _, err := procGetProcessTimes.Call(
		handle,
		uintptr(unsafe.Pointer(&creationTime)),
		uintptr(unsafe.Pointer(&exitTime)),
		uintptr(unsafe.Pointer(&kernelTime)),
		uintptr(unsafe.Pointer(&userTime)),
	)
	if r == 0 {
		return 0, err
	}
	k := int64(kernelTime.HighDateTime)<<32 | int64(kernelTime.LowDateTime)
	u := int64(userTime.HighDateTime)<<32 | int64(userTime.LowDateTime)
	// Windows Filetime is in 100-nanosecond intervals
	return time.Duration(k+u) * 100 * time.Nanosecond, nil
}
