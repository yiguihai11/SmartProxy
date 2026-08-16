//go:build !windows

package admin

import (
	"syscall"
	"time"
)

// getProcessCPUTime returns the cumulative CPU time (user + system) consumed by the current process.
// Uses POSIX getrusage which works accurately across Linux, Android (Bionic), and macOS/Darwin.
func getProcessCPUTime() (time.Duration, error) {
	var rusage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &rusage); err != nil {
		return 0, err
	}
	user := time.Duration(rusage.Utime.Sec)*time.Second + time.Duration(rusage.Utime.Usec)*time.Microsecond
	sys := time.Duration(rusage.Stime.Sec)*time.Second + time.Duration(rusage.Stime.Usec)*time.Microsecond
	return user + sys, nil
}
