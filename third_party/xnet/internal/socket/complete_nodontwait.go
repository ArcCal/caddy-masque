//go:build aix || windows || zos

package socket

import (
	"syscall"
)

// ioComplete checks the flags and result of a syscall, to be used as return
// value in a syscall.RawConn.Read or Write callback.
func ioComplete(flags int, operr error) bool {
	if operr == syscall.EAGAIN || operr == syscall.EWOULDBLOCK {
		// No data available, block for I/O and try again.
		return false
	}
	return true
}
