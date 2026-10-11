//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package ipv4_test

import (
	"errors"

	"golang.org/x/sys/unix"
)

// isENOBUFS reports whether err is unix.ENOBUFS.
// (Always false on non-Unix platforms.)
func isENOBUFS(err error) bool {
	return errors.Is(err, unix.ENOBUFS)
}
