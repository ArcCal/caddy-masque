//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !zos

package socket

type iovec struct{}

func (v *iovec) set(b []byte) {}
