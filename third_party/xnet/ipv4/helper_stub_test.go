//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows && !zos

package ipv4_test

func protocolNotSupported(err error) bool {
	return false
}
