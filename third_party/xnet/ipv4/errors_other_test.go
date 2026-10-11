//go:build !(aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris)

package ipv4_test

// isENOBUFS reports whether err is unix.ENOBUFS.
// (Always false on non-Unix platforms.)
func isENOBUFS(err error) bool {
	return false
}
