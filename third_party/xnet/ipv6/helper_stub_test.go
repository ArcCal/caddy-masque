//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows && !zos

package ipv6_test

import (
	"fmt"
	"runtime"
)

func supportsIPv6MulticastDeliveryOnLoopback() (string, bool) {
	return fmt.Sprintf("not supported on %s/%s", runtime.GOOS, runtime.GOARCH), false
}

func protocolNotSupported(err error) bool {
	return false
}
