//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || windows || zos

package ipv4_test

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/net/ipv4"
)

func protocolNotSupported(err error) bool {
	switch err := err.(type) {
	case syscall.Errno:
		switch err {
		case syscall.EPROTONOSUPPORT, syscall.ENOPROTOOPT:
			return true
		}
	case *os.SyscallError:
		switch err := err.Err.(type) {
		case syscall.Errno:
			switch err {
			case syscall.EPROTONOSUPPORT, syscall.ENOPROTOOPT:
				return true
			}
		}
	}
	return errors.Is(err, ipv4.ErrNotImplemented)
}
