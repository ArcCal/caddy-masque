//go:build (arm || mips || mipsle || 386 || ppc) && (darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package socket

import "unsafe"

func (v *iovec) set(b []byte) {
	l := len(b)
	if l == 0 {
		return
	}
	v.Base = (*byte)(unsafe.Pointer(&b[0]))
	v.Len = uint32(l)
}
