//go:build amd64 && solaris

package socket

import "unsafe"

func (v *iovec) set(b []byte) {
	l := len(b)
	if l == 0 {
		return
	}
	v.Base = (*int8)(unsafe.Pointer(&b[0]))
	v.Len = uint64(l)
}
