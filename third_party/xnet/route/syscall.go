//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package route

import _ "unsafe" // for linkname

//go:linkname sysctl syscall.sysctl
func sysctl(mib []int32, old *byte, oldlen *uintptr, new *byte, newlen uintptr) error
