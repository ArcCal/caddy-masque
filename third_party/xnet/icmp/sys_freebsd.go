package icmp

import "syscall"

func init() {
	freebsdVersion, _ = syscall.SysctlUint32("kern.osreldate")
}
