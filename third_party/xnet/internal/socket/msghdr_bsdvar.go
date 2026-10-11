//go:build aix || darwin || dragonfly || freebsd || netbsd

package socket

func (h *msghdr) setIov(vs []iovec) {
	l := len(vs)
	if l == 0 {
		return
	}
	h.Iov = &vs[0]
	h.Iovlen = int32(l)
}
