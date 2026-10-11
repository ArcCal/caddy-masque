//go:build (arm64 || amd64 || loong64 || ppc64 || ppc64le || mips64 || mips64le || riscv64 || s390x) && linux

package socket

func (h *cmsghdr) set(l, lvl, typ int) {
	h.Len = uint64(l)
	h.Level = int32(lvl)
	h.Type = int32(typ)
}
