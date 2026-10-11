package socket

func (h *cmsghdr) set(l, lvl, typ int) {
	h.Len = int32(l)
	h.Level = int32(lvl)
	h.Type = int32(typ)
}
