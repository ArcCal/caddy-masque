//go:build !linux

package ipv6

import (
	"golang.org/x/net/bpf"
	"golang.org/x/net/internal/socket"
)

func (so *sockOpt) setAttachFilter(c *socket.Conn, f []bpf.RawInstruction) error {
	return errNotImplemented
}
