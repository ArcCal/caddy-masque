package ipv4

import (
	"net"

	"golang.org/x/net/internal/socket"
)

// BUG(mikio): On Windows, the ControlMessage for ReadFrom and WriteTo
// methods of PacketConn is not implemented.

// A payloadHandler represents the IPv4 datagram payload handler.
type payloadHandler struct {
	net.PacketConn
	*socket.Conn
	rawOpt
}

func (c *payloadHandler) ok() bool { return c != nil && c.PacketConn != nil && c.Conn != nil }
