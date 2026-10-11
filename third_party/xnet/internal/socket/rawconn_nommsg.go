//go:build !linux

package socket

func (c *Conn) recvMsgs(ms []Message, flags int) (int, error) {
	return 0, errNotImplemented
}

func (c *Conn) sendMsgs(ms []Message, flags int) (int, error) {
	return 0, errNotImplemented
}
