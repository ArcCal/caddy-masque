//go:build go1.27 && !go1.27

// MASQUE requires the patched legacy implementation on every toolchain.
// Retain this upstream wrapper for review, but never select it for a build.

package http2

import "net/http"

func (t *Transport) TestTransport() *http.Transport {
	return t.init()
}

func (s *Server) TestSetNewConnFunc(f func(*ServerConn)) {
	panic("ServerConns are only available with http2legacy")
}
