package websocket

import (
	"context"
	"crypto/tls"
	"net"
)

func dialWithDialer(ctx context.Context, dialer *net.Dialer, config *Config) (conn net.Conn, err error) {
	switch config.Location.Scheme {
	case "ws":
		conn, err = dialer.DialContext(ctx, "tcp", parseAuthority(config.Location))

	case "wss":
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config:    config.TlsConfig,
		}

		conn, err = tlsDialer.DialContext(ctx, "tcp", parseAuthority(config.Location))
	default:
		err = ErrBadScheme
	}
	return
}
