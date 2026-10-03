package masque

import (
	"crypto/tls"
	"net"
	"testing"
)

// Wrappers like Caddy's: a value and a pointer type that embed net.Conn.
type valueWrapper struct{ net.Conn }

type pointerWrapper struct {
	net.Conn
	once bool
}

// Like the PROXY protocol's connection.
type rawWrapper struct {
	net.Conn
	raw net.Conn
}

func (w rawWrapper) Raw() net.Conn { return w.raw }

// A connection kept where it cannot be reached.
type hiddenWrapper struct {
	net.Conn
	c net.Conn
}

func TestTCPConnOfFindsTheConnectionUnderWrappers(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	tc := server.(*net.TCPConn)
	for name, c := range map[string]net.Conn{
		"TCP":                tc,
		"TLS":                tls.Server(tc, &tls.Config{}),
		"wrapped, then TLS":  tls.Server(&pointerWrapper{Conn: tc}, &tls.Config{}),
		"TLS, then wrapped":  valueWrapper{tls.Server(tc, &tls.Config{})},
		"PROXY protocol":     tls.Server(rawWrapper{raw: tc}, &tls.Config{}),
		"wrapped many times": valueWrapper{&pointerWrapper{Conn: valueWrapper{tc}}},
	} {
		if got, ok := tcpConnOf(c); !ok || got != tc {
			t.Errorf("%s: %v %v", name, got, ok)
		}
	}
	for name, c := range map[string]net.Conn{
		"hidden":   hiddenWrapper{c: tc},
		"nil":      valueWrapper{},
		"nil TLS":  tls.Server(valueWrapper{}, &tls.Config{}),
		"not TCP":  &net.UnixConn{},
		"too deep": deep(tc, 20),
	} {
		if got, ok := tcpConnOf(c); ok {
			t.Errorf("%s: found %v", name, got)
		}
	}
}

func deep(c net.Conn, n int) net.Conn {
	for range n {
		c = valueWrapper{c}
	}
	return c
}
