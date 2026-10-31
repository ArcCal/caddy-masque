package masque

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

// The module never serves classic CONNECT. Its refusal must not have a 2xx
// status, which would announce a tunnel (RFC 9110 Section 9.3.6), and over
// HTTP/1.x it must close the connection without reading another request
// from it (RFC 9112 as updated by RFC 9931 Section 8), even when the site
// answers with 200.
func TestCaddyRefusedClassicConnect(t *testing.T) {
	e := newCaddyEnv(t)
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	credentials := "Authorization: " + authorization(testPassword) + "\r\n"
	for _, tc := range []struct {
		name, head string
		status     int
	}{
		{"HTTP/1.1", "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n", http.StatusNotFound},
		{"HTTP/1.1 with credentials", "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n" + credentials, http.StatusNotFound},
		{"HTTP/1.0 keep-alive", "CONNECT example.com:443 HTTP/1.0\r\nConnection: keep-alive\r\n", http.StatusNotFound},
		{"HTTP/1.1 with connect-ip upgrade", fmt.Sprintf("CONNECT vpn.test:%d HTTP/1.1\r\nHost: vpn.test:%d\r\n"+
			"Connection: Upgrade\r\nUpgrade: connect-ip\r\n", e.port, e.port) + credentials, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := e.dialTCP(ctx, e.tlsConfig("http/1.1"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			// Data a client sent optimistically, as a request of its own.
			if _, err := fmt.Fprintf(conn, "%s\r\nGET / HTTP/1.1\r\nHost: vpn.test\r\n\r\n", tc.head); err != nil {
				t.Fatal(err)
			}
			br := bufio.NewReader(conn)
			resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.status || !resp.Close {
				t.Errorf("status %d, close %v; want %d and close", resp.StatusCode, resp.Close, tc.status)
			}
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				t.Fatal(err)
			}
			if rest, err := io.ReadAll(br); err != nil || len(rest) != 0 {
				t.Errorf("after the refusal: %q, %v; want the connection closed", rest, err)
			}
		})
	}

	h2 := &http2.Transport{TLSClientConfig: e.tlsConfig("h2"),
		DialTLSContext: func(ctx context.Context, _, _ string, cfg *tls.Config) (net.Conn, error) { return e.dialTCP(ctx, cfg) }}
	h3 := &http3.Transport{TLSClientConfig: e.tlsConfig("h3"),
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, fmt.Sprintf("127.0.0.1:%d", e.port), tlsCfg, cfg)
		}}
	defer h3.Close()
	for name, rt := range map[string]http.RoundTripper{"HTTP/2": h2, "HTTP/3": h3} {
		t.Run(name, func(t *testing.T) {
			body, done := io.Pipe()
			defer done.Close()
			req, _ := http.NewRequest(http.MethodConnect, e.url("/"), body)
			req.Header.Set("Authorization", authorization(testPassword))
			resp, err := rt.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound || string(b) != "cover page" {
				t.Errorf("status %d body %q, want %d with the site's body", resp.StatusCode, b, http.StatusNotFound)
			}
		})
	}
}
