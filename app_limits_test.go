package masque

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// New connections enforce reloaded header limits while old tunnels remain open.
func TestHTTP3HeaderLimitReload(t *testing.T) {
	for _, takeover := range []bool{false, true} {
		t.Run(fmt.Sprintf("takeover=%v", takeover), func(t *testing.T) {
			e := newCaddyEnv(t)
			e.server = map[string]any{"max_header_bytes": 32768}
			cfg := masqueConfig("alice")
			cfg["http3"] = takeover
			if err := e.load(cfg); err != nil {
				t.Fatal(err)
			}
			request := func() (int, error) {
				rt := &http3.Transport{TLSClientConfig: e.tlsConfig("h3"),
					Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
						return quic.DialAddr(ctx, fmt.Sprintf("127.0.0.1:%d", e.port), tlsCfg, cfg)
					},
				}
				defer rt.Close()
				req, _ := http.NewRequest(http.MethodGet, e.url("/"), nil)
				req.Header.Set("X-Audit-Large", strings.Repeat("a", 8192))
				resp, err := rt.RoundTrip(req)
				if err != nil {
					return 0, err
				}
				defer resp.Body.Close()
				_, _ = io.Copy(io.Discard, resp.Body)
				return resp.StatusCode, nil
			}
			if status, err := request(); err != nil || status != 200 {
				t.Fatalf("baseline=%d %v", status, err)
			}
			e.server["max_header_bytes"] = 1024
			if err := e.load(cfg); err != nil {
				t.Fatal(err)
			}
			status, err := request()
			t.Logf("after tightening max_header_bytes 32768 -> 1024, 8192-byte field: HTTP/3 status=%d error=%v", status, err)
			if err == nil && status == 200 {
				t.Error("new HTTP/3 connection accepted a header over the reloaded limit")
			}
		})
	}
}

// Ordinary connections retain the configured Caddy keep-alive limit.
func TestHTTP3IdleTimeoutConfig(t *testing.T) {
	for _, takeover := range []bool{false, true} {
		t.Run(fmt.Sprintf("takeover=%v", takeover), func(t *testing.T) {
			e := newCaddyEnv(t)
			e.server = map[string]any{"idle_timeout": "250ms"}
			cfg := masqueConfig("alice")
			cfg["http3"] = takeover
			if err := e.load(cfg); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			conn, err := quic.DialAddr(ctx, fmt.Sprintf("127.0.0.1:%d", e.port), http3.ConfigureTLSConfig(e.tlsConfig("h3")), &quic.Config{})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.CloseWithError(0, "")
			cc := (&http3.Transport{}).NewClientConn(conn)
			req, _ := http.NewRequest(http.MethodGet, e.url("/"), nil)
			resp, err := cc.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			select {
			case <-conn.Context().Done():
				t.Logf("idle ordinary HTTP/3 connection closed: %v", context.Cause(conn.Context()))
			case <-time.After(time.Second):
				t.Error("ordinary HTTP/3 connection remains open after four times configured idle_timeout")
			}
		})
	}
}

func TestFailedHTTP3BindReloadPreservesSession(t *testing.T) {
	e := newCaddyEnv(t)
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	live := e.dialH1(t, testPassword, anyTarget)
	defer live.close()
	addr, _ := opening(t, live)
	busy, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	var cfg map[string]any
	_ = json.Unmarshal(e.config(masqueConfig("bob")), &cfg)
	servers := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	servers["blocked"] = map[string]any{"listen": []string{busy.LocalAddr().String()}, "tls_connection_policies": []any{map[string]any{}}, "automatic_https": map[string]any{"disable": true}}
	b, _ := json.Marshal(cfg)
	if err := caddy.Load(b, true); err == nil {
		t.Fatal("expected busy UDP-port reload failure")
	} else {
		t.Logf("expected candidate failure: %v", err)
	}
	restored := e.dialH1(t, testPassword, anyTarget)
	defer restored.close()
	if restored.status != http.StatusSwitchingProtocols {
		t.Fatalf("old credentials after rollback: %d", restored.status)
	}
	e.dev.fromHost <- udp("1.1.1.1", addr.String(), 8)
	_, err = live.recv()
	if err != nil {
		t.Errorf("original live tunnel did not survive failed H3 candidate reload: %v", err)
	}
}
