package masque

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

// Other extended CONNECT requests still receive the cover response when
// the upstream does not upgrade them. WebSockets have supported byte-stream
// semantics, but no HTTP Datagram semantics. Rejecting their Datagrams must
// not change the response when the client sends no HTTP Datagrams.
func TestHTTP3OtherProtocolsWithoutDatagramsPreserveCover(t *testing.T) {
	forwarded := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded <- r.Method
		_, _ = io.WriteString(w, "cover page")
	}))
	e := newCaddyEnv(t)
	t.Cleanup(func() {
		upstream.CloseClientConnections()
		upstream.Close()
	})
	proxyTestRoutes(e, upstream)
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	ctx, cc := datagramTestClient(t, e)
	for _, protocol := range []string{"unknown-protocol", "websocket"} {
		for _, host := range []string{"vpn.test", "plain.test"} {
			t.Run(protocol+"/"+host, func(t *testing.T) {
				str, err := cc.OpenRequestStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				_ = str.SetDeadline(time.Now().Add(5 * time.Second))
				u, _ := url.Parse(e.url("/normal"))
				if err := str.SendRequestHeader(&http.Request{Method: http.MethodConnect, Proto: protocol,
					Host: host, URL: u, Header: make(http.Header)}); err != nil {
					t.Fatal(err)
				}
				if err := str.Close(); err != nil {
					t.Fatal(err)
				}
				resp, err := str.ReadResponse()
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if err != nil || resp.StatusCode != http.StatusOK || string(body) != "cover page" || resp.Header.Get("Capsule-Protocol") != "" {
					t.Fatalf("cover response: status %d, body %q, Capsule-Protocol %q, error %v",
						resp.StatusCode, body, resp.Header.Get("Capsule-Protocol"), err)
				}
				select {
				case method := <-forwarded:
					wantMethod := http.MethodConnect
					if protocol == "websocket" {
						// Caddy's existing extended WebSocket handling rewrites
						// CONNECT to the HTTP/1.1 upgrade's GET upstream.
						wantMethod = http.MethodGet
					}
					if method != wantMethod {
						t.Fatalf("upstream method %q, want %s", method, wantMethod)
					}
				case <-ctx.Done():
					t.Fatal("unsupported extended CONNECT did not reach the cover website")
				}
			})
		}
	}
}

// Caddy's existing WebSocket mode carries frames in HTTP DATA, without
// HTTP Datagrams. Exercise an actual upstream upgrade and a binary frame
// in both directions, rather than only a website refusing the upgrade.
func TestHTTP3WebSocketDataFramesPreserved(t *testing.T) {
	for _, host := range []string{"vpn.test", "plain.test"} {
		t.Run(host, func(t *testing.T) {
			var mu sync.Mutex
			var active *websocket.Conn
			stopping := false
			handlerErr := make(chan error, 1)
			upstream := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
				mu.Lock()
				active = ws
				stop := stopping
				mu.Unlock()
				defer ws.Close()
				if stop {
					return
				}
				var message []byte
				err := websocket.Message.Receive(ws, &message)
				if err == nil {
					err = websocket.Message.Send(ws, message)
				}
				handlerErr <- err
			}))
			e := newCaddyEnv(t)
			t.Cleanup(func() {
				// httptest does not track connections after the WebSocket
				// handshake hijacks them. Close that connection explicitly.
				mu.Lock()
				stopping = true
				ws := active
				mu.Unlock()
				if ws != nil {
					_ = ws.Close()
				}
				upstream.CloseClientConnections()
				upstream.Close()
			})
			proxyTestRoutes(e, upstream)
			if err := e.load(masqueConfig("alice")); err != nil {
				t.Fatal(err)
			}
			ctx, cc := datagramTestClient(t, e)
			str, err := cc.OpenRequestStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_ = str.SetDeadline(time.Now().Add(5 * time.Second))
			u, _ := url.Parse(e.url("/normal"))
			if err := str.SendRequestHeader(&http.Request{Method: http.MethodConnect, Proto: "websocket",
				Host: host, URL: u, Header: http.Header{"Sec-Websocket-Version": {"13"}, "Origin": {"https://" + host}}}); err != nil {
				t.Fatal(err)
			}
			resp, err := str.ReadResponse()
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusOK || resp.Header.Get("Capsule-Protocol") != "" {
				t.Fatalf("WebSocket upgrade: status %d, Capsule-Protocol %q", resp.StatusCode, resp.Header.Get("Capsule-Protocol"))
			}
			// A masked client-to-server binary WebSocket frame (RFC 6455).
			message := []byte("websocket echo")
			mask := [4]byte{1, 2, 3, 4}
			frame := append([]byte{0x82, 0x80 | byte(len(message))}, mask[:]...)
			for i, b := range message {
				frame = append(frame, b^mask[i%len(mask)])
			}
			if _, err := str.Write(frame); err != nil {
				t.Fatal(err)
			}
			var header [2]byte
			if _, err := io.ReadFull(resp.Body, header[:]); err != nil {
				t.Fatal(err)
			}
			if header != [2]byte{0x82, byte(len(message))} {
				t.Fatalf("echo frame header %x, want an unmasked binary frame", header)
			}
			echo := make([]byte, len(message))
			if _, err := io.ReadFull(resp.Body, echo); err != nil || !bytes.Equal(echo, message) {
				t.Fatalf("WebSocket echo %q, error %v", echo, err)
			}
			select {
			case err := <-handlerErr:
				if err != nil {
					t.Fatalf("upstream WebSocket echo: %v", err)
				}
			case <-ctx.Done():
				t.Fatal("upstream WebSocket did not finish the echo")
			}
			_ = str.Close()
			_ = resp.Body.Close()
		})
	}
}
