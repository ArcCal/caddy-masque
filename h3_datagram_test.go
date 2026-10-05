package masque

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func datagramTestClient(t *testing.T, e *caddyEnv) (context.Context, *http3.ClientConn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	conn, err := quic.DialAddr(ctx, fmt.Sprintf("127.0.0.1:%d", e.port), http3.ConfigureTLSConfig(e.tlsConfig("h3")),
		&quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	// Low-level RequestStream and connect-ip-go reads do not inherit the
	// opening context as read deadlines. Bound the entire connection too.
	stop := context.AfterFunc(ctx, func() { _ = conn.CloseWithError(0, "test deadline") })
	t.Cleanup(func() {
		stop()
		_ = conn.CloseWithError(0, "")
	})
	cc := (&http3.Transport{EnableDatagrams: true}).NewClientConn(conn)
	select {
	case <-cc.ReceivedSettings():
	case <-ctx.Done():
		t.Fatal("no HTTP/3 SETTINGS")
	}
	if !cc.Settings().EnableDatagrams || !cc.Settings().EnableExtendedConnect {
		t.Fatalf("server settings: %+v", cc.Settings())
	}
	return ctx, cc
}

func proxyTestRoutes(e *caddyEnv, upstream *httptest.Server) {
	proxy := map[string]any{"handler": "reverse_proxy", "upstreams": []any{
		map[string]any{"dial": strings.TrimPrefix(upstream.URL, "http://")},
	}}
	e.server = map[string]any{"routes": []any{
		// This host has no masque handler, but shares the app's HTTP/3 listener.
		map[string]any{"match": []any{map[string]any{"host": []string{"plain.test"}}}, "handle": []any{proxy}},
		map[string]any{"match": []any{map[string]any{"path": []string{"/held", "/normal", anyTarget}}}, "handle": []any{e.handlerConfig(), proxy}},
		map[string]any{"handle": []any{e.handlerConfig(), map[string]any{"handler": "static_response", "status_code": 200, "body": "cover page"}}},
	}}
}

// An invalid Datagram ends only its request, with the exact RFC 9297 §2
// error. Keep both request directions open until the upstream confirms
// dispatch, so this cannot accidentally exercise the late-Datagram drop.
func TestHTTP3UnexpectedDatagramsPreserveOtherStreams(t *testing.T) {
	for _, reqCase := range []struct{ name, method, protocol string }{
		{http.MethodGet, http.MethodGet, ""},
		{http.MethodPost, http.MethodPost, ""},
		{http.MethodConnect, http.MethodConnect, ""},
		{"unknown-protocol", http.MethodConnect, "unknown-protocol"},
		{"websocket", http.MethodConnect, "websocket"},
	} {
		for _, host := range []string{"vpn.test", "plain.test"} {
			if reqCase.method == http.MethodConnect && reqCase.protocol == "" && host == "vpn.test" {
				// Classic CONNECT has only :authority, so the plain host
				// route catches it without depending on :path.
				continue
			}
			t.Run(reqCase.name+"/"+host, func(t *testing.T) {
				entered := make(chan struct{})
				canceled := make(chan struct{})
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					close(entered)
					// net/http observes a disconnect while reading the open
					// request body, then cancels the request context.
					_, _ = io.Copy(io.Discard, r.Body)
					<-r.Context().Done()
					close(canceled)
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

				// An already active CONNECT-IP stream must survive another
				// stream's protocol error, rather than merely reconnecting.
				req, err := connectip.NewRequest(ctx, uritemplate.MustNew(e.url(anyTarget)))
				if err != nil {
					t.Fatal(err)
				}
				req.Header().Set("Authorization", authorization(testPassword))
				tunnel, resp, err := connectip.NewClientConn(cc).Dial(req)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = tunnel.Close() })
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("CONNECT-IP status: %d", resp.StatusCode)
				}
				assigned, err := tunnel.ReceiveAddressAssignment(ctx)
				if err != nil || len(assigned) != 2 {
					t.Fatalf("address assignment: %v, %v", assigned, err)
				}
				if _, err := tunnel.Routes(ctx); err != nil {
					t.Fatal(err)
				}

				str, err := cc.OpenRequestStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				_ = str.SetDeadline(time.Now().Add(5 * time.Second))
				u, _ := url.Parse(e.url("/held"))
				if err := str.SendRequestHeader(&http.Request{Method: reqCase.method, Proto: reqCase.protocol, Host: host,
					URL: u, Header: make(http.Header), ContentLength: -1}); err != nil {
					t.Fatal(err)
				}
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("upstream did not receive the website request")
				}
				if err := str.SendDatagram([]byte("unexpected")); err != nil {
					t.Fatal(err)
				}
				_, err = str.ReadResponse()
				var streamErr *quic.StreamError
				if !errors.As(err, &streamErr) || !streamErr.Remote || streamErr.ErrorCode != quic.StreamErrorCode(http3.ErrCodeDatagramError) {
					t.Fatalf("request error: %v; want remote stream reset 0x33", err)
				}
				select {
				case <-canceled:
				case <-ctx.Done():
					t.Fatal("upstream request was not canceled after the stream reset")
				}

				website, _ := http.NewRequestWithContext(ctx, http.MethodGet, e.url("/"), nil)
				response, err := cc.RoundTrip(website)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || response.StatusCode != 200 || string(body) != "cover page" {
					t.Fatalf("website after reset: %d %q, %v", response.StatusCode, body, err)
				}
				packet := udp(assigned[0].IPPrefix.Addr().String(), "1.1.1.1", 30)
				if _, err := tunnel.WritePacket(packet); err != nil {
					t.Fatal(err)
				}
				if got := hostPacket(t, e.dev); !slices.Equal(got, packet) {
					t.Fatal("CONNECT-IP outgoing packet changed after unrelated stream reset")
				}
				back := udp("1.1.1.1", assigned[0].IPPrefix.Addr().String(), 1000)
				e.dev.fromHost <- back
				buf := make([]byte, 2000)
				if n, err := readPacket(tunnel, buf); err != nil || !slices.Equal(buf[:n], back) {
					t.Fatalf("CONNECT-IP incoming packet after reset: %v", err)
				}
			})
		}
	}
}

// Marking ordinary requests as not supporting Datagrams must leave
// request bodies, status selection, response framing, trailers and FIN
// ownership with quic-go's normal HTTP handler lifecycle.
func TestHTTP3WebsiteBodyAndTrailers(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Trailer", "X-Body-Proof")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(append([]byte("echo:"), body...))
		w.Header().Set("X-Body-Proof", "complete")
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
	for _, host := range []string{"vpn.test", "plain.test"} {
		t.Run(host, func(t *testing.T) {
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, e.url("/normal"), strings.NewReader("website body"))
			req.Host = host
			resp, err := cc.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil || resp.StatusCode != http.StatusCreated || string(body) != "echo:website body" || resp.Trailer.Get("X-Body-Proof") != "complete" {
				t.Fatalf("website response: status %d, body %q, trailers %v, error %v", resp.StatusCode, body, resp.Trailer, err)
			}
		})
	}
}

// RFC 9484 §7.1 permits optimistic packets on a recognized CONNECT-IP
// request even when authentication fails and the website answers it.
func TestHTTP3OptimisticRefusalDatagrams(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-release:
			w.WriteHeader(http.StatusTeapot)
			_, _ = io.WriteString(w, "cover refusal")
		case <-r.Context().Done():
		}
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
	str, err := cc.OpenRequestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = str.SetDeadline(time.Now().Add(5 * time.Second))
	u, _ := url.Parse(e.url(anyTarget))
	if err := str.SendRequestHeader(&http.Request{Method: http.MethodConnect, Proto: "connect-ip", Host: u.Host, URL: u,
		Header: http.Header{"Capsule-Protocol": {"?1"}, "Authorization": {authorization("wrong password")}}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("CONNECT-IP authentication refusal did not reach the website")
	}
	if err := str.SendDatagram([]byte{0, 1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	close(release)
	resp, err := str.ReadResponse()
	if err != nil {
		t.Fatalf("optimistic CONNECT-IP Datagram changed the refusal: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusTeapot || string(body) != "cover refusal" {
		t.Fatalf("CONNECT-IP refusal: %d %q, %v", resp.StatusCode, body, err)
	}
}
