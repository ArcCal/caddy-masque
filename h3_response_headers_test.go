package masque

import (
	"io"
	"net/http"
	"net/url"
	"testing"
)

// Caddy's supported close option sets Connection: close for its HTTP/1
// writer. Reusing the same site over HTTP/3 must not serialize that field
// or lose ordinary response metadata when filtering it (RFC 9114 §4.2).
func TestHTTP3CaddyCloseResponseHeaders(t *testing.T) {
	e := newCaddyEnv(t)
	e.server = map[string]any{"routes": []any{map[string]any{"handle": []any{
		e.handlerConfig(),
		map[string]any{
			"handler": "static_response", "close": true, "status_code": 201, "body": "closing cover page",
			"headers": map[string][]string{
				"X-Site":       {"preserved"},
				"Trailer":      {"X-Site-Proof"},
				"X-Site-Proof": {"complete"},
			},
		},
	}}}}
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	ctx, cc := datagramTestClient(t, e)
	check := func(t *testing.T, resp *http.Response, want int) {
		t.Helper()
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != want || string(body) != "closing cover page" {
			t.Fatalf("site response: status %d, body %q, error %v", resp.StatusCode, body, err)
		}
		if resp.Header.Get("X-Site") != "preserved" || resp.Trailer.Get("X-Site-Proof") != "complete" {
			t.Fatalf("site header or trailer lost: headers %v, trailers %v", resp.Header, resp.Trailer)
		}
		for _, name := range []string{"Connection", "Keep-Alive", "Proxy-Connection", "Transfer-Encoding", "Upgrade", "Te", "Capsule-Protocol"} {
			if _, present := resp.Header[name]; present {
				t.Errorf("unexpected response field %s: %q", name, resp.Header.Values(name))
			}
		}
	}
	t.Run("ordinary site", func(t *testing.T) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, e.url("/"), nil)
		resp, err := cc.RoundTrip(req)
		if err != nil {
			t.Fatalf("supported Caddy close response was malformed: %v", err)
		}
		check(t, resp, http.StatusCreated)
	})
	t.Run("CONNECT-IP refusal", func(t *testing.T) {
		str, err := cc.OpenRequestStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer str.Close()
		u, _ := url.Parse(e.url(anyTarget))
		req := &http.Request{Method: http.MethodConnect, Proto: connectIP, Host: u.Host, URL: u,
			Header: http.Header{"Authorization": {authorization("wrong password!!")}}}
		if err := str.SendRequestHeader(req); err != nil {
			t.Fatal(err)
		}
		resp, err := str.ReadResponse()
		if err != nil {
			t.Fatalf("site refusal was malformed: %v", err)
		}
		check(t, resp, http.StatusNotFound)
	})
}
