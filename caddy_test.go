package masque

// Tests that run Caddy in the test process with the masque app and handler,
// and talk CONNECT-IP to it over HTTP/3, HTTP/2 and HTTP/1.1 with small Go
// clients. The TUN device is replaced by a fake one, so they need no
// privileges.

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"

	"github.com/ArcCal/caddy-masque/internal/auth"
	"github.com/ArcCal/caddy-masque/internal/hostnet"
	"github.com/ArcCal/caddy-masque/internal/proto"
)

const testPassword = "correct horse battery"

var (
	testHashOnce sync.Once
	testHashed   string
)

func testPasswordHash() string {
	testHashOnce.Do(func() { testHashed = auth.HashPassword(testPassword) })
	return testHashed
}

type testCert struct {
	certPEM, keyPEM string
	pool            *x509.CertPool
}

func newTestCert(t *testing.T) testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "vpn.test"},
		DNSNames:              []string{"vpn.test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return testCert{
		certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		keyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
		pool:    pool,
	}
}

// freePort finds a port free for both TCP and UDP on 127.0.0.1.
func freePort(t *testing.T) int {
	t.Helper()
	for range 50 {
		tl, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := tl.Addr().(*net.TCPAddr).Port
		ul, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
		tl.Close()
		if err == nil {
			ul.Close()
			return port
		}
	}
	t.Fatal("no free port")
	return 0
}

type caddyEnv struct {
	t       *testing.T
	port    int
	cert    testCert
	dev     *fakeDevice
	storage string
	// Extra settings of the HTTP server.
	server map[string]any
}

// newCaddyEnv replaces the host network with a fake device and stops
// Caddy at the end of the test.
func newCaddyEnv(t *testing.T) *caddyEnv {
	e := &caddyEnv{t: t, port: freePort(t), cert: newTestCert(t), dev: newFakeDevice(), storage: t.TempDir()}
	oldOpen, oldForget := openDevice, forgetConntrack
	openDevice = func(hostnet.Config) (device, error) { return e.dev, nil }
	forgetConntrack = func(p []netip.Prefix) (int, error) { return 0, nil }
	t.Cleanup(func() {
		_ = caddy.Stop()
		openDevice, forgetConntrack = oldOpen, oldForget
	})
	return e
}

// config is a Caddy JSON configuration: one HTTPS server whose routes are
// the masque handler and a cover page.
func (e *caddyEnv) config(masque map[string]any) []byte {
	cfg := map[string]any{
		"admin":   map[string]any{"disabled": true},
		"storage": map[string]any{"module": "file_system", "root": e.storage},
		"logging": map[string]any{"logs": map[string]any{"default": map[string]any{"level": "ERROR"}}},
		"apps": map[string]any{
			"masque": masque,
			"tls": map[string]any{"certificates": map[string]any{"load_pem": []any{
				map[string]any{"certificate": e.cert.certPEM, "key": e.cert.keyPEM},
			}}},
			"http": map[string]any{"servers": map[string]any{"vpn": e.serverConfig(map[string]any{
				"listen":                  []string{fmt.Sprintf("127.0.0.1:%d", e.port)},
				"tls_connection_policies": []any{map[string]any{}},
				"automatic_https":         map[string]any{"disable": true},
				"routes": []any{map[string]any{"handle": []any{
					map[string]any{"handler": "masque"},
					map[string]any{"handler": "static_response", "status_code": 200, "body": "cover page"},
				}}},
			})}},
		},
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	return b
}

func (e *caddyEnv) serverConfig(srv map[string]any) map[string]any {
	for k, v := range e.server {
		srv[k] = v
	}
	return srv
}

func masqueConfig(users ...string) map[string]any {
	var list []any
	for _, u := range users {
		list = append(list, map[string]any{"name": u, "password_hash": testPasswordHash()})
	}
	return map[string]any{"interface": "test0", "ipv4": "10.89.0.1/24", "ipv6": "fd89::1/64", "users": list}
}

func (e *caddyEnv) load(masque map[string]any) error {
	return caddy.Load(e.config(masque), true)
}

func (e *caddyEnv) tlsConfig(alpn string) *tls.Config {
	return &tls.Config{RootCAs: e.cert.pool, ServerName: "vpn.test", NextProtos: []string{alpn}}
}

// dialTCP connects to Caddy, with TLS when cfg is set. On Linux, a Caddy
// reload opens a new SO_REUSEPORT socket and closes the old one, which
// resets connections waiting in the old one's queue: like a real client,
// try again.
func (e *caddyEnv) dialTCP(ctx context.Context, cfg *tls.Config) (net.Conn, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", e.port)
	for attempt := 0; ; attempt++ {
		var conn net.Conn
		var err error
		if cfg != nil {
			conn, err = (&tls.Dialer{Config: cfg}).DialContext(ctx, "tcp", addr)
		} else {
			conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		}
		if err == nil || attempt == 4 || !errors.Is(err, syscall.ECONNRESET) {
			return conn, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (e *caddyEnv) url(path string) string { return fmt.Sprintf("https://vpn.test:%d%s", e.port, path) }

const anyTarget = "/.well-known/masque/ip/*/*/"

// tunnelClient is the client's side of a CONNECT-IP stream.
type tunnelClient struct {
	status  int
	header  http.Header
	body    string // of a refusal
	capsule func() (proto.Capsule, error)
	send    func(pkt []byte) error // an IP packet, with context ID 0
	recv    func() ([]byte, error) // an IP packet
	close   func()
}

func authorization(password string) string { return auth.BasicAuthorization("alice", password) }

func (e *caddyEnv) dialH3(t *testing.T, password, path string) *tunnelClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, fmt.Sprintf("127.0.0.1:%d", e.port), http3.ConfigureTLSConfig(e.tlsConfig("h3")),
		&quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	cc := (&http3.Transport{EnableDatagrams: true}).NewClientConn(conn)
	select {
	case <-cc.ReceivedSettings():
	case <-ctx.Done():
		t.Fatal("no SETTINGS")
	}
	if s := cc.Settings(); !s.EnableDatagrams || !s.EnableExtendedConnect {
		t.Fatalf("server settings %+v", s)
	}
	str, err := cc.OpenRequestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(e.url(path))
	req := &http.Request{Method: http.MethodConnect, Proto: "connect-ip", Host: u.Host, URL: u,
		Header: http.Header{"Capsule-Protocol": {"?1"}, "Authorization": {authorization(password)}}}
	if err := str.SendRequestHeader(req); err != nil {
		t.Fatal(err)
	}
	resp, err := str.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	c := &tunnelClient{status: resp.StatusCode, header: resp.Header,
		close: func() { str.CancelRead(0x100); str.Close(); conn.CloseWithError(0, "") }}
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Capsule-Protocol") == "" {
		b, _ := io.ReadAll(resp.Body)
		c.body = string(b)
		c.close()
		return c
	}
	reader := newCapsuleReader(str)
	c.capsule = reader.next
	c.send = func(pkt []byte) error { return str.SendDatagram(append([]byte{0}, pkt...)) }
	c.recv = func() ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		d, err := str.ReceiveDatagram(ctx)
		if err != nil {
			return nil, err
		}
		return d[1:], nil
	}
	return c
}

// streamClient is the capsule side of HTTP/2 and HTTP/1.1 tunnels, where
// datagrams travel as DATAGRAM capsules.
func streamClient(c *tunnelClient, r io.Reader, w io.Writer) {
	reader := newCapsuleReader(r)
	var mu sync.Mutex
	c.capsule = reader.next
	c.send = func(pkt []byte) error {
		mu.Lock()
		defer mu.Unlock()
		_, err := w.Write(proto.Append(nil, proto.Datagram(append([]byte{0}, pkt...))))
		return err
	}
	c.recv = func() ([]byte, error) {
		for {
			cap, err := reader.next()
			if err != nil {
				return nil, err
			}
			if d, ok := cap.(proto.Datagram); ok {
				return d[1:], nil
			}
		}
	}
}

func (e *caddyEnv) dialH2(t *testing.T, password, path string) *tunnelClient {
	t.Helper()
	tr := &http2.Transport{TLSClientConfig: e.tlsConfig("h2"),
		DialTLSContext: func(ctx context.Context, network, _ string, cfg *tls.Config) (net.Conn, error) {
			return e.dialTCP(ctx, cfg)
		}}
	pr, pw := io.Pipe()
	req, _ := http.NewRequest(http.MethodConnect, e.url(path), pr)
	req.Header = http.Header{":protocol": {"connect-ip"}, "Capsule-Protocol": {"?1"}, "Authorization": {authorization(password)}}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("HTTP/%d", resp.ProtoMajor)
	}
	c := &tunnelClient{status: resp.StatusCode, header: resp.Header,
		close: func() { pw.Close(); resp.Body.Close(); tr.CloseIdleConnections() }}
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Capsule-Protocol") == "" {
		b, _ := io.ReadAll(resp.Body)
		c.body = string(b)
		c.close()
		return c
	}
	streamClient(c, resp.Body, pw)
	return c
}

func (e *caddyEnv) dialH1(t *testing.T, password, path string) *tunnelClient {
	t.Helper()
	conn, err := e.dialTCP(context.Background(), e.tlsConfig("http/1.1"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: vpn.test:%d\r\nConnection: Upgrade\r\nUpgrade: connect-ip\r\n"+
		"Capsule-Protocol: ?1\r\nAuthorization: %s\r\n\r\n", path, e.port, authorization(password))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &tunnelClient{status: resp.StatusCode, header: resp.Header, close: func() { conn.Close() }}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		b, _ := io.ReadAll(resp.Body)
		c.body = string(b)
		c.close()
		return c
	}
	streamClient(c, br, conn)
	return c
}

type dialer func(*caddyEnv, *testing.T, string, string) *tunnelClient

var transports = []struct {
	name string
	dial dialer
	ok   int
}{
	{"HTTP/3", (*caddyEnv).dialH3, http.StatusOK},
	{"HTTP/2", (*caddyEnv).dialH2, http.StatusOK},
	{"HTTP/1.1", (*caddyEnv).dialH1, http.StatusSwitchingProtocols},
}

// opening reads ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT and returns the
// assigned IPv4 and IPv6 addresses.
func opening(t *testing.T, c *tunnelClient) (netip.Addr, netip.Addr) {
	t.Helper()
	first, err := c.capsule()
	if err != nil {
		t.Fatal(err)
	}
	assign, ok := first.(proto.AddressAssign)
	if !ok || len(assign) != 2 {
		t.Fatalf("first capsule %#v", first)
	}
	second, err := c.capsule()
	if err != nil {
		t.Fatal(err)
	}
	if adv, ok := second.(proto.RouteAdvertisement); !ok || len(adv) == 0 || proto.ValidateRoutes(adv) != nil {
		t.Fatalf("second capsule %#v", second)
	}
	return assign[0].Prefix.Addr(), assign[1].Prefix.Addr()
}

func TestCaddyServesConnectIP(t *testing.T) {
	e := newCaddyEnv(t)
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			c := tr.dial(e, t, testPassword, anyTarget)
			if c.status != tr.ok {
				t.Fatalf("status %d: %s", c.status, c.body)
			}
			if c.header.Get("Capsule-Protocol") != "?1" {
				t.Errorf("Capsule-Protocol %q", c.header.Get("Capsule-Protocol"))
			}
			for _, h := range []string{"Content-Type", "Content-Length", "Transfer-Encoding"} {
				if v, ok := c.header[h]; ok {
					t.Errorf("%s %q on a Capsule Protocol response (RFC 9297 §3.2)", h, v)
				}
			}
			v4, v6 := opening(t, c)
			for _, pkt := range [][]byte{udp(v4.String(), "1.1.1.1", 50), udp(v6.String(), "2606:4700::1111", 50)} {
				if err := c.send(pkt); err != nil {
					t.Fatal(err)
				}
				if got := hostPacket(t, e.dev); !slices.Equal(got, pkt) {
					t.Error("the network got another packet")
				}
			}
			for _, pkt := range [][]byte{udp("1.1.1.1", v4.String(), 1200), udp("2606:4700::1111", v6.String(), 1200)} {
				e.dev.fromHost <- pkt
				got, err := c.recv()
				if err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(got, pkt) {
					t.Error("the client got another packet")
				}
			}
			c.close()
			waitNoSessions(t)
		})
	}
}

func waitNoSessions(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		n := 0
		cores.Range(func(_ any, v any) bool {
			c := v.(*core)
			c.sessMu.RLock()
			n += len(c.sessions) + int(c.running.Load())
			c.sessMu.RUnlock()
			return true
		})
		if n == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("a session or its handler is still running")
}

func TestCaddyRefusalsLookLikeTheSite(t *testing.T) {
	e := newCaddyEnv(t)
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	for _, tr := range transports {
		for _, c := range []struct{ name, password, path string }{
			{"wrong password", "wrong password!!", anyTarget},
			{"other path", testPassword, "/not/the/template/"},
		} {
			got := tr.dial(e, t, c.password, c.path)
			if got.status != http.StatusOK || got.body != "cover page" || got.header.Get("Capsule-Protocol") != "" {
				t.Errorf("%s, %s: %d %q %v", tr.name, c.name, got.status, got.body, got.header)
			}
		}
		// Authenticated, but blocked or malformed: status codes for users.
		for _, c := range []struct {
			path   string
			status int
		}{
			{"/.well-known/masque/ip/192.168.0.0%2F16/*/", http.StatusForbidden},
			{"/.well-known/masque/ip/*/0/", http.StatusBadRequest},
			{"/.well-known/masque/ip/not%20a%20name/*/", http.StatusBadRequest},
			{"/.well-known/masque/ip/name.invalid/*/", http.StatusBadGateway},
		} {
			got := tr.dial(e, t, testPassword, c.path)
			if got.status != c.status {
				t.Errorf("%s %s: %d, want %d", tr.name, c.path, got.status, c.status)
			}
			if c.status == http.StatusBadGateway && !strings.Contains(got.header.Get("Proxy-Status"), "error=dns_") {
				t.Errorf("%s: Proxy-Status %q", tr.name, got.header.Get("Proxy-Status"))
			}
		}
	}
}

func TestCaddyWebsiteOverEveryVersion(t *testing.T) {
	e := newCaddyEnv(t)
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	get := func(rt http.RoundTripper) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, e.url("/"), nil)
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != "cover page" {
			t.Errorf("HTTP/%d: %q", resp.ProtoMajor, b)
		}
		return resp
	}
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return e.dialTCP(ctx, nil)
	}
	for _, h2 := range []bool{false, true} {
		cfg := e.tlsConfig("http/1.1")
		if h2 {
			cfg = e.tlsConfig("h2")
		}
		resp := get(&http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: h2, DialContext: dial})
		want := fmt.Sprintf(`h3=":%d"; ma=2592000`, e.port)
		if got := resp.Header.Get("Alt-Svc"); got != want {
			t.Errorf("HTTP/%d Alt-Svc %q, want %q", resp.ProtoMajor, got, want)
		}
		if !strings.HasPrefix(resp.Header.Get("Server"), "Caddy") {
			t.Errorf("Server %q", resp.Header.Get("Server"))
		}
	}
	h3 := &http3.Transport{TLSClientConfig: e.tlsConfig("h3"),
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, fmt.Sprintf("127.0.0.1:%d", e.port), tlsCfg, cfg)
		}}
	defer h3.Close()
	if resp := get(h3); resp.ProtoMajor != 3 {
		t.Errorf("HTTP/%d", resp.ProtoMajor)
	}
}

func TestCaddyReloads(t *testing.T) {
	e := newCaddyEnv(t)
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	var clients []*tunnelClient
	for _, tr := range transports {
		c := tr.dial(e, t, testPassword, anyTarget)
		if c.status != tr.ok {
			t.Fatalf("%s: %d", tr.name, c.status)
		}
		opening(t, c)
		clients = append(clients, c)
	}
	// A reload that keeps the user keeps the tunnels.
	cfg := masqueConfig("alice", "bob")
	if err := e.load(cfg); err != nil {
		t.Fatal(err)
	}
	for i, c := range clients {
		v4 := netip.Addr{}
		cores.Range(func(_ any, v any) bool {
			cc := v.(*core)
			cc.sessMu.RLock()
			for a, h := range cc.sessions {
				if a.Is4() && h.id == uint64(i+1) {
					v4 = a
				}
			}
			cc.sessMu.RUnlock()
			return true
		})
		if !v4.IsValid() {
			t.Fatalf("%s: session gone after the reload", transports[i].name)
		}
		e.dev.fromHost <- udp("1.1.1.1", v4.String(), 10)
		if _, err := c.recv(); err != nil {
			t.Errorf("%s: %v after the reload", transports[i].name, err)
		}
	}
	// More destinations reach running sessions as a new advertisement.
	cfg["allow_client_to_client"] = true
	if err := e.load(cfg); err != nil {
		t.Fatal(err)
	}
	for i, c := range clients {
		next, err := c.capsule()
		if err != nil {
			t.Fatalf("%s: %v", transports[i].name, err)
		}
		if _, ok := next.(proto.RouteAdvertisement); !ok {
			t.Errorf("%s: %T instead of new routes", transports[i].name, next)
		}
	}
	// Changing the tunnel needs a restart.
	bad := masqueConfig("alice")
	bad["ipv4"] = "10.90.0.1/24"
	if err := e.load(bad); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Errorf("tunnel change: %v", err)
	}
	// Fewer destinations, or removing the user, end the tunnels.
	for _, change := range []map[string]any{
		{"blocked_destinations": []string{"1.0.0.0/8"}, "allow_client_to_client": true},
		{"users": nil},
	} {
		next := masqueConfig("alice", "bob")
		for k, v := range change {
			next[k] = v
		}
		if change["users"] != nil || len(change) == 1 {
			next = masqueConfig("bob")
		}
		if err := e.load(next); err != nil {
			t.Fatal(err)
		}
		for i, c := range clients {
			done := make(chan error, 1)
			go func() {
				for {
					if _, err := c.capsule(); err != nil {
						done <- err
						return
					}
				}
			}()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Errorf("%s: the tunnel stays open", transports[i].name)
			}
			c.close()
		}
		waitNoSessions(t)
		if err := e.load(masqueConfig("alice", "bob")); err != nil {
			t.Fatal(err)
		}
		clients = clients[:0]
		for _, tr := range transports {
			c := tr.dial(e, t, testPassword, anyTarget)
			opening(t, c)
			clients = append(clients, c)
		}
	}
	for _, c := range clients {
		c.close()
	}
	waitNoSessions(t)
}

func TestCaddyWithoutHTTP3(t *testing.T) {
	e := newCaddyEnv(t)
	cfg := masqueConfig("alice")
	cfg["http3"] = false
	if err := e.load(cfg); err != nil {
		t.Fatal(err)
	}
	// Caddy serves HTTP/3 itself, without datagrams: the client sees the
	// SETTINGS and does not use it for CONNECT-IP.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, fmt.Sprintf("127.0.0.1:%d", e.port), http3.ConfigureTLSConfig(e.tlsConfig("h3")),
		&quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	cc := (&http3.Transport{EnableDatagrams: true}).NewClientConn(conn)
	<-cc.ReceivedSettings()
	if cc.Settings().EnableDatagrams {
		t.Error("Caddy's own HTTP/3 has datagrams?")
	}
	for _, tr := range transports[1:] {
		c := tr.dial(e, t, testPassword, anyTarget)
		if c.status != tr.ok {
			t.Errorf("%s: %d", tr.name, c.status)
		}
		c.close()
	}
}

func TestCaddyHandlerNeedsTheApp(t *testing.T) {
	e := newCaddyEnv(t)
	var cfg map[string]any
	_ = json.Unmarshal(e.config(nil), &cfg)
	delete(cfg["apps"].(map[string]any), "masque")
	b, _ := json.Marshal(cfg)
	if err := caddy.Load(b, true); err == nil || !strings.Contains(err.Error(), "masque") {
		t.Errorf("loaded without the app: %v", err)
	}
}

// A client that stops reading fills the stream's flow control window, and
// the session's writes block. Removing the user must still end the session
// and let the handler return.
func TestCaddyEndsBlockedTunnels(t *testing.T) {
	e := newCaddyEnv(t)
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	for _, tr := range transports {
		c := tr.dial(e, t, testPassword, anyTarget)
		v4, _ := opening(t, c)
		// Until the session's queue toward the client stays full: its
		// writer is blocked. QUIC datagrams are not flow controlled, so
		// HTTP/3 does not get there.
		var queue chan queued
		cores.Range(func(_ any, v any) bool {
			c := v.(*core)
			c.sessMu.RLock()
			if h := c.sessions[v4]; h != nil {
				queue = h.toClient
			}
			c.sessMu.RUnlock()
			return true
		})
		blocked := false
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline) && !blocked; {
			for range 200 {
				e.dev.fromHost <- udp("1.1.1.1", v4.String(), 1200)
			}
			// Full, and not drained for a while.
			if len(queue) == cap(queue) {
				time.Sleep(300 * time.Millisecond)
				blocked = len(queue) == cap(queue)
			}
		}
		if tr.name != "HTTP/3" && !blocked {
			t.Fatalf("%s: the writer never blocked", tr.name)
		}
		if err := e.load(masqueConfig("bob")); err != nil {
			t.Fatal(err)
		}
		waitNoSessions(t)
		c.close()
		if err := e.load(masqueConfig("alice")); err != nil {
			t.Fatal(err)
		}
	}
}

// Caddy's default read and write idle timeouts (one minute in 2.11), and
// read and write timeouts, must not end idle tunnels.
func TestCaddyTimeoutsDoNotEndTunnels(t *testing.T) {
	e := newCaddyEnv(t)
	e.server = map[string]any{
		"read_idle_timeout": "500ms", "write_idle_timeout": "500ms",
		"read_timeout": "1s", "write_timeout": "1s",
	}
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	var clients []*tunnelClient
	var addrs []netip.Addr
	for _, tr := range transports {
		c := tr.dial(e, t, testPassword, anyTarget)
		if c.status != tr.ok {
			t.Fatalf("%s: %d", tr.name, c.status)
		}
		v4, _ := opening(t, c)
		clients = append(clients, c)
		addrs = append(addrs, v4)
	}
	time.Sleep(2 * time.Second)
	for i, c := range clients {
		pkt := udp(addrs[i].String(), "1.1.1.1", 20)
		if err := c.send(pkt); err != nil {
			t.Errorf("%s: send after idling: %v", transports[i].name, err)
			continue
		}
		if got := hostPacket(t, e.dev); !slices.Equal(got, pkt) {
			t.Errorf("%s: wrong packet", transports[i].name)
		}
		e.dev.fromHost <- udp("1.1.1.1", addrs[i].String(), 20)
		if _, err := c.recv(); err != nil {
			t.Errorf("%s: receive after idling: %v", transports[i].name, err)
		}
		c.close()
	}
	waitNoSessions(t)
}

// A client that ends its side of the stream gets a clean end of the
// response, not a reset.
func TestCaddyCleanEndOfHTTP2Tunnels(t *testing.T) {
	e := newCaddyEnv(t)
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	tr := &http2.Transport{TLSClientConfig: e.tlsConfig("h2"),
		DialTLSContext: func(ctx context.Context, network, _ string, cfg *tls.Config) (net.Conn, error) {
			return e.dialTCP(ctx, cfg)
		}}
	defer tr.CloseIdleConnections()
	pr, pw := io.Pipe()
	req, _ := http.NewRequest(http.MethodConnect, e.url(anyTarget), pr)
	req.Header = http.Header{":protocol": {"connect-ip"}, "Authorization": {authorization(testPassword)}}
	resp, err := tr.RoundTrip(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatal(resp, err)
	}
	reader := newCapsuleReader(resp.Body)
	for range 2 {
		if _, err := reader.next(); err != nil {
			t.Fatal(err)
		}
	}
	pw.Close() // END_STREAM from the client
	if _, err := reader.next(); err != io.EOF {
		t.Errorf("the server ended the stream with %v, want a clean end", err)
	}
	waitNoSessions(t)
}

// A client without HTTP/3 datagram support gets its packets in DATAGRAM
// capsules (RFC 9297 §2.1.1, §3.5).
func TestCaddyHTTP3WithoutDatagrams(t *testing.T) {
	e := newCaddyEnv(t)
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, fmt.Sprintf("127.0.0.1:%d", e.port), http3.ConfigureTLSConfig(e.tlsConfig("h3")), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	cc := (&http3.Transport{}).NewClientConn(conn)
	<-cc.ReceivedSettings()
	str, err := cc.OpenRequestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(e.url(anyTarget))
	if err := str.SendRequestHeader(&http.Request{Method: http.MethodConnect, Proto: "connect-ip", Host: u.Host, URL: u,
		Header: http.Header{"Authorization": {authorization(testPassword)}}}); err != nil {
		t.Fatal(err)
	}
	resp, err := str.ReadResponse()
	if err != nil || resp.StatusCode != 200 {
		t.Fatal(resp, err)
	}
	c := &tunnelClient{}
	streamClient(c, str, str)
	v4, _ := opening(t, c)
	pkt := udp(v4.String(), "1.1.1.1", 30)
	if err := c.send(pkt); err != nil {
		t.Fatal(err)
	}
	if got := hostPacket(t, e.dev); !slices.Equal(got, pkt) {
		t.Error("wrong packet to the network")
	}
	back := udp("1.1.1.1", v4.String(), 1000)
	e.dev.fromHost <- back
	if got, err := c.recv(); err != nil || !slices.Equal(got, back) {
		t.Errorf("DATAGRAM capsule: %v", err)
	}
}

// A reload that fails after the masque app started leaves the previous
// configuration in charge: its users, and HTTP/3 served by its handlers.
func TestCaddyFailedReloadKeepsThePreviousConfig(t *testing.T) {
	e := newCaddyEnv(t)
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	var cfg map[string]any
	_ = json.Unmarshal(e.config(masqueConfig("bob")), &cfg)
	servers := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	servers["blocked"] = map[string]any{"listen": []string{busy.Addr().String()}}
	b, _ := json.Marshal(cfg)
	if err := caddy.Load(b, true); err == nil {
		t.Fatal("a configuration with a busy port loaded")
	}
	for _, tr := range transports {
		c := tr.dial(e, t, testPassword, anyTarget)
		if c.status != tr.ok {
			t.Errorf("%s: alice gets %d after the failed reload", tr.name, c.status)
			continue
		}
		v4, _ := opening(t, c)
		e.dev.fromHost <- udp("1.1.1.1", v4.String(), 10)
		if _, err := c.recv(); err != nil {
			t.Errorf("%s: %v", tr.name, err)
		}
		c.close()
	}
	waitNoSessions(t)
}

// Turning HTTP/3 over to the app by a reload, while Caddy's own HTTP/3
// socket on the port is still open.
func TestCaddyReloadTakesHTTP3Over(t *testing.T) {
	e := newCaddyEnv(t)
	cfg := masqueConfig("alice")
	cfg["http3"] = false
	if err := e.load(cfg); err != nil {
		t.Fatal(err)
	}
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	c := e.dialH3(t, testPassword, anyTarget)
	if c.status != http.StatusOK {
		t.Fatalf("status %d", c.status)
	}
	opening(t, c)
	c.close()
	// And back.
	if err := e.load(cfg); err != nil {
		t.Fatal(err)
	}
	waitNoSessions(t)
}

func TestCaddyIPv6Target(t *testing.T) {
	e := newCaddyEnv(t)
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	// RFC 9484 §4.6: colons and the slash are percent-encoded.
	for _, tr := range transports {
		c := tr.dial(e, t, testPassword, "/.well-known/masque/ip/2001%3Adb8%3A%3A%2F32/17/")
		if c.status != tr.ok {
			t.Fatalf("%s: %d", tr.name, c.status)
		}
		first, err := c.capsule()
		if err != nil {
			t.Fatal(err)
		}
		if a, ok := first.(proto.AddressAssign); !ok || len(a) != 1 || !a[0].Prefix.Addr().Is6() {
			t.Errorf("%s: an IPv6 scope gets one IPv6 address: %v", tr.name, first)
		}
		second, err := c.capsule()
		if err != nil {
			t.Fatal(err)
		}
		want := proto.RouteAdvertisement{{Start: netip.MustParseAddr("2001:db8::"),
			End: netip.MustParseAddr("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"), Protocol: 17}}
		if !slices.Equal(second.(proto.RouteAdvertisement), want) {
			t.Errorf("%s: routes %v", tr.name, second)
		}
		c.close()
	}
	waitNoSessions(t)
}

func TestCaddyMalformedHTTP1Requests(t *testing.T) {
	e := newCaddyEnv(t)
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	send := func(request string) string {
		conn, err := e.dialTCP(context.Background(), e.tlsConfig("http/1.1"))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		fmt.Fprint(conn, request)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		return fmt.Sprintf("%d %s", resp.StatusCode, b)
	}
	for _, c := range []struct{ name, head, want string }{
		{"POST with valid credentials", "POST", "400 "},
		{"GET without Connection: Upgrade", "GET-noconn", "400 "},
	} {
		method, conn := c.head, "Connection: Upgrade\r\n"
		if method == "GET-noconn" {
			method, conn = "GET", ""
		}
		got := send(fmt.Sprintf("%s %s HTTP/1.1\r\nHost: vpn.test\r\n%sUpgrade: connect-ip\r\nAuthorization: %s\r\nContent-Length: 0\r\n\r\n",
			method, anyTarget, conn, authorization(testPassword)))
		if !strings.HasPrefix(got, c.want) {
			t.Errorf("%s: %q", c.name, got)
		}
	}
	// Without valid credentials, the site answers.
	got := send(fmt.Sprintf("POST %s HTTP/1.1\r\nHost: vpn.test\r\nUpgrade: connect-ip\r\nContent-Length: 0\r\n\r\n", anyTarget))
	if got != "200 cover page" {
		t.Errorf("anonymous: %q", got)
	}
}
