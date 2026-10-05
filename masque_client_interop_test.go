package masque

// Interoperability with masque-vpn's masque-client, the production Rust
// client that the IETF Masque app bundles, run as a separate process. In
// SOCKS mode its user-space IP stack needs no TUN device and no kernel
// IPv6, so IPv4 and IPv6 through the tunnel are checked on any host, over
// HTTP/3 (with QUIC datagrams, and with DATAGRAM capsules), HTTP/2 and
// HTTP/1.1. MASQUE_CLIENT names the binary; CI sets it in the end-to-end
// job, which builds the client.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/ArcCal/caddy-masque/internal/ip"
)

// newTestChain is a CA and a certificate for vpn.test it issued: rustls,
// unlike Go, refuses a CA certificate as the server's own.
func newTestChain(t *testing.T) (testCert, string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "vpn.test"},
		DNSNames:     []string{"vpn.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return testCert{
		certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + caPEM,
		keyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
		pool:    pool,
	}, caPEM
}

// reflectUDP answers a UDP packet to port 7 the way an echo server on the
// network would: addresses and ports swapped, checksums made anew. nil for
// anything else.
func reflectUDP(p []byte) []byte {
	h, ok := ip.Parse(p)
	if !ok || h.Protocol != ip.ProtoUDP || h.PayloadOffset < 0 || h.PayloadOffset+8 > h.TotalLen {
		return nil
	}
	out := slices.Clone(p[:h.TotalLen])
	u := out[h.PayloadOffset:]
	if binary.BigEndian.Uint16(u[2:4]) != 7 {
		return nil
	}
	sport, dport := binary.BigEndian.Uint16(u[0:2]), binary.BigEndian.Uint16(u[2:4])
	binary.BigEndian.PutUint16(u[0:2], dport)
	binary.BigEndian.PutUint16(u[2:4], sport)
	var src, dst []byte
	if h.IsIPv4() {
		src, dst = slices.Clone(out[16:20]), slices.Clone(out[12:16])
		copy(out[12:16], src)
		copy(out[16:20], dst)
		out[10], out[11] = 0, 0
		binary.BigEndian.PutUint16(out[10:12], ip.Checksum(out[:h.PayloadOffset]))
	} else {
		src, dst = slices.Clone(out[24:40]), slices.Clone(out[8:24])
		copy(out[8:24], src)
		copy(out[24:40], dst)
	}
	u[6], u[7] = 0, 0
	length := binary.BigEndian.AppendUint32(nil, uint32(len(u)))
	csum := ip.Checksum(src, dst, length, []byte{0, 0, 0, ip.ProtoUDP}, u)
	if csum == 0 {
		csum = 0xffff // zero means "no checksum" (RFC 768)
	}
	binary.BigEndian.PutUint16(u[6:8], csum)
	return out
}

// lockedBuffer collects the client's output, which the test reads while the
// process still writes it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// socksUDP is a SOCKS5 UDP association (RFC 1928 §7) through masque-client.
type socksUDP struct {
	control net.Conn
	relay   *net.UDPConn
	to      *net.UDPAddr
}

func dialSocksUDP(t *testing.T, proxy string) *socksUDP {
	t.Helper()
	control, err := net.DialTimeout("tcp", proxy, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { control.Close() })
	_ = control.SetDeadline(time.Now().Add(20 * time.Second))
	// No authentication, then UDP ASSOCIATE from any address.
	if _, err := control.Write([]byte{5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2+10)
	if _, err := io.ReadFull(control, reply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply[:2], []byte{5, 0}) || reply[3] != 0 || reply[5] != 1 {
		t.Fatalf("SOCKS5 UDP ASSOCIATE refused: % x", reply)
	}
	to := &net.UDPAddr{IP: net.IP(reply[6:10]), Port: int(binary.BigEndian.Uint16(reply[10:12]))}
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { relay.Close() })
	_ = control.SetDeadline(time.Time{})
	return &socksUDP{control: control, relay: relay, to: to}
}

// echo sends data to dest port 7 through the tunnel and waits for it back.
func (s *socksUDP) echo(dest netip.Addr, data []byte) error {
	req := []byte{0, 0, 0}
	if dest.Is4() {
		req = append(req, 1)
	} else {
		req = append(req, 4)
	}
	req = append(req, dest.AsSlice()...)
	req = binary.BigEndian.AppendUint16(req, 7)
	header := len(req)
	req = append(req, data...)
	buf := make([]byte, 65536)
	// Datagrams may be lost while the tunnel starts: try a few times.
	for attempt := 0; attempt < 5; attempt++ {
		if _, err := s.relay.WriteToUDP(req, s.to); err != nil {
			return err
		}
		_ = s.relay.SetReadDeadline(time.Now().Add(2 * time.Second))
		for {
			n, err := s.relay.Read(buf)
			if err != nil {
				break
			}
			if n == len(req) && bytes.Equal(buf[:header], req[:header]) && bytes.Equal(buf[header:n], data) {
				return nil
			}
		}
	}
	return fmt.Errorf("no echo from %s with %d bytes", dest, len(data))
}

func TestInteropMasqueClient(t *testing.T) {
	client := os.Getenv("MASQUE_CLIENT")
	if client == "" {
		t.Skip("set MASQUE_CLIENT to masque-vpn's masque-client")
	}
	e := newCaddyEnv(t)
	cert, caPEM := newTestChain(t)
	e.cert = cert
	cfg := masqueConfig("alice")
	cfg["blocked_destinations"] = []string{}
	if err := e.load(cfg); err != nil {
		t.Fatal(err)
	}
	// The network behind the server: an echo server on UDP port 7 at every
	// address.
	go func() {
		for {
			select {
			case p := <-e.dev.toHost:
				if r := reflectUDP(p); r != nil {
					e.dev.fromHost <- r
				}
			case <-e.dev.closed:
				return
			}
		}
	}()
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, []byte(caPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	v4, v6 := netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("2001:db8::7")
	for _, c := range []struct{ name, transport string }{
		{"h3", "h3"}, {"h2", "h2"}, {"http1.1", "http/1.1"},
		// With `http3 off`, Caddy's own HTTP/3 server, which announces no
		// HTTP Datagrams: packets travel in DATAGRAM capsules (RFC 9297
		// §3.5) on the HTTP/3 stream.
		{"h3-capsules", "h3"},
	} {
		transport := c.transport
		t.Run(c.name, func(t *testing.T) {
			if c.name == "h3-capsules" {
				cfg["http3"] = false
				if err := e.load(cfg); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				conn, err := quic.DialAddr(ctx, fmt.Sprintf("127.0.0.1:%d", e.port),
					http3.ConfigureTLSConfig(e.tlsConfig("h3")), &quic.Config{EnableDatagrams: true})
				if err != nil {
					t.Fatal(err)
				}
				cc := (&http3.Transport{EnableDatagrams: true}).NewClientConn(conn)
				<-cc.ReceivedSettings()
				datagrams := cc.Settings().EnableDatagrams
				_ = conn.CloseWithError(0, "")
				if datagrams {
					t.Fatal("Caddy's own HTTP/3 announces HTTP Datagrams")
				}
			}
			socks := fmt.Sprintf("127.0.0.1:%d", freePort(t))
			config := filepath.Join(dir, "client.toml")
			if err := os.WriteFile(config, []byte(fmt.Sprintf(`uri_template = "https://127.0.0.1:%d/.well-known/masque/ip/{target}/{ipproto}/"
server_name = "vpn.test"
ca = %q
username = "alice"
password = %q
transport = %q
mode = "socks"
dns = ["198.51.100.53", "2001:db8::53"]

[socks]
listen = [%q]
`, e.port, caFile, testPassword, transport, socks)), 0o600); err != nil {
				t.Fatal(err)
			}
			var out lockedBuffer
			cmd := exec.Command(client, "--config", config)
			cmd.Env = append(os.Environ(), "RUST_LOG=info")
			cmd.Stdout, cmd.Stderr = &out, &out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			exited := make(chan error, 1)
			go func() { exited <- cmd.Wait() }()
			defer func() {
				_ = cmd.Process.Signal(os.Interrupt)
				select {
				case <-exited:
				case <-time.After(5 * time.Second):
					_ = cmd.Process.Kill()
					<-exited
				}
				if t.Failed() {
					t.Logf("masque-client output:\n%s", out.String())
				}
			}()
			deadline := time.After(20 * time.Second)
			want := map[string]string{"h3": "HTTP/3", "h2": "HTTP/2", "http/1.1": "HTTP/1.1"}[transport]
			for !strings.Contains(out.String(), "tunnel up") {
				select {
				case err := <-exited:
					exited <- err // for the deferred cleanup
					t.Fatalf("masque-client exited: %v", err)
				case <-deadline:
					t.Fatal("the tunnel did not come up")
				case <-time.After(50 * time.Millisecond):
				}
			}
			if !strings.Contains(out.String(), `transport="`+want+`"`) {
				t.Fatalf("not over %s", want)
			}
			udp := dialSocksUDP(t, socks)
			// Small packets, and the largest the client's stack sends: 1280
			// bytes in IPv4 and IPv6 alike, the minimum IPv6 link MTU.
			for _, c := range []struct {
				dest netip.Addr
				size int
			}{{v4, 16}, {v6, 16}, {v4, 1280 - 28}, {v6, 1280 - 48}} {
				data := make([]byte, c.size)
				_, _ = rand.Read(data)
				if err := udp.echo(c.dest, data); err != nil {
					t.Fatal(err)
				}
			}
			// Both sides probe the IPv6 MTU with 1280-byte echo requests
			// (RFC 9484 §7.2) and end the tunnel without a reply within 10
			// seconds; the tunnel must still be the first one after that.
			time.Sleep(12 * time.Second)
			if err := udp.echo(v6, []byte("still up")); err != nil {
				t.Fatal(err)
			}
			if n := strings.Count(out.String(), "tunnel up"); n != 1 {
				t.Fatalf("the tunnel came up %d times", n)
			}
			for _, bad := range []string{"session failed", "aborted", "reconnecting"} {
				if strings.Contains(out.String(), bad) {
					t.Fatalf("the client logged %q", bad)
				}
			}
		})
	}
}
