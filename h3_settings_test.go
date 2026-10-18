package masque

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/ArcCal/caddy-masque/internal/proto"
	"github.com/ArcCal/caddy-masque/internal/routes"
)

// SETTINGS and requests use independent QUIC streams. A control stream
// delayed past the former three-second fallback must still negotiate a
// working Datagram tunnel, with the same behavior as immediate SETTINGS.
func TestHTTP3DelayedSettings(t *testing.T) {
	for _, delayed := range []bool{false, true} {
		t.Run(fmt.Sprintf("delayed=%v", delayed), func(t *testing.T) {
			e := newCaddyEnv(t)
			if err := e.load(h3SettingsConfig("alice")); err != nil {
				t.Fatal(err)
			}
			p := newH3SettingsPeer(t, e, !delayed, anyTarget)
			result := make(chan h3SettingsResponse, 1)
			go func() {
				h, err := h3SettingsReadHeaders(p.stream)
				result <- h3SettingsResponse{h, err}
			}()
			if delayed {
				h3SettingsPendingLease(t)
				// Admission counts pending requests: they cannot reserve an
				// unlimited number of addresses while withholding SETTINGS.
				limited := e.dialH3(t, testPassword, anyTarget)
				if limited.status != http.StatusTooManyRequests || limited.header.Get("Capsule-Protocol") != "" {
					t.Fatalf("pending lease quota: status %d, headers %v", limited.status, limited.header)
				}
				limited.close()
				// An unchanged reload must not cancel a pending request.
				if err := e.load(h3SettingsConfig("alice")); err != nil {
					t.Fatal(err)
				}
				select {
				case early := <-result:
					t.Fatalf("response before peer SETTINGS: %v, %v", early.header, early.err)
				case <-time.After(3100 * time.Millisecond):
				}
				p.settings(t)
			}
			response := <-result
			if response.err != nil || response.header[":status"] != "200" || response.header["capsule-protocol"] != "?1" {
				t.Fatalf("response: %v, %v", response.header, response.err)
			}
			reader := newCapsuleReader(&h3SettingsBodyReader{stream: p.stream})
			cap, err := reader.next()
			assigned, ok := cap.(proto.AddressAssign)
			if err != nil || !ok || len(assigned) != 1 {
				t.Fatalf("assignment: %v, %v", cap, err)
			}
			if cap, err := reader.next(); err != nil {
				t.Fatal(err)
			} else if routes, ok := cap.(proto.RouteAdvertisement); !ok || len(routes) == 0 {
				t.Fatalf("route advertisement: %v", cap)
			}
			addr := assigned[0].Prefix.Addr().String()
			out := udp(addr, "1.1.1.1", 10)
			wire := quicvarint.Append(nil, uint64(p.stream.StreamID()/4))
			wire = append(wire, 0) // CONNECT-IP context ID
			if err := p.conn.SendDatagram(append(wire, out...)); err != nil {
				t.Fatal(err)
			}
			if got := hostPacket(t, e.dev); !slices.Equal(got, out) {
				t.Fatal("outgoing QUIC Datagram changed")
			}
			back := udp("1.1.1.1", addr, 20)
			e.dev.fromHost <- back
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got, err := p.conn.ReceiveDatagram(ctx)
			if err != nil || !slices.Equal(got, append(wire, back...)) {
				t.Fatalf("incoming QUIC Datagram: %x, %v", got, err)
			}
		})
	}
}

func TestHTTP3PendingSettingsCancellation(t *testing.T) {
	for _, reason := range []string{"request canceled", "user revoked", "core stopped"} {
		t.Run(reason, func(t *testing.T) {
			e := newCaddyEnv(t)
			if err := e.load(h3SettingsConfig("alice")); err != nil {
				t.Fatal(err)
			}
			p := newH3SettingsPeer(t, e, false, anyTarget)
			c, addr := h3SettingsPendingLease(t)
			switch reason {
			case "request canceled":
				p.stream.CancelRead(h3RequestCancelled)
				p.stream.CancelWrite(h3RequestCancelled)
			case "user revoked":
				if err := e.load(h3SettingsConfig("bob")); err != nil {
					t.Fatal(err)
				}
			case "core stopped":
				// This is the same cancellation performed by the stopping
				// event before Caddy starts shutting down its HTTP servers.
				c.shutdown("server shutting down")
			}
			if reason != "request canceled" {
				h, err := h3SettingsReadHeaders(p.stream)
				if err != nil || h[":status"] != "503" || h["capsule-protocol"] != "" {
					t.Fatalf("pending refusal: %v, %v; want 503 without success headers", h, err)
				}
			}
			h3SettingsLeaseReleased(t, c, addr)
			if reason == "core stopped" {
				return
			}
			if reason == "user revoked" {
				if err := e.load(h3SettingsConfig("alice")); err != nil {
					t.Fatal(err)
				}
			}
			// The canceled request must release the one-session admission
			// slot; an ordinary client with SETTINGS can connect afterward.
			fresh := e.dialH3(t, testPassword, anyTarget)
			defer fresh.close()
			if fresh.status != http.StatusOK {
				t.Fatalf("fresh request after pending cancellation: %d", fresh.status)
			}
		})
	}
}

func TestHTTP3PendingSettingsScopeWithdrawal(t *testing.T) {
	e := newCaddyEnv(t)
	if err := e.load(h3SettingsConfig("alice")); err != nil {
		t.Fatal(err)
	}
	const target = "/.well-known/masque/ip/1.1.1.1/*/"
	p := newH3SettingsPeer(t, e, false, target)
	c, addr := h3SettingsPendingLease(t)
	cfg := h3SettingsConfig("alice")
	cfg["blocked_destinations"] = append(slices.Clone(routes.DefaultBlocked), "1.1.1.1/32")
	if err := e.load(cfg); err != nil {
		t.Fatal(err)
	}
	h, err := h3SettingsReadHeaders(p.stream)
	if err != nil || h[":status"] != "503" || h["capsule-protocol"] != "" {
		t.Fatalf("scope withdrawal while pending: %v, %v; want 503 without success headers", h, err)
	}
	h3SettingsLeaseReleased(t, c, addr)
	// Retrying the withdrawn scope must enforce the newly committed policy,
	// while a permitted target can still use the released session slot.
	refused := e.dialH3(t, testPassword, target)
	defer refused.close()
	if refused.status != http.StatusForbidden || refused.header.Get("Capsule-Protocol") != "" {
		t.Fatalf("withdrawn scope after reconnect: status %d, headers %v", refused.status, refused.header)
	}
	fresh := e.dialH3(t, testPassword, anyTarget)
	defer fresh.close()
	if fresh.status != http.StatusOK {
		t.Fatalf("allowed scope after pending withdrawal: %d", fresh.status)
	}
}

func h3SettingsConfig(user string) map[string]any {
	cfg := masqueConfig(user)
	delete(cfg, "ipv6")
	cfg["max_sessions"] = 1
	return cfg
}

type h3SettingsPeer struct {
	conn   *quic.Conn
	stream *quic.Stream
	ctrl   *quic.SendStream
}

func newH3SettingsPeer(t *testing.T, e *caddyEnv, settings bool, path string) *h3SettingsPeer {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	conn, err := quic.DialAddr(ctx, fmt.Sprintf("127.0.0.1:%d", e.port), e.tlsConfig("h3"), &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.CloseWithError(0, "test deadline") })
	t.Cleanup(func() { stop(); _ = conn.CloseWithError(0, "") })
	ctrl, err := conn.OpenUniStream()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ctrl.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	// Observe the server's SETTINGS before using extended CONNECT. Only
	// the client's control-stream delivery is withheld in this test.
	serverCtrl, err := conn.AcceptUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	vr := quicvarint.NewReader(serverCtrl)
	if typ, err := quicvarint.Read(vr); err != nil || typ != 0 {
		t.Fatalf("server control-stream type: %d, %v", typ, err)
	}
	if typ, err := quicvarint.Read(vr); err != nil || typ != 4 {
		t.Fatalf("server SETTINGS type: %d, %v", typ, err)
	}
	n, err := quicvarint.Read(vr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(io.Discard, vr, int64(n)); err != nil {
		t.Fatal(err)
	}
	p := &h3SettingsPeer{conn: conn, ctrl: ctrl}
	if settings {
		p.settings(t)
	}
	p.stream, err = conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = p.stream.SetDeadline(time.Now().Add(9 * time.Second))
	var block bytes.Buffer
	encoder := qpack.NewEncoder(&block)
	for _, hf := range []qpack.HeaderField{
		{Name: ":method", Value: "CONNECT"}, {Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "vpn.test"}, {Name: ":path", Value: path},
		{Name: ":protocol", Value: "connect-ip"}, {Name: "authorization", Value: authorization(testPassword)},
	} {
		if err := encoder.WriteField(hf); err != nil {
			t.Fatal(err)
		}
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	frame := quicvarint.Append(quicvarint.Append(nil, 1), uint64(block.Len()))
	if _, err := p.stream.Write(append(frame, block.Bytes()...)); err != nil {
		t.Fatal(err)
	}
	return p
}

func (p *h3SettingsPeer) settings(t *testing.T) {
	t.Helper()
	// SETTINGS_H3_DATAGRAM=1. The control-stream type was already sent.
	if _, err := p.ctrl.Write([]byte{4, 2, 0x33, 1}); err != nil {
		t.Fatal(err)
	}
}

type h3SettingsResponse struct {
	header map[string]string
	err    error
}

func h3SettingsReadHeaders(stream *quic.Stream) (map[string]string, error) {
	vr := quicvarint.NewReader(stream)
	typ, err := quicvarint.Read(vr)
	if err != nil {
		return nil, err
	}
	if typ != 1 {
		return nil, fmt.Errorf("expected HEADERS, got frame %d", typ)
	}
	n, err := quicvarint.Read(vr)
	if err != nil {
		return nil, err
	}
	block := make([]byte, n)
	if _, err := io.ReadFull(vr, block); err != nil {
		return nil, err
	}
	headers := map[string]string{}
	decode := qpack.NewDecoder().Decode(block)
	for {
		hf, err := decode()
		if errors.Is(err, io.EOF) {
			return headers, nil
		}
		if err != nil {
			return nil, err
		}
		headers[hf.Name] = hf.Value
	}
}

type h3SettingsBodyReader struct {
	stream    *quic.Stream
	remaining uint64
}

func (r *h3SettingsBodyReader) Read(p []byte) (int, error) {
	for r.remaining == 0 {
		vr := quicvarint.NewReader(r.stream)
		typ, err := quicvarint.Read(vr)
		if err != nil {
			return 0, err
		}
		if typ != 0 {
			return 0, fmt.Errorf("expected DATA, got frame %d", typ)
		}
		r.remaining, err = quicvarint.Read(vr)
		if err != nil {
			return 0, err
		}
	}
	n, err := r.stream.Read(p[:min(uint64(len(p)), r.remaining)])
	r.remaining -= uint64(n)
	return n, err
}

func h3SettingsPendingLease(t *testing.T) (*core, netip.Addr) {
	t.Helper()
	app, err := caddy.ActiveContext().AppIfConfigured("masque")
	if err != nil {
		t.Fatal(err)
	}
	c := app.(*App).core
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		c.sessMu.RLock()
		var addr netip.Addr
		for a := range c.sessions {
			addr = a
		}
		c.sessMu.RUnlock()
		if addr.IsValid() {
			return c, addr
		}
	}
	t.Fatal("pending request did not acquire a lease")
	return nil, netip.Addr{}
}

func h3SettingsLeaseReleased(t *testing.T, c *core, addr netip.Addr) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		c.sessMu.RLock()
		count := len(c.sessions)
		c.sessMu.RUnlock()
		if count != 0 {
			continue
		}
		c.poolMu.Lock()
		free := c.pool.Claim(addr)
		if free {
			c.pool.Release(addr)
		}
		c.poolMu.Unlock()
		if free {
			return
		}
	}
	t.Fatal("pending request kept its session slot or pool address")
}
