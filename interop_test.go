package masque

// Interoperability with connect-ip-go, the CONNECT-IP implementation of
// the quic-go project, as an independent client: it parses every capsule
// our server sends with its own code and checks the packets it receives
// against the addresses and routes we assigned.

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"testing"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"

	"github.com/ArcCal/caddy-masque/internal/ip"
)

func (e *caddyEnv) dialConnectIPGo(t *testing.T, password, path string) (*connectip.Conn, *http.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	conn, err := quic.DialAddr(ctx, fmt.Sprintf("127.0.0.1:%d", e.port), http3.ConfigureTLSConfig(e.tlsConfig("h3")),
		&quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.CloseWithError(0, "") })
	cc := (&http3.Transport{EnableDatagrams: true}).NewClientConn(conn)
	req, err := connectip.NewRequest(ctx, uritemplate.MustNew(e.url(path)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header().Set("Authorization", authorization(password))
	return connectip.NewClientConn(cc).Dial(req)
}

// readPacket reads the next packet from connect-ip-go, answering the MTU
// probe (RFC 9484 §7.2) as the client's IPv6 stack would.
func readPacket(conn *connectip.Conn, buf []byte) (int, error) {
	for {
		n, err := conn.ReadPacket(buf)
		if err != nil || n != ip.IPv6MinMTU {
			return n, err
		}
		reply := ip.EchoReply(buf[:n])
		if reply == nil {
			return n, nil
		}
		if _, err := conn.WritePacket(reply); err != nil {
			return 0, err
		}
	}
}

func TestInteropConnectIPGo(t *testing.T) {
	e := newCaddyEnv(t)
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	conn, rsp, err := e.dialConnectIPGo(t, testPassword, anyTarget)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if rsp.Header.Get("Capsule-Protocol") != "?1" {
		t.Errorf("Capsule-Protocol %q", rsp.Header.Get("Capsule-Protocol"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	assigned, err := conn.ReceiveAddressAssignment(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(assigned) != 2 || assigned[0].RequestID != 0 || !assigned[0].IPPrefix.Addr().Is4() ||
		!assigned[1].IPPrefix.Addr().Is6() || !assigned[0].IPPrefix.IsSingleIP() {
		t.Fatalf("assigned %+v", assigned)
	}
	v4, v6 := assigned[0].IPPrefix.Addr(), assigned[1].IPPrefix.Addr()
	routes, err := conn.Routes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) == 0 {
		t.Fatal("no routes")
	}
	routed := func(a string) bool {
		x := netip.MustParseAddr(a)
		return slices.ContainsFunc(routes, func(r connectip.IPRoute) bool {
			return r.StartIP.Compare(x) <= 0 && x.Compare(r.EndIP) <= 0
		})
	}
	if !routed("1.1.1.1") || !routed("2606:4700::1111") || routed("10.1.2.3") || routed("fe80::1") {
		t.Errorf("routes %v", routes)
	}

	// Address requests are answered with the request's ID (§4.7.2).
	ids, err := conn.RequestAddresses([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/32"), netip.MustParsePrefix("::/128")})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := conn.ReceiveAddressAssignment(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range ids {
		if !slices.ContainsFunc(reply, func(a connectip.AssignedAddress) bool {
			return a.RequestID == id && a.IPPrefix.Addr() == []netip.Addr{v4, v6}[i]
		}) {
			t.Errorf("request %d not answered: %+v", id, reply)
		}
	}

	// Packets both ways, IPv4 and IPv6.
	for _, c := range []struct{ local, remote string }{{v4.String(), "1.1.1.1"}, {v6.String(), "2606:4700::1111"}} {
		pkt := udp(c.local, c.remote, 100)
		sent := slices.Clone(pkt)
		if icmp, err := conn.WritePacket(pkt); err != nil || icmp != nil {
			t.Fatalf("WritePacket: %v %x", err, icmp)
		}
		got := hostPacket(t, e.dev)
		// connect-ip-go decrements the TTL (and fixes the checksum) itself.
		if len(got) != len(sent) || !slices.Equal(got[20:], sent[20:]) && !slices.Equal(got[40:], sent[40:]) {
			t.Errorf("forwarded % x", got[:40])
		}
		back := udp(c.remote, c.local, 1200)
		e.dev.fromHost <- back
		buf := make([]byte, 2000)
		n, err := readPacket(conn, buf)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(buf[:n], back) {
			t.Errorf("received %d bytes, sent %d", n, len(back))
		}
	}

	// A blocked destination: the ICMP error passes connect-ip-go's checks
	// (from a routed address, to our own).
	if _, err := conn.WritePacket(udp(v4.String(), "10.1.2.3", 10)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2000)
	n, err := readPacket(conn, buf)
	if err != nil {
		t.Fatal(err)
	}
	if n < 28 || buf[9] != 1 || buf[20] != 3 || buf[21] != 13 {
		t.Errorf("expected ICMP administratively prohibited, got % x", buf[:min(n, 28)])
	}
}

func TestInteropConnectIPGoScoped(t *testing.T) {
	e := newCaddyEnv(t)
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	conn, _, err := e.dialConnectIPGo(t, testPassword, "/.well-known/masque/ip/192.0.2.0%2F24/17/")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	assigned, err := conn.ReceiveAddressAssignment(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(assigned) != 1 || !assigned[0].IPPrefix.Addr().Is4() {
		t.Fatalf("an IPv4 scope gets one IPv4 address: %+v", assigned)
	}
	routes, err := conn.Routes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []connectip.IPRoute{{StartIP: netip.MustParseAddr("192.0.2.0"), EndIP: netip.MustParseAddr("192.0.2.255"), IPProtocol: 17}}
	if !slices.Equal(routes, want) {
		t.Errorf("routes %+v, want %+v", routes, want)
	}
	v4 := assigned[0].IPPrefix.Addr().String()
	if _, err := conn.WritePacket(udp(v4, "192.0.2.9", 10)); err != nil {
		t.Fatal(err)
	}
	hostPacket(t, e.dev)
	// Replies from the scope reach connect-ip-go; ICMP is allowed too.
	for _, back := range [][]byte{udp("192.0.2.9", v4, 10), echoRequest("192.0.2.9", v4)} {
		e.dev.fromHost <- back
		buf := make([]byte, 2000)
		n, err := readPacket(conn, buf)
		if err != nil || !slices.Equal(buf[:n], back) {
			t.Errorf("received % x, %v", buf[:n], err)
		}
	}
}

func TestInteropConnectIPGoWrongPassword(t *testing.T) {
	e := newCaddyEnv(t)
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	_, rsp, err := e.dialConnectIPGo(t, "wrong password!!", anyTarget)
	if err != nil {
		t.Log(err)
	}
	if rsp.Header.Get("Capsule-Protocol") != "" {
		t.Error("a refused request got Capsule-Protocol")
	}
}
