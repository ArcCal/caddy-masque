package masque

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap/zaptest"

	"github.com/ArcCal/caddy-masque/internal/auth"
	"github.com/ArcCal/caddy-masque/internal/ip"
	"github.com/ArcCal/caddy-masque/internal/proto"
	"github.com/ArcCal/caddy-masque/internal/routes"
)

// fakeDevice stands in for the TUN device.
type fakeDevice struct {
	toHost   chan []byte // written by the core
	fromHost chan []byte // read by the core
	closed   chan struct{}
	once     sync.Once
}

func newFakeDevice() *fakeDevice {
	return &fakeDevice{toHost: make(chan []byte, 100), fromHost: make(chan []byte, 100), closed: make(chan struct{})}
}

func (d *fakeDevice) Read(b []byte) (int, error) {
	select {
	case p := <-d.fromHost:
		return copy(b, p), nil
	case <-d.closed:
		return 0, io.EOF
	}
}

func (d *fakeDevice) Write(b []byte) (int, error) {
	d.toHost <- slices.Clone(b)
	return len(b), nil
}

func (d *fakeDevice) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

// fakeTunnel stands in for a request stream.
type fakeTunnel struct {
	capsules  chan proto.Capsule // from the client; closed: the client finished
	errs      chan error
	datagrams chan []byte // QUIC datagrams from the client
	quic      bool
	// The largest datagram payload the QUIC path takes (0: any).
	maxDatagram atomic.Int64
	// The client's IPv6 stack answers the MTU probe unless this is set.
	ignoreProbes atomic.Bool
	out          chan any // capsules and datagrams (sentDatagram) to the client
	aborted      atomic.Bool
	closed       atomic.Bool
	done         chan struct{} // closed by abort and close
	doneOnce     sync.Once
	// Writes fail from this one on (1: the first; 0: none).
	failFrom int
	writes   atomic.Int32
	// Writes block until the stream is stopped, as for a client that
	// stopped reading; each one that blocks is reported on stalls.
	stalled atomic.Bool
	stalls  chan struct{}
}

type sentDatagram []byte

func newFakeTunnel(quicDatagrams bool) *fakeTunnel {
	return &fakeTunnel{capsules: make(chan proto.Capsule, 10), errs: make(chan error, 1), datagrams: make(chan []byte, 10),
		quic: quicDatagrams, out: make(chan any, 100), done: make(chan struct{}), stalls: make(chan struct{}, 10)}
}

func (t *fakeTunnel) readCapsule() (proto.Capsule, error) {
	select {
	case c, ok := <-t.capsules:
		if !ok {
			return nil, io.EOF
		}
		return c, nil
	case err := <-t.errs:
		return nil, err
	case <-t.done:
		return nil, errors.New("stream closed")
	}
}

func (t *fakeTunnel) writeCapsule(c proto.Capsule) error {
	if t.stalled.Load() {
		select {
		case t.stalls <- struct{}{}:
		default:
		}
		<-t.done
		return errors.New("stream closed")
	}
	if n := int(t.writes.Add(1)); t.failFrom > 0 && n >= t.failFrom {
		return errors.New("write failed")
	}
	// What the client gets is what it decodes from the wire.
	d := proto.NewDecoder(proto.DefaultMaxValueLen)
	d.Push(proto.Append(nil, c))
	raw, err := d.Next()
	if err != nil {
		return err
	}
	decoded, err := proto.Decode(raw)
	if err != nil {
		return err
	}
	t.out <- decoded
	return nil
}

func (t *fakeTunnel) sendDatagram(p []byte) error {
	if !t.quic {
		return t.writeCapsule(proto.Datagram(p))
	}
	if max := t.maxDatagram.Load(); max > 0 && int64(len(p)) > max {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: max}
	}
	// The MTU probe, a 1280-byte ICMPv6 echo request, is answered as the
	// client's IPv6 stack would.
	if len(p) == 1+ip.IPv6MinMTU && !t.ignoreProbes.Load() {
		if reply := ip.EchoReply(p[1:]); reply != nil {
			select {
			case t.datagrams <- append([]byte{0}, reply...):
			default: // lost
			}
			return nil
		}
	}
	t.out <- sentDatagram(slices.Clone(p))
	return nil
}

func (t *fakeTunnel) receiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case p := <-t.datagrams:
		return p, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *fakeTunnel) hasQUICDatagrams() bool { return t.quic }
func (t *fakeTunnel) stop(abort bool) {
	if abort {
		t.aborted.Store(true)
	}
	t.doneOnce.Do(func() { close(t.done) })
}

func (t *fakeTunnel) force() {}

func (t *fakeTunnel) finish(abort bool) {
	if !abort {
		t.closed.Store(true)
	}
}

// next returns what the session sent the client next.
func (t *fakeTunnel) next(tb testing.TB) any {
	tb.Helper()
	select {
	case v := <-t.out:
		return v
	case <-time.After(2 * time.Second):
		tb.Fatal("nothing sent to the client")
		return nil
	}
}

// nextPacket returns the next IP packet sent to the client, checking its
// context ID.
func (t *fakeTunnel) nextPacket(tb testing.TB) []byte {
	tb.Helper()
	var payload []byte
	switch v := t.next(tb).(type) {
	case sentDatagram:
		payload = v
	case proto.Datagram:
		payload = v
	default:
		tb.Fatalf("expected a datagram, got %T", v)
	}
	id, pkt, err := proto.SplitContextID(payload)
	if err != nil || id != proto.ContextIDIPPacket {
		tb.Fatalf("context ID %d, %v", id, err)
	}
	return pkt
}

func (t *fakeTunnel) quiet(tb testing.TB) {
	tb.Helper()
	select {
	case v := <-t.out:
		tb.Fatalf("unexpected %T sent to the client", v)
	case <-time.After(100 * time.Millisecond):
	}
}

func hostPacket(tb testing.TB, d *fakeDevice) []byte {
	tb.Helper()
	select {
	case p := <-d.toHost:
		return p
	case <-time.After(2 * time.Second):
		tb.Fatal("nothing written to the network")
		return nil
	}
}

func noHostPacket(tb testing.TB, d *fakeDevice) {
	tb.Helper()
	select {
	case p := <-d.toHost:
		tb.Fatalf("unexpected packet to the network: % x", p[:min(len(p), 40)])
	case <-time.After(100 * time.Millisecond):
	}
}

// udp builds an IPv4 or IPv6 UDP packet with n bytes of payload.
func udp(src, dst string, n int) []byte {
	return packet(src, dst, ip.ProtoUDP, make([]byte, 8+n))
}

func packet(src, dst string, protocol uint8, payload []byte) []byte {
	s, d := netip.MustParseAddr(src), netip.MustParseAddr(dst)
	if s.Is4() {
		p := make([]byte, 20+len(payload))
		p[0] = 0x45
		binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
		p[8] = 64
		p[9] = protocol
		copy(p[12:], s.AsSlice())
		copy(p[16:], d.AsSlice())
		binary.BigEndian.PutUint16(p[10:], ip.Checksum(p[:20]))
		copy(p[20:], payload)
		return p
	}
	p := make([]byte, 40+len(payload))
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:], uint16(len(payload)))
	p[6] = protocol
	p[7] = 64
	copy(p[8:], s.AsSlice())
	copy(p[24:], d.AsSlice())
	copy(p[40:], payload)
	return p
}

func echoRequest(src, dst string) []byte {
	if netip.MustParseAddr(src).Is4() {
		return packet(src, dst, ip.ProtoICMP, []byte{8, 0, 0, 0, 0, 1, 0, 1})
	}
	return packet(src, dst, ip.ProtoICMPv6, []byte{128, 0, 0, 0, 0, 1, 0, 1})
}

type testEnv struct {
	core   *core
	dev    *fakeDevice
	app    *App
	forget struct {
		sync.Mutex
		calls [][]netip.Prefix
		err   error
	}
}

var (
	alice = auth.User{Name: "alice", Hash: "hash-a"}
	bob   = auth.User{Name: "bob", Hash: "hash-b"}
)

// newTestEnv makes a core with a fake device, configured as the app would
// from these settings.
func newTestEnv(tb testing.TB, app *App) *testEnv {
	tb.Helper()
	if app.IPv4 == "" {
		app.IPv4 = "10.89.0.1/24"
	}
	if err := app.parse(); err != nil {
		tb.Fatal(err)
	}
	c, err := newCore(app.cfg, zaptest.NewLogger(tb))
	if err != nil {
		tb.Fatal(err)
	}
	e := &testEnv{core: c, dev: newFakeDevice(), app: app}
	c.forget = func(p []netip.Prefix) (int, error) {
		e.forget.Lock()
		defer e.forget.Unlock()
		e.forget.calls = append(e.forget.calls, p)
		return len(p), e.forget.err
	}
	c.attach(e.dev)
	c.allowed.Store(&app.allowed)
	c.setUsers(map[string]string{alice.Name: alice.Hash, bob.Name: bob.Hash})
	tb.Cleanup(func() { _ = c.Destruct() })
	return e
}

func (e *testEnv) forgetCalls() [][]netip.Prefix {
	e.forget.Lock()
	defer e.forget.Unlock()
	return slices.Clone(e.forget.calls)
}

type running struct {
	tun   *fakeTunnel
	lease *lease
	s     *session
	ended chan string
}

// start runs a session for a user with the full scope.
func (e *testEnv) start(tb testing.TB, user auth.User, quicDatagrams bool) *running {
	tb.Helper()
	return e.startScoped(tb, user, quicDatagrams, newScope(*e.core.allowed.Load(), anyDestination, 0))
}

func (e *testEnv) startScoped(tb testing.TB, user auth.User, quicDatagrams bool, sc scope) *running {
	tb.Helper()
	return e.startOn(tb, user, newFakeTunnel(quicDatagrams), sc)
}

// startOn runs a session on a tunnel set up beforehand.
func (e *testEnv) startOn(tb testing.TB, user auth.User, tun *fakeTunnel, sc scope) *running {
	tb.Helper()
	l := e.core.acquire(context.Background(), user, sc.routes.HasIPv4(), sc.routes.HasIPv6())
	if l == nil {
		tb.Fatal("no lease")
	}
	r := &running{tun: tun, lease: l, ended: make(chan string, 1)}
	r.s = newSession(e.core, l, sc, r.tun, zaptest.NewLogger(tb))
	go func() {
		why := r.s.run(context.Background())
		l.release()
		r.ended <- why
	}()
	tb.Cleanup(func() {
		close(r.tun.capsules)
		<-r.ended
	})
	// The opening capsules.
	if _, ok := r.tun.next(tb).(proto.AddressAssign); !ok {
		tb.Fatal("the first capsule is not ADDRESS_ASSIGN")
	}
	if _, ok := r.tun.next(tb).(proto.RouteAdvertisement); !ok {
		tb.Fatal("the second capsule is not ROUTE_ADVERTISEMENT")
	}
	return r
}

func (r *running) addr(v6 bool) string {
	for _, a := range r.lease.addrs {
		if a.Is6() == v6 {
			return a.String()
		}
	}
	panic("no address of the family")
}

func (r *running) waitEnd(tb testing.TB) string {
	tb.Helper()
	select {
	case why := <-r.ended:
		r.ended <- why // for the cleanup
		return why
	case <-time.After(2 * time.Second):
		tb.Fatal("the session did not end")
		return ""
	}
}

func dualStack() *App { return &App{IPv4: "10.89.0.1/24", IPv6: "fd89::1/64"} }

func TestSessionOpensWithAddressesAndRoutes(t *testing.T) {
	e := newTestEnv(t, dualStack())
	l := e.core.acquire(context.Background(), alice, true, true)
	tun := newFakeTunnel(true)
	s := newSession(e.core, l, newScope(*e.core.allowed.Load(), anyDestination, 0), tun, zaptest.NewLogger(t))
	done := make(chan string)
	go func() { done <- s.run(context.Background()) }()

	assign, ok := tun.next(t).(proto.AddressAssign)
	if !ok || len(assign) != 2 {
		t.Fatalf("ADDRESS_ASSIGN: %v", assign)
	}
	for i, want := range []string{"10.89.0.1/24", "fd89::1/64"} {
		if assign[i].RequestID != 0 || !assign[i].Prefix.IsSingleIP() {
			t.Errorf("entry %d: %+v", i, assign[i])
		}
		if a := assign[i].Prefix.Addr(); !netip.MustParsePrefix(want).Contains(a) || a == netip.MustParseAddr(want[:len(want)-3]) {
			t.Errorf("address %s is not a client address of %s", a, want)
		}
	}
	adv, ok := tun.next(t).(proto.RouteAdvertisement)
	if !ok {
		t.Fatal("no ROUTE_ADVERTISEMENT")
	}
	if err := proto.ValidateRoutes(adv); err != nil {
		t.Fatal(err)
	}
	covers := func(a string) bool {
		x := netip.MustParseAddr(a)
		for _, r := range adv {
			if r.Protocol == 0 && r.Start.Compare(x) <= 0 && x.Compare(r.End) <= 0 {
				return true
			}
		}
		return false
	}
	for _, a := range []string{"1.1.1.1", "10.89.0.1", "2606:4700::1111", "fd89::1"} {
		if !covers(a) {
			t.Errorf("%s not advertised", a)
		}
	}
	for _, a := range []string{"10.1.2.3", "10.89.0.3", "192.168.1.1", "fd89::2", "fe80::1", "169.254.169.254"} {
		if covers(a) {
			t.Errorf("%s advertised", a)
		}
	}
	close(tun.capsules)
	if why := <-done; why != "client closed the tunnel" {
		t.Errorf("ended: %s", why)
	}
	if !tun.closed.Load() || tun.aborted.Load() {
		t.Error("a finished stream is closed, not aborted")
	}
	l.release()
}

func TestClientPacketsReachTheNetwork(t *testing.T) {
	for _, quicDatagrams := range []bool{true, false} {
		e := newTestEnv(t, dualStack())
		r := e.start(t, alice, quicDatagrams)
		for _, v6 := range []bool{false, true} {
			dst := map[bool]string{false: "1.1.1.1", true: "2606:4700::1111"}[v6]
			pkt := udp(r.addr(v6), dst, 100)
			// Bytes past the packet's own length are not forwarded.
			payload := append(append([]byte{0}, pkt...), 0xde, 0xad)
			if quicDatagrams {
				r.tun.datagrams <- payload
			} else {
				r.tun.capsules <- proto.Datagram(payload)
			}
			if got := hostPacket(t, e.dev); !slices.Equal(got, pkt) {
				t.Errorf("quic=%v v6=%v: forwarded % x", quicDatagrams, v6, got[:20])
			}
		}
		if n := r.s.stats.fromClient.Load(); n != 2 {
			t.Errorf("%d packets counted", n)
		}
	}
}

func TestClientPacketsThatAreDropped(t *testing.T) {
	e := newTestEnv(t, dualStack())
	r := e.start(t, alice, true)
	other := e.start(t, bob, true)
	for name, payload := range map[string][]byte{
		"spoofed IPv4 source":        append([]byte{0}, udp("10.89.0.200", "1.1.1.1", 10)...),
		"another client's source":    append([]byte{0}, udp(other.addr(false), "1.1.1.1", 10)...),
		"spoofed IPv6 source":        append([]byte{0}, udp("2001:db8::1", "2606:4700::1111", 10)...),
		"unknown context ID":         append([]byte{2}, udp(r.addr(false), "1.1.1.1", 10)...),
		"empty datagram":             {},
		"not an IP packet":           {0, 0x45, 1, 2},
		"truncated IPv4 packet":      append([]byte{0}, udp(r.addr(false), "1.1.1.1", 10)[:24]...),
		"IPv4 packet on IPv6 header": append([]byte{0, 0x60}, udp(r.addr(false), "1.1.1.1", 10)[1:]...),
	} {
		before := r.s.stats.dropped.Load()
		r.tun.datagrams <- payload
		noHostPacket(t, e.dev)
		r.tun.quiet(t)
		if r.s.stats.dropped.Load() != before+1 {
			t.Errorf("%s: not counted as dropped", name)
		}
	}
	select {
	case why := <-r.ended:
		t.Fatalf("the session ended: %s", why)
	default:
	}
}

func TestBlockedDestinationsGetAdministrativelyProhibited(t *testing.T) {
	e := newTestEnv(t, dualStack())
	r := e.start(t, alice, true)
	other := e.start(t, bob, true)
	for _, c := range []struct {
		dst         string
		gateway     string
		typ, code   byte
		v6          bool
		description string
	}{
		{"10.1.2.3", "10.89.0.1", 3, 13, false, "private IPv4"},
		{"169.254.169.254", "10.89.0.1", 3, 13, false, "metadata service"},
		{other.addr(false), "10.89.0.1", 3, 13, false, "another client"},
		{"fd00::1", "fd89::1", 1, 1, true, "unique local IPv6"},
		{"fe80::1", "fd89::1", 1, 1, true, "link-local IPv6"},
		{other.addr(true), "fd89::1", 1, 1, true, "another client over IPv6"},
	} {
		pkt := udp(r.addr(c.v6), c.dst, 10)
		r.tun.datagrams <- append([]byte{0}, pkt...)
		noHostPacket(t, e.dev)
		reply := r.tun.nextPacket(t)
		h, ok := ip.Parse(reply)
		if !ok || h.Src.String() != c.gateway || h.Dst.String() != r.addr(c.v6) {
			t.Fatalf("%s: reply %+v", c.description, h)
		}
		if reply[h.PayloadOffset] != c.typ || reply[h.PayloadOffset+1] != c.code {
			t.Errorf("%s: ICMP type %d code %d", c.description, reply[h.PayloadOffset], reply[h.PayloadOffset+1])
		}
	}
	// The tunnel gateway itself is reachable.
	r.tun.datagrams <- append([]byte{0}, echoRequest(r.addr(false), "10.89.0.1")...)
	hostPacket(t, e.dev)
}

func TestClientToClientWhenAllowed(t *testing.T) {
	e := newTestEnv(t, &App{IPv4: "10.89.0.1/24", AllowClientToClient: true})
	r := e.start(t, alice, true)
	other := e.start(t, bob, true)
	pkt := udp(r.addr(false), other.addr(false), 10)
	r.tun.datagrams <- append([]byte{0}, pkt...)
	// The kernel routes it back into the TUN device.
	e.dev.fromHost <- hostPacket(t, e.dev)
	if got := other.tun.nextPacket(t); !slices.Equal(got, pkt) {
		t.Error("the other client got something else")
	}
}

func TestScopedProtocol(t *testing.T) {
	e := newTestEnv(t, dualStack())
	sc := newScope(*e.core.allowed.Load(), []netip.Prefix{netip.MustParsePrefix("192.0.2.80/32")}, ip.ProtoTCP)
	r := e.startScoped(t, alice, true, sc)
	if len(r.lease.addrs) != 1 || !r.lease.addrs[0].Is4() {
		t.Fatalf("an IPv4-only scope gets IPv4 only: %v", r.lease.addrs)
	}
	src := r.addr(false)
	r.tun.datagrams <- append([]byte{0}, packet(src, "192.0.2.80", ip.ProtoTCP, make([]byte, 20))...)
	hostPacket(t, e.dev)
	// ICMP is allowed to the scope's destinations whatever the protocol.
	r.tun.datagrams <- append([]byte{0}, echoRequest(src, "192.0.2.80")...)
	hostPacket(t, e.dev)
	for _, pkt := range [][]byte{udp(src, "192.0.2.80", 10), packet(src, "192.0.2.81", ip.ProtoTCP, make([]byte, 20))} {
		r.tun.datagrams <- append([]byte{0}, pkt...)
		noHostPacket(t, e.dev)
		reply := r.tun.nextPacket(t)
		h, _ := ip.Parse(reply)
		if reply[h.PayloadOffset] != 3 || reply[h.PayloadOffset+1] != 13 {
			t.Error("no administratively prohibited")
		}
	}
}

// fragment6 is an IPv6 fragment: a Fragment header with the offset (in
// 8-byte units), more flag, identification and next header, then data.
func fragment6(src, dst string, id uint32, offset uint16, more bool, next byte, data []byte) []byte {
	frag := make([]byte, 8)
	frag[0] = next
	v := offset << 3
	if more {
		v |= 1
	}
	binary.BigEndian.PutUint16(frag[2:], v)
	binary.BigEndian.PutUint32(frag[4:], id)
	return packet(src, dst, 44, append(frag, data...))
}

// With Destination Options after the Fragment header, a later fragment
// names those, not the upper layer; a session scoped to a protocol takes
// the first fragment's (RFC 9484 §4.8).
func TestScopedProtocolIPv6Fragments(t *testing.T) {
	const dst = "2001:db8::80"
	first := func(src string, id uint32) []byte {
		dstOpts := []byte{ip.ProtoTCP, 0, 1, 4, 0, 0, 0, 0}
		return fragment6(src, dst, id, 0, true, 60, append(dstOpts, make([]byte, 24)...))
	}
	later := func(src string, id uint32) []byte { return fragment6(src, dst, id, 4, false, 60, make([]byte, 16)) }
	for _, protocol := range []uint8{ip.ProtoTCP, ip.ProtoUDP} {
		e := newTestEnv(t, dualStack())
		sc := newScope(*e.core.allowed.Load(), []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")}, protocol)
		r := e.startScoped(t, alice, true, sc)
		src := r.addr(true)
		for _, pkt := range [][]byte{first(src, 7), later(src, 7)} {
			r.tun.datagrams <- append([]byte{0}, pkt...)
			if protocol == ip.ProtoTCP {
				hostPacket(t, e.dev)
			} else {
				noHostPacket(t, e.dev)
			}
		}
		// A later fragment without its first: the protocol is unknown.
		r.tun.datagrams <- append([]byte{0}, later(src, 8)...)
		noHostPacket(t, e.dev)
	}
}

func TestNetworkPacketsReachTheirClient(t *testing.T) {
	for _, quicDatagrams := range []bool{true, false} {
		e := newTestEnv(t, dualStack())
		r := e.start(t, alice, quicDatagrams)
		other := e.start(t, bob, quicDatagrams)
		for _, v6 := range []bool{false, true} {
			src := map[bool]string{false: "1.1.1.1", true: "2606:4700::1111"}[v6]
			pkt := udp(src, r.addr(v6), 1200)
			// Bytes the device read past the packet are not sent.
			e.dev.fromHost <- append(slices.Clone(pkt), 1, 2, 3)
			if got := r.tun.nextPacket(t); !slices.Equal(got, pkt) {
				t.Errorf("quic=%v v6=%v: got %d bytes", quicDatagrams, v6, len(got))
			}
		}
		other.tun.quiet(t)
		// Nobody's address: dropped.
		e.dev.fromHost <- udp("1.1.1.1", "10.89.0.250", 10)
		r.tun.quiet(t)
		other.tun.quiet(t)
	}
}

func TestAddressRequestsAreAnswered(t *testing.T) {
	e := newTestEnv(t, dualStack())
	r := e.start(t, alice, true)
	r.tun.capsules <- proto.AddressRequest{
		{RequestID: 7, Prefix: proto.Unspecified(false)},
		{RequestID: 8, Prefix: proto.Unspecified(true)},
		{RequestID: 9, Prefix: netip.MustParsePrefix("10.89.0.77/32")},
	}
	reply, ok := r.tun.next(t).(proto.AddressAssign)
	if !ok || len(reply) != 3 {
		t.Fatalf("reply %v", reply)
	}
	want := []proto.AssignedAddress{
		{RequestID: 7, Prefix: proto.Host(netip.MustParseAddr(r.addr(false)))},
		{RequestID: 8, Prefix: proto.Host(netip.MustParseAddr(r.addr(true)))},
		// A specific address is not granted; the client gets its own.
		{RequestID: 9, Prefix: proto.Host(netip.MustParseAddr(r.addr(false)))},
	}
	if !slices.Equal(reply, want) {
		t.Errorf("reply %v, want %v", reply, want)
	}
}

func TestAddressRequestForAFamilyWithoutAddress(t *testing.T) {
	e := newTestEnv(t, &App{IPv4: "10.89.0.1/24"})
	r := e.start(t, alice, true)
	r.tun.capsules <- proto.AddressRequest{{RequestID: 3, Prefix: proto.Unspecified(true)}}
	reply := r.tun.next(t).(proto.AddressAssign)
	// The rejection for the request, then the full set.
	want := proto.AddressAssign{
		{RequestID: 3, Prefix: proto.Unspecified(true)},
		{RequestID: 0, Prefix: proto.Host(netip.MustParseAddr(r.addr(false)))},
	}
	if !slices.Equal(reply, want) {
		t.Errorf("reply %v, want %v", reply, want)
	}
}

func TestIgnoredCapsules(t *testing.T) {
	e := newTestEnv(t, dualStack())
	r := e.start(t, alice, true)
	r.tun.capsules <- proto.Unknown{Type: 0x1234, Value: []byte{1}}
	r.tun.capsules <- proto.AddressAssign{}
	r.tun.capsules <- proto.RouteAdvertisement{}
	r.tun.quiet(t)
	// Still serving.
	r.tun.datagrams <- append([]byte{0}, udp(r.addr(false), "1.1.1.1", 1)...)
	hostPacket(t, e.dev)
}

func TestMalformedCapsulesAbortTheStream(t *testing.T) {
	e := newTestEnv(t, dualStack())
	r := e.start(t, alice, true)
	r.tun.errs <- proto.MalformedError("test")
	if why := r.waitEnd(t); why == "" {
		t.Error("no reason")
	}
	if !r.tun.aborted.Load() {
		t.Error("the stream was not aborted")
	}
}

func TestStreamErrorsEndTheSession(t *testing.T) {
	e := newTestEnv(t, dualStack())
	r := e.start(t, alice, false)
	r.tun.errs <- errors.New("connection reset")
	if why := r.waitEnd(t); why != "connection reset" {
		t.Errorf("ended: %s", why)
	}
	if r.tun.aborted.Load() || !r.tun.closed.Load() {
		t.Error("closed, not aborted")
	}
}

// runSession runs a session for alice without reading the opening
// capsules; it returns why the session ended, or fails after a while.
func (e *testEnv) runSession(tb testing.TB, tun *fakeTunnel) <-chan string {
	tb.Helper()
	l := e.core.acquire(context.Background(), alice, true, true)
	if l == nil {
		tb.Fatal("no lease")
	}
	s := newSession(e.core, l, newScope(*e.core.allowed.Load(), anyDestination, 0), tun, zaptest.NewLogger(tb))
	ended := make(chan string, 1)
	go func() {
		why := s.run(context.Background())
		l.release()
		ended <- why
	}()
	return ended
}

func waitWhy(tb testing.TB, ended <-chan string) string {
	tb.Helper()
	select {
	case why := <-ended:
		return why
	case <-time.After(2 * time.Second):
		tb.Fatal("the session did not end")
		return ""
	}
}

func waitStall(tb testing.TB, tun *fakeTunnel) {
	tb.Helper()
	select {
	case <-tun.stalls:
	case <-time.After(2 * time.Second):
		tb.Fatal("no write blocked")
	}
}

// The opening capsules failing to go out ends the stream like any error.
func TestOpeningWriteErrorsEndTheStream(t *testing.T) {
	for n := 1; n <= 2; n++ {
		e := newTestEnv(t, dualStack())
		tun := newFakeTunnel(true)
		tun.failFrom = n
		if why := waitWhy(t, e.runSession(t, tun)); why != "write failed" {
			t.Errorf("write %d failing: ended: %s", n, why)
		}
		select {
		case <-tun.done:
		default:
			t.Errorf("write %d failing: the stream was not stopped", n)
		}
		if !tun.closed.Load() || tun.aborted.Load() {
			t.Errorf("write %d failing: the stream was not closed", n)
		}
	}
}

// A client that stops reading blocks the capsules the session sends of
// its own accord; removing its user still ends the session.
func TestBlockedWritesDoNotKeepRemovedUsers(t *testing.T) {
	const removed = "user removed or password changed"
	t.Run("opening", func(t *testing.T) {
		e := newTestEnv(t, dualStack())
		tun := newFakeTunnel(true)
		tun.stalled.Store(true)
		ended := e.runSession(t, tun)
		waitStall(t, tun)
		e.core.setUsers(map[string]string{bob.Name: bob.Hash})
		if why := waitWhy(t, ended); why != removed {
			t.Errorf("ended: %s", why)
		}
	})
	t.Run("more routes", func(t *testing.T) {
		e := newTestEnv(t, dualStack())
		r := e.start(t, alice, true)
		r.tun.stalled.Store(true)
		more := dualStack()
		more.AllowClientToClient = true
		if err := more.parse(); err != nil {
			t.Fatal(err)
		}
		e.core.setAllowed(more.allowed)
		waitStall(t, r.tun)
		e.core.setUsers(map[string]string{bob.Name: bob.Hash})
		if why := r.waitEnd(t); why != removed {
			t.Errorf("ended: %s", why)
		}
	})
}

func TestTooLargeForTheQUICPath(t *testing.T) {
	e := newTestEnv(t, &App{IPv4: "10.89.0.1/24"})
	r := e.start(t, alice, true)
	r.tun.maxDatagram.Store(1001)

	// With DF: dropped, and the sender learns the MTU (RFC 1191).
	pkt := udp("1.1.1.1", r.addr(false), 1200)
	pkt[6] |= 0x40
	binary.BigEndian.PutUint16(pkt[10:], 0)
	binary.BigEndian.PutUint16(pkt[10:], ip.Checksum(pkt[:20]))
	e.dev.fromHost <- pkt
	ptb := hostPacket(t, e.dev)
	h, ok := ip.Parse(ptb)
	if !ok || h.Src.String() != "10.89.0.1" || h.Dst.String() != "1.1.1.1" || h.Protocol != ip.ProtoICMP {
		t.Fatalf("ICMP to the sender: %+v", h)
	}
	icmp := ptb[h.PayloadOffset:]
	if icmp[0] != 3 || icmp[1] != 4 || binary.BigEndian.Uint16(icmp[6:]) != 1000 {
		t.Errorf("fragmentation needed with MTU 1000: % x", icmp[:8])
	}
	r.tun.quiet(t)

	// Without DF: fragmented, as a router would.
	e.dev.fromHost <- udp("1.1.1.1", r.addr(false), 1200)
	var total int
	for range 2 {
		f := r.tun.nextPacket(t)
		if len(f) > 1000 {
			t.Errorf("fragment of %d bytes", len(f))
		}
		total += len(f) - 20
	}
	if total != 8+1200 {
		t.Errorf("fragments carry %d bytes", total)
	}
	noHostPacket(t, e.dev)

	// Small packets still pass.
	e.dev.fromHost <- udp("1.1.1.1", r.addr(false), 100)
	r.tun.nextPacket(t)
}

// A tunnel with IPv6 whose QUIC datagrams turn out unable to carry
// 1280-byte packets is aborted (RFC 9484 §7.2), whichever packet showed it:
// an IPv6 one, or an IPv4 one too large for the path.
func TestIPv6NeedsRoomFor1280BytePackets(t *testing.T) {
	for _, v6 := range []bool{true, false} {
		e := newTestEnv(t, dualStack())
		r := e.start(t, alice, true)
		r.tun.maxDatagram.Store(1280) // one byte short: the context ID
		src := map[bool]string{true: "2606:4700::1111", false: "1.1.1.1"}[v6]
		e.dev.fromHost <- udp(src, r.addr(v6), 1280)
		r.waitEnd(t)
		if !r.tun.aborted.Load() {
			t.Errorf("IPv6 %v: the stream was not aborted", v6)
		}
	}
}

// shortProbe makes the MTU probe quick for a test.
func shortProbe(t *testing.T) {
	interval, timeout := probeInterval, probeTimeout
	probeInterval, probeTimeout = 50*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { probeInterval, probeTimeout = interval, timeout })
}

// A tunnel with IPv6 over QUIC datagrams is probed with 1280-byte ICMPv6
// echo requests from the gateway (RFC 9484 §7.2); the reply ends the probe
// and goes no further.
func TestMTUProbe(t *testing.T) {
	shortProbe(t)
	e := newTestEnv(t, dualStack())
	tun := newFakeTunnel(true)
	tun.ignoreProbes.Store(true)
	r := e.startOn(t, alice, tun, newScope(*e.core.allowed.Load(), anyDestination, 0))
	probe := r.tun.nextPacket(t)
	h, ok := ip.Parse(probe)
	m, isEcho := ip.Echo(probe, h)
	if !ok || !isEcho || m.Type != ip.EchoRequestV6 || m.ID != r.s.probeID || len(probe) != ip.IPv6MinMTU ||
		h.Src.String() != "fd89::1" || h.Dst.String() != r.addr(true) {
		t.Fatalf("probe: %+v, %d bytes, echo %v %+v", h, len(probe), isEcho, m)
	}
	r.tun.datagrams <- append([]byte{0}, ip.EchoReply(probe)...)
	noHostPacket(t, e.dev)
	// Answered: the tunnel stays past the probe's timeout, and nothing but
	// probes sent before the reply arrived went to the client.
	time.Sleep(probeTimeout)
	select {
	case why := <-r.ended:
		r.ended <- why
		t.Fatalf("ended: %s", why)
	default:
	}
	for len(r.tun.out) > 0 {
		if v, ok := (<-r.tun.out).(sentDatagram); !ok || len(v) != 1+ip.IPv6MinMTU {
			t.Fatalf("unexpected %T sent", v)
		}
	}
}

// Only a whole reply shows the tunnel carries 1280-byte packets both
// ways: a short one, one to a probe not sent, one with other data or a
// wrong checksum does not, and without a whole one the tunnel is torn
// down.
func TestMTUProbeNeedsAWholeReply(t *testing.T) {
	shortProbe(t)
	e := newTestEnv(t, dualStack())
	tun := newFakeTunnel(true)
	tun.ignoreProbes.Store(true)
	r := e.startOn(t, alice, tun, newScope(*e.core.allowed.Load(), anyDestination, 0))
	probe := r.tun.nextPacket(t)
	h, _ := ip.Parse(probe)
	m, _ := ip.Echo(probe, h)
	data := slices.Clone(m.Data)
	other := slices.Clone(data)
	other[0] ^= 0xff
	badChecksum := ip.EchoReply(probe)
	badChecksum[100] ^= 1
	for _, reply := range [][]byte{
		ip.EchoV6(ip.EchoReplyV6, h.Dst, h.Src, m.ID, m.Seq, nil),
		ip.EchoV6(ip.EchoReplyV6, h.Dst, h.Src, m.ID, 999, data),
		ip.EchoV6(ip.EchoReplyV6, h.Dst, h.Src, m.ID, m.Seq, other),
		badChecksum,
	} {
		r.tun.datagrams <- append([]byte{0}, reply...)
	}
	if why := r.waitEnd(t); !strings.Contains(why, "ICMPv6 echo") {
		t.Errorf("ended: %s", why)
	}
}

// Without a reply, the tunnel is torn down.
func TestMTUProbeWithoutReply(t *testing.T) {
	shortProbe(t)
	e := newTestEnv(t, dualStack())
	tun := newFakeTunnel(true)
	tun.ignoreProbes.Store(true)
	r := e.startOn(t, alice, tun, newScope(*e.core.allowed.Load(), anyDestination, 0))
	why := r.waitEnd(t)
	if !strings.Contains(why, "ICMPv6 echo") || !r.tun.aborted.Load() {
		t.Errorf("ended: %s (aborted %v)", why, r.tun.aborted.Load())
	}
}

// No probe where the tunnel cannot lack room for 1280-byte IPv6 packets
// (IPv4 only, or datagrams in capsules on the stream), nor when the
// configuration turns it off.
func TestNoMTUProbe(t *testing.T) {
	for _, c := range []struct {
		name string
		app  *App
		quic bool
		off  bool
	}{
		{"IPv4 only", &App{IPv4: "10.89.0.1/24"}, true, false},
		{"capsules", dualStack(), false, false},
		{"mtu_probe off", dualStack(), true, true},
	} {
		e := newTestEnv(t, c.app)
		e.core.noMTUProbe.Store(c.off)
		tun := newFakeTunnel(c.quic)
		tun.ignoreProbes.Store(true)
		r := e.startOn(t, alice, tun, newScope(*e.core.allowed.Load(), anyDestination, 0))
		r.tun.quiet(t)
	}
}

func TestIPv6PacketTooBig(t *testing.T) {
	e := newTestEnv(t, dualStack())
	r := e.start(t, alice, true)
	r.tun.maxDatagram.Store(1301)
	e.dev.fromHost <- udp("2606:4700::1111", r.addr(true), 1400)
	ptb := hostPacket(t, e.dev)
	h, _ := ip.Parse(ptb)
	icmp := ptb[h.PayloadOffset:]
	if h.Src.String() != "fd89::1" || icmp[0] != 2 || binary.BigEndian.Uint32(icmp[4:]) != 1300 {
		t.Errorf("Packet Too Big with MTU 1300 from the gateway: %v % x", h.Src, icmp[:8])
	}
}

func TestRemovedUsersAreDisconnected(t *testing.T) {
	e := newTestEnv(t, dualStack())
	r := e.start(t, alice, true)
	kept := e.start(t, bob, true)
	e.core.setUsers(map[string]string{bob.Name: bob.Hash})
	if why := r.waitEnd(t); why != "user removed or password changed" {
		t.Errorf("ended: %s", why)
	}
	if e.core.acquire(context.Background(), alice, true, false) != nil {
		t.Error("a removed user got a lease")
	}
	// A changed password is a removal too.
	e.core.setUsers(map[string]string{bob.Name: "new-hash"})
	kept.waitEnd(t)
	// Packets for a gone session's address are dropped.
	e.dev.fromHost <- udp("1.1.1.1", r.addr(false), 10)
	r.tun.quiet(t)
}

func TestDestructEndsEverySession(t *testing.T) {
	e := newTestEnv(t, dualStack())
	r := e.start(t, alice, true)
	_ = e.core.Destruct()
	if why := r.waitEnd(t); why != "server stopped" {
		t.Errorf("ended: %s", why)
	}
}

func TestReconnectingUsersGetTheirAddressesBack(t *testing.T) {
	e := newTestEnv(t, dualStack())
	ctx := context.Background()
	l := e.core.acquire(ctx, alice, true, true)
	first := slices.Clone(l.addrs)
	l.release()
	other := e.core.acquire(ctx, bob, true, true)
	defer other.release()
	if slices.ContainsFunc(other.addrs, func(a netip.Addr) bool { return slices.Contains(first, a) }) {
		t.Error("another user got the returned addresses while fresh ones were free")
	}
	l = e.core.acquire(ctx, alice, true, true)
	if !slices.Equal(l.addrs, first) {
		t.Errorf("reconnect got %v, had %v", l.addrs, first)
	}
	l.release()
	if calls := e.forgetCalls(); len(calls) != 0 {
		t.Errorf("connection tracking deleted for fresh or own addresses: %v", calls)
	}
}

func TestReusedAddressesForgetTheirConnections(t *testing.T) {
	// A /30 has one client address.
	e := newTestEnv(t, &App{IPv4: "10.89.0.1/30"})
	ctx := context.Background()
	l := e.core.acquire(ctx, alice, true, false)
	if e.core.acquire(ctx, bob, true, false) != nil {
		t.Fatal("a second lease from a one-address pool")
	}
	addr := l.addrs[0]
	l.release()
	l = e.core.acquire(ctx, bob, true, false)
	if l == nil || l.addrs[0] != addr {
		t.Fatal("the address was not reused")
	}
	calls := e.forgetCalls()
	if len(calls) != 1 || !slices.Equal(calls[0], []netip.Prefix{netip.PrefixFrom(addr, 32)}) {
		t.Errorf("forget calls %v", calls)
	}
	l.release()
	// The address is bob's now: alice does not reclaim it without a reset.
	e.forget.Lock()
	e.forget.err = errors.New("netlink failed")
	e.forget.Unlock()
	if e.core.acquire(ctx, alice, true, false) != nil {
		t.Error("an address was handed out although its connections could not be deleted")
	}
	e.forget.Lock()
	e.forget.err = nil
	e.forget.Unlock()
	if l := e.core.acquire(ctx, alice, true, false); l == nil {
		t.Error("the address was lost after a failed deletion")
	} else {
		l.release()
	}
}

func TestPoolExhaustion(t *testing.T) {
	e := newTestEnv(t, &App{IPv4: "10.89.0.1/29", IPv6: "fd89::1/64"})
	ctx := context.Background()
	var leases []*lease
	for i := 0; ; i++ {
		u := auth.User{Name: "u" + string(rune('a'+i)), Hash: "h"}
		users := map[string]string{}
		for _, l := range leases {
			users[l.handle.user.Name] = "h"
		}
		users[u.Name] = "h"
		e.core.setUsers(users)
		l := e.core.acquire(ctx, u, true, true)
		if l == nil {
			break
		}
		leases = append(leases, l)
	}
	if len(leases) != 5 { // .2 to .6 of a /29
		t.Errorf("%d leases from a /29", len(leases))
	}
	// A failed acquisition returns its IPv6 address: all of them are free.
	for _, l := range leases {
		l.release()
	}
}

func TestScopeAllows(t *testing.T) {
	set := routes.Everything()
	tcp := scope{routes: set, protocol: ip.ProtoTCP}
	parse := func(p []byte) ip.Header { h, _ := ip.Parse(p); return h }
	if !tcp.allows(parse(packet("10.0.0.1", "1.1.1.1", ip.ProtoTCP, make([]byte, 20)))) {
		t.Error("TCP")
	}
	if tcp.allows(parse(udp("10.0.0.1", "1.1.1.1", 1))) {
		t.Error("UDP in a TCP scope")
	}
	if !tcp.allows(parse(echoRequest("10.0.0.1", "1.1.1.1"))) || !tcp.allows(parse(echoRequest("fd89::2", "2001:db8::1"))) {
		t.Error("ICMP")
	}
	// ICMPv6 inside IPv4 is not ICMP.
	if tcp.allows(parse(packet("10.0.0.1", "1.1.1.1", ip.ProtoICMPv6, make([]byte, 8)))) {
		t.Error("protocol 58 over IPv4")
	}
}

// A scope that leaves out the server's IPv6 tunnel address still lets the
// client send ICMPv6 to it, and says so in the ROUTE_ADVERTISEMENT: the
// MTU probe comes from there, and a client sends only where routes lead
// (RFC 9484 §7.2), so it could not reply otherwise.
func TestScopedIPv6KeepsICMPv6ToTheGateway(t *testing.T) {
	gw := netip.MustParseAddr("fd89::1")
	for _, protocol := range []uint8{0, ip.ProtoTCP, 132} {
		e := newTestEnv(t, dualStack())
		sc := newScope(*e.core.allowed.Load(), []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")}, protocol)
		r := e.startScoped(t, alice, true, sc)
		adv := r.s.current.Load().advertised()
		if err := proto.ValidateRoutes(adv); err != nil {
			t.Fatalf("protocol %d: %v: %v", protocol, err, adv)
		}
		want := proto.AddressRange{Start: gw, End: gw, Protocol: ip.ProtoICMPv6}
		if !slices.Contains(adv, want) || len(adv) != 2 {
			t.Fatalf("protocol %d: routes %v, want the scope's and %v", protocol, adv, want)
		}
		src := r.addr(true)
		r.tun.datagrams <- append([]byte{0}, echoRequest(src, gw.String())...)
		hostPacket(t, e.dev)
		r.tun.datagrams <- append([]byte{0}, udp(src, gw.String(), 10)...)
		noHostPacket(t, e.dev)
		if reply := r.tun.nextPacket(t); len(reply) < 48 || reply[40] != 1 || reply[41] != 1 {
			t.Errorf("protocol %d: UDP to the gateway is not administratively prohibited", protocol)
		}
	}
	// The full scope holds the gateway already: nothing is added.
	e := newTestEnv(t, dualStack())
	r := e.start(t, alice, true)
	for _, rt := range r.s.current.Load().advertised() {
		if rt.Protocol != 0 {
			t.Errorf("full scope: extra route %v", rt)
		}
	}
}

// The gateway's ICMPv6 route is ordered by address too: with a scope of
// protocol 58 it shares the protocol with the scope's ranges, and a route
// out of order is one the encoder refuses to send (a panic).
func TestGatewayRouteIsOrderedByAddress(t *testing.T) {
	e := newTestEnv(t, dualStack())
	allowed := *e.core.allowed.Load()
	gw := netip.MustParseAddr("fd89::1")
	for _, targets := range [][]string{
		{"2001:db8::/64"},                              // below the gateway
		{"fec0::/64"},                                  // above it
		{"2001:db8::/64", "fec0::/64"},                 // on both sides
		{"192.0.2.0/24", "2001:db8::/64", "fec0::/64"}, // and IPv4 first
	} {
		var prefixes []netip.Prefix
		for _, p := range targets {
			prefixes = append(prefixes, netip.MustParsePrefix(p))
		}
		for _, protocol := range []uint8{0, ip.ProtoTCP, ip.ProtoICMPv6, 132} {
			sc := newScope(allowed, prefixes, protocol)
			sc.gateway6 = gw
			adv := sc.advertised()
			if err := proto.ValidateRoutes(adv); err != nil {
				t.Errorf("%v, protocol %d: %v: %v", targets, protocol, err, adv)
				continue
			}
			if !slices.Contains(adv, proto.AddressRange{Start: gw, End: gw, Protocol: ip.ProtoICMPv6}) {
				t.Errorf("%v, protocol %d: no gateway route: %v", targets, protocol, adv)
			}
			if len(adv) != len(targets)+1 {
				t.Errorf("%v, protocol %d: %d routes: %v", targets, protocol, len(adv), adv)
			}
			_ = proto.Append(nil, proto.RouteAdvertisement(adv))
		}
	}
	// A session with such a scope opens: the advertisement goes out.
	sc := newScope(allowed, []netip.Prefix{netip.MustParsePrefix("fec0::/64")}, ip.ProtoICMPv6)
	r := e.startScoped(t, alice, true, sc)
	if len(r.lease.addrs) != 1 || !r.lease.addrs[0].Is6() {
		t.Fatalf("an IPv6 scope gets one IPv6 address: %v", r.lease.addrs)
	}
}

// Routes that break RFC 9484 §4.7.3 are a bug, but one that ends only the
// tunnel concerned: the encoder would panic, in a goroutine where that ends
// the whole process.
func TestInvalidRoutesEndOnlyTheirSession(t *testing.T) {
	e := newTestEnv(t, dualStack())
	r := e.start(t, alice, true)
	// The gateway's ICMPv6 range inside a protocol-58 route: they overlap.
	bad := newScope(*e.core.allowed.Load(), []netip.Prefix{netip.MustParsePrefix("fd89::/64")}, ip.ProtoICMPv6)
	bad.gateway6 = netip.MustParseAddr("fd89::1")
	if proto.ValidateRoutes(bad.advertised()) == nil {
		t.Fatal("the test scope should give invalid routes")
	}
	r.s.current.Store(&bad)
	var abort errAbort
	if err := r.s.advertise(); !errors.As(err, &abort) {
		t.Fatalf("advertise: %v, want the session aborted", err)
	}
	r.tun.quiet(t)
}

func TestConfigurationChangesAndRunningSessions(t *testing.T) {
	e := newTestEnv(t, dualStack())
	r := e.start(t, alice, true)
	scoped := e.startScoped(t, bob, true, newScope(*e.core.allowed.Load(),
		[]netip.Prefix{netip.MustParsePrefix("1.1.0.0/16"), netip.MustParsePrefix("10.89.0.0/24")}, 0))

	// An unchanged configuration advertises nothing.
	e.core.setAllowed(*e.core.allowed.Load())
	r.tun.quiet(t)
	scoped.tun.quiet(t)

	// More destinations: a new advertisement, the session goes on.
	more := dualStack()
	more.AllowClientToClient = true
	if err := more.parse(); err != nil {
		t.Fatal(err)
	}
	e.core.setAllowed(more.allowed)
	for _, x := range []*running{r, scoped} {
		adv, ok := x.tun.next(t).(proto.RouteAdvertisement)
		if !ok || proto.ValidateRoutes(adv) != nil {
			t.Fatal("no valid new ROUTE_ADVERTISEMENT")
		}
	}
	other := scoped.addr(false)
	r.tun.datagrams <- append([]byte{0}, udp(r.addr(false), other, 10)...)
	hostPacket(t, e.dev)
	// The scoped session's routes stay within its scope.
	if got := scoped.s.current.Load().routes; got.Contains(netip.MustParseAddr("8.8.8.8")) ||
		!got.Contains(netip.MustParseAddr("10.89.0.200")) {
		t.Errorf("scoped routes %v", got.Routes(0))
	}

	// Fewer destinations: assigned routes are kept while the stream is
	// open (RFC 9484 §4), so the sessions end.
	fewer := dualStack()
	fewer.BlockedDestinations = &[]string{"1.0.0.0/8"}
	if err := fewer.parse(); err != nil {
		t.Fatal(err)
	}
	e.core.setAllowed(fewer.allowed)
	for _, x := range []*running{r, scoped} {
		if why := x.waitEnd(t); why != "the new configuration withdraws routes of the tunnel" {
			t.Errorf("ended: %s", why)
		}
		if x.tun.aborted.Load() || !x.tun.closed.Load() {
			t.Error("the stream is closed, not aborted")
		}
	}
	// A new session gets the new routes.
	n := e.start(t, alice, true)
	if n.s.current.Load().routes.Contains(netip.MustParseAddr("1.1.1.1")) {
		t.Error("a new session got a blocked destination")
	}
}

func TestLogLimit(t *testing.T) {
	l := logLimit{max: 2}
	for i, want := range []bool{true, true, false, false} {
		if ok, _ := l.allow(); ok != want {
			t.Errorf("event %d: %v", i, ok)
		}
	}
	l.window = l.window.Add(-time.Minute)
	if ok, suppressed := l.allow(); !ok || suppressed != 2 {
		t.Errorf("next minute: %v, %d suppressed", ok, suppressed)
	}
}
