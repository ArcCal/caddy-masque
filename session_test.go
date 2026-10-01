package masque

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"slices"
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
	maxDatagram int
	out         chan any // capsules and datagrams (sentDatagram) to the client
	aborted     atomic.Bool
	closed      atomic.Bool
}

type sentDatagram []byte

func newFakeTunnel(quicDatagrams bool) *fakeTunnel {
	return &fakeTunnel{capsules: make(chan proto.Capsule, 10), errs: make(chan error, 1), datagrams: make(chan []byte, 10),
		quic: quicDatagrams, out: make(chan any, 100)}
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
	}
}

func (t *fakeTunnel) writeCapsule(c proto.Capsule) error {
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
	if t.maxDatagram > 0 && len(p) > t.maxDatagram {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: int64(t.maxDatagram)}
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
func (t *fakeTunnel) abort()                 { t.aborted.Store(true) }
func (t *fakeTunnel) close()                 { t.closed.Store(true) }

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
	l := e.core.acquire(context.Background(), user, sc.routes.HasIPv4(), sc.routes.HasIPv6())
	if l == nil {
		tb.Fatal("no lease")
	}
	r := &running{tun: newFakeTunnel(quicDatagrams), lease: l, ended: make(chan string, 1)}
	r.s = &session{core: e.core, lease: l, scope: sc, tun: r.tun, log: zaptest.NewLogger(tb), icmp: ip.NewRateLimit()}
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
	s := &session{core: e.core, lease: l, scope: newScope(*e.core.allowed.Load(), anyDestination, 0), tun: tun, log: zaptest.NewLogger(t), icmp: ip.NewRateLimit()}
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

func TestTooLargeForTheQUICPath(t *testing.T) {
	e := newTestEnv(t, &App{IPv4: "10.89.0.1/24"})
	r := e.start(t, alice, true)
	r.tun.maxDatagram = 1001
	pkt := udp("1.1.1.1", r.addr(false), 1200)
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
	// Small packets still pass.
	e.dev.fromHost <- udp("1.1.1.1", r.addr(false), 100)
	r.tun.nextPacket(t)
}

func TestIPv6NeedsRoomFor1280BytePackets(t *testing.T) {
	e := newTestEnv(t, dualStack())
	r := e.start(t, alice, true)
	r.tun.maxDatagram = 1280 // one byte short: the context ID
	e.dev.fromHost <- udp("2606:4700::1111", r.addr(true), 1280-48)
	r.waitEnd(t)
	if !r.tun.aborted.Load() {
		t.Error("the stream was not aborted (RFC 9484 §7.1)")
	}
}

func TestIPv6PacketTooBig(t *testing.T) {
	e := newTestEnv(t, dualStack())
	r := e.start(t, alice, true)
	r.tun.maxDatagram = 1301
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

func TestNewBlocksApplyToRunningSessions(t *testing.T) {
	e := newTestEnv(t, dualStack())
	r := e.start(t, alice, true)
	scoped := e.startScoped(t, bob, true, newScope(*e.core.allowed.Load(),
		[]netip.Prefix{netip.MustParsePrefix("1.1.0.0/16"), netip.MustParsePrefix("8.8.8.8/32")}, 0))

	// An unchanged configuration advertises nothing.
	e.core.setAllowed(*e.core.allowed.Load())
	r.tun.quiet(t)

	app := dualStack()
	app.BlockedDestinations = &[]string{"1.0.0.0/8"}
	if err := app.parse(); err != nil {
		t.Fatal(err)
	}
	e.core.setAllowed(app.allowed)
	for _, x := range []*running{r, scoped} {
		adv, ok := x.tun.next(t).(proto.RouteAdvertisement)
		if !ok {
			t.Fatal("no new ROUTE_ADVERTISEMENT")
		}
		if err := proto.ValidateRoutes(adv); err != nil {
			t.Fatal(err)
		}
		for _, rt := range adv {
			if rt.Start.Compare(netip.MustParseAddr("1.1.1.1")) <= 0 && netip.MustParseAddr("1.1.1.1").Compare(rt.End) <= 0 {
				t.Errorf("1.1.1.1 still advertised: %v", rt)
			}
		}
		pkt := udp(x.addr(false), "1.1.1.1", 10)
		x.tun.datagrams <- append([]byte{0}, pkt...)
		noHostPacket(t, e.dev)
		if reply := x.tun.nextPacket(t); reply[20] != 3 || reply[21] != 13 {
			t.Error("the newly blocked destination is not refused")
		}
	}
	// The scoped session keeps its scope: 8.8.8.8 only, IPv4 only.
	adv := scoped.s.current.Load().routes.Routes(0)
	if len(adv) != 1 || adv[0].Start != netip.MustParseAddr("8.8.8.8") || adv[0].End != adv[0].Start {
		t.Errorf("scoped routes %v", adv)
	}
	scoped.tun.datagrams <- append([]byte{0}, udp(scoped.addr(false), "8.8.8.8", 10)...)
	hostPacket(t, e.dev)
}
