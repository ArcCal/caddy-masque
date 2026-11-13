package masque

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"github.com/ArcCal/caddy-masque/internal/ip"
	"github.com/ArcCal/caddy-masque/internal/proto"
	"github.com/ArcCal/caddy-masque/internal/routes"
)

// scope is what a session may reach: the destinations it asked for (a
// target's prefix, or the addresses its host name resolved to) that the
// server allows, and the IP protocol for them (0: all). ICMP is always
// allowed (RFC 9484 §4.7.3).
type scope struct {
	requested []netip.Prefix
	protocol  uint8
	routes    routes.Set
	// The server's IPv6 tunnel address when it is outside routes: the
	// client may still send ICMPv6 to it, or it could not answer the MTU
	// probe, which comes from there (RFC 9484 §7.2).
	gateway6 netip.Addr
}

// anyDestination is the request of target "*".
var anyDestination = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}

func newScope(allowed routes.Set, requested []netip.Prefix, protocol uint8) scope {
	var set routes.Set
	for _, p := range requested {
		set = set.Union(allowed.Intersect(p))
	}
	return scope{requested: requested, protocol: protocol, routes: set}
}

func (s scope) allows(h ip.Header) bool {
	icmp := h.Protocol == ip.ProtoICMP && h.IsIPv4() || h.Protocol == ip.ProtoICMPv6 && !h.IsIPv4()
	if icmp && s.gateway6.IsValid() && h.Dst == s.gateway6 {
		return true
	}
	return s.routes.Contains(h.Dst) && (s.protocol == 0 || h.Protocol == s.protocol || icmp)
}

// advertised are the ranges of the ROUTE_ADVERTISEMENT: the routes, and
// ICMPv6 to the gateway when the routes leave it out, in the order RFC 9484
// §4.7.3 requires (IP version, then protocol, then address).
func (s scope) advertised() []proto.AddressRange {
	out := s.routes.Routes(s.protocol)
	if s.gateway6.IsValid() {
		out = append(out, proto.AddressRange{Start: s.gateway6, End: s.gateway6, Protocol: ip.ProtoICMPv6})
		// The gateway is outside the routes, so it overlaps none of them; with
		// a scope of protocol 58 its range shares the protocol, and the
		// address decides the order. netip orders IPv4 before IPv6.
		slices.SortFunc(out, func(a, b proto.AddressRange) int {
			if a.Start.Is4() != b.Start.Is4() {
				return a.Start.Compare(b.Start)
			}
			return cmp.Or(cmp.Compare(a.Protocol, b.Protocol), a.Start.Compare(b.Start))
		})
	}
	return out
}

type stats struct{ toClient, fromClient, dropped atomic.Uint64 }

func (s *stats) String() string {
	return fmt.Sprintf("%d packets to client, %d from client, %d dropped", s.toClient.Load(), s.fromClient.Load(), s.dropped.Load())
}

type session struct {
	core  *core
	lease *lease
	scope scope
	// The scope narrowed to what the server allows now and to the lease's
	// address families; replaced when the configuration changes.
	current atomic.Pointer[scope]
	tun     tunnel
	log     *zap.Logger
	stats   *stats
	// Shared by the errors sent to the client and those sent to the network
	// for its sake.
	icmpMu sync.Mutex
	icmp   *ip.RateLimit
	// The IPv6 MTU probe: the client address it goes to, its echo
	// identifier and data, how many were sent, and closed on a reply.
	probeTo    netip.Addr
	probeID    uint16
	probeData  []byte
	probeSent  atomic.Uint32
	probeReply chan struct{}
	probeOnce  sync.Once
	frags      fragments
}

// fragments remembers the upper-layer protocol of the first fragments of
// the client's IPv6 packets, for scoping their later fragments; at most
// maxFragments packets, each for as long as reassembly may take.
type fragments struct {
	mu sync.Mutex
	m  map[fragmentKey]fragment
}

type fragmentKey struct {
	src, dst netip.Addr
	id       uint32
}

type fragment struct {
	protocol uint8
	at       time.Time
}

const (
	maxFragments     = 64
	fragmentLifetime = 60 * time.Second // RFC 8200 §4.5
)

func (f *fragments) note(h ip.Header) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	if f.m == nil {
		f.m = map[fragmentKey]fragment{}
	}
	if len(f.m) >= maxFragments {
		for k, v := range f.m {
			if now.Sub(v.at) > fragmentLifetime {
				delete(f.m, k)
			}
		}
		if len(f.m) >= maxFragments {
			return
		}
	}
	f.m[fragmentKey{h.Src, h.Dst, h.FragmentID}] = fragment{h.Protocol, now}
}

func (f *fragments) protocol(h ip.Header) (uint8, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.m[fragmentKey{h.Src, h.Dst, h.FragmentID}]
	if !ok || time.Since(v.at) > fragmentLifetime {
		return 0, false
	}
	return v.protocol, true
}

func newSession(c *core, l *lease, sc scope, tun tunnel, log *zap.Logger) *session {
	s := &session{core: c, lease: l, scope: sc, tun: tun, log: log, stats: &l.handle.stats, icmp: ip.NewRateLimit(),
		probeID: uint16(rand.Uint32()), probeData: make([]byte, probeData), probeReply: make(chan struct{})}
	for _, a := range l.addrs {
		if a.Is6() {
			s.probeTo = a
		}
	}
	// Random data: only a client that got the probe can return it.
	for i := range s.probeData {
		s.probeData[i] = byte(rand.Uint32())
	}
	return s
}

// The IPv6 MTU probe (RFC 9484 §7.2): an ICMPv6 echo request with 1232
// bytes of data, a 1280-byte packet, sent again every probeInterval (a
// datagram may be lost) until a reply, for at most probeTimeout.
var (
	probeInterval = time.Second
	probeTimeout  = 10 * time.Second
)

const probeData = ip.IPv6MinMTU - 40 - 8

// dropped counts a packet the session did not forward.
func (s *session) dropped() {
	s.stats.dropped.Add(1)
	s.core.counters.dropped.Add(1)
}

func (s *session) icmpAllow() bool {
	s.icmpMu.Lock()
	defer s.icmpMu.Unlock()
	return s.icmp.Allow()
}

// How long an ending session waits for writes in progress.
const drainTimeout = 2 * time.Second

// errAbort ends the session with an aborted stream: as a malformed message
// when the client broke the protocol, otherwise cancelled (see ending).
type errAbort struct {
	why       string
	malformed bool
}

func (e errAbort) Error() string { return "aborted: " + e.why }

// run serves the session until the client ends it, the user is removed,
// or an error ends it. It returns why it ended.
func (s *session) run(ctx context.Context) string {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ended := make(chan error, 5)
	var wg sync.WaitGroup
	spawn := func(f func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ended <- f()
		}()
	}
	// The capsules the session sends of its own accord have a goroutine
	// of their own: a client that stops reading blocks writes to the
	// stream, and this loop must still see the session end.
	s.current.Store(s.narrow())
	opened := make(chan struct{})
	readvertise := make(chan struct{}, 1)
	spawn(func() error { return s.announce(ctx, opened, readvertise) })
	opening := (<-chan struct{})(opened)
	var err error
	for err == nil {
		select {
		case err = <-ended:
		case <-opening:
			// The client has its addresses and routes: the tunnel opens.
			opening = nil
			spawn(s.readCapsules)
			if s.tun.hasQUICDatagrams() {
				spawn(func() error { return s.readDatagrams(ctx) })
			}
			spawn(func() error { return s.sendToClientLoop(ctx) })
			if s.tun.hasQUICDatagrams() && s.lease.hasIPv6() && !s.core.noMTUProbe.Load() {
				spawn(func() error { return s.probeMTU(ctx) })
			}
		case <-s.lease.handle.revoked:
			err = errors.New(s.lease.handle.why)
		case <-ctx.Done():
			err = ctx.Err()
		case <-s.lease.handle.rescope:
			// The allowed destinations changed. The proxy maintains the
			// routes it assigned while the stream is open (§4): more
			// routes are advertised, the latest advertisement replacing
			// the earlier ones (§4.7.3); fewer end the tunnel, and the
			// client gets the new ones when it reconnects.
			cur, next := s.current.Load(), s.narrow()
			switch {
			case next.routes.Equal(cur.routes):
			case cur.routes.Union(next.routes).Equal(next.routes):
				s.current.Store(next)
				select {
				case readvertise <- struct{}{}:
				default: // already pending; it sends the latest routes
				}
				s.log.Info("more routes with the new configuration", zap.Int("routes", len(next.routes.Routes(next.protocol))))
			default:
				err = errors.New("the new configuration withdraws routes of the tunnel")
			}
		}
	}
	// Unblock the goroutines and wait for them: nothing may use the
	// stream after the handler returns. A write still blocked (a client
	// that stopped reading) is cut short after a while.
	cancel()
	how := endClose
	if abort := (errAbort{}); errors.As(err, &abort) {
		how = endCancel
		if abort.malformed {
			how = endMalformed
		}
	}
	s.tun.stop(how)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(drainTimeout):
		s.tun.force()
		<-done
	}
	s.tun.finish(how)
	if errors.Is(err, io.EOF) {
		return "client closed the tunnel"
	}
	return err.Error()
}

// announce tells the client its addresses and where it may send (§4.7),
// closes opened, and advertises the routes again when asked to.
func (s *session) announce(ctx context.Context, opened chan<- struct{}, readvertise <-chan struct{}) error {
	assigned := proto.AddressAssign{}
	for _, a := range s.lease.addrs {
		assigned = append(assigned, proto.AssignedAddress{Prefix: proto.Host(a)})
	}
	if err := s.tun.writeCapsule(assigned); err != nil {
		return err
	}
	if err := s.advertise(); err != nil {
		return err
	}
	close(opened)
	for {
		select {
		case <-readvertise:
			if err := s.advertise(); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// probeMTU checks that the tunnel carries 1280-byte IPv6 packets, which
// QUIC DATAGRAM frames may not (RFC 9484 §7.2): padding the QUIC Initial
// packets shows it only without HTTP intermediaries, so unless told there
// are none, the proxy sends ICMPv6 echo requests with 1232 bytes of data
// to the client and tears the tunnel down without a reply. It returns nil
// once the client replies.
func (s *session) probeMTU(ctx context.Context) error {
	gateway := s.core.gateway(true)
	timeout := time.NewTimer(probeTimeout)
	defer timeout.Stop()
	tick := time.NewTicker(probeInterval)
	defer tick.Stop()
	for seq := uint16(0); ; seq++ {
		s.probeSent.Store(uint32(seq) + 1)
		// Too large for the path ends the session (sendToClient).
		if err := s.sendToClient(append([]byte{0}, ip.EchoV6(ip.EchoRequestV6, gateway, s.probeTo, s.probeID, seq, s.probeData)...)); err != nil {
			return err
		}
		select {
		case <-s.probeReply:
			s.log.Debug("the tunnel carries 1280-byte IPv6 packets")
			return nil
		case <-timeout.C:
			return errAbort{why: "no reply to 1280-byte ICMPv6 echo requests: the tunnel may not carry IPv6's minimum MTU (RFC 9484 §7.2)"}
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// isProbeReply reports an echo reply to the MTU probe, which goes no
// further. It shows the tunnel carries 1280-byte packets both ways only if
// it is whole: from the probed address, 1280 bytes, to a probe sent, with
// the probe's data unmodified (RFC 4443 §4.2) and a valid checksum.
func (s *session) isProbeReply(pkt []byte, h ip.Header) bool {
	if h.IsIPv4() || h.Dst != s.core.gateway(true) || s.probeReply == nil {
		return false
	}
	m, ok := ip.Echo(pkt, h)
	if !ok || m.Type != ip.EchoReplyV6 || m.ID != s.probeID {
		return false
	}
	if h.Src == s.probeTo && h.TotalLen == ip.IPv6MinMTU && uint32(m.Seq) < s.probeSent.Load() && bytes.Equal(m.Data, s.probeData) {
		s.probeOnce.Do(func() { close(s.probeReply) })
	}
	return true
}

// narrow is the session's scope within what the server allows now, for the
// address families the session has.
func (s *session) narrow() *scope {
	sc := newScope(*s.core.allowed.Load(), s.scope.requested, s.scope.protocol)
	v4, v6 := false, false
	for _, a := range s.lease.addrs {
		v4, v6 = v4 || a.Is4(), v6 || a.Is6()
	}
	sc.routes = sc.routes.Families(v4, v6)
	if gw := s.core.gateway(true); v6 && gw.IsValid() && !sc.routes.Contains(gw) {
		sc.gateway6 = gw
	}
	return &sc
}

func (s *session) advertise() error {
	routes := s.current.Load().advertised()
	// The encoder panics on routes RFC 9484 §4.7.3 forbids, and this runs
	// in a goroutine of its own, where a panic ends the whole process. A
	// bug here ends this tunnel only.
	if err := proto.ValidateRoutes(routes); err != nil {
		s.log.Error("not sending invalid routes", zap.Error(err), zap.Any("routes", routes))
		return errAbort{why: "internal error: invalid route advertisement"}
	}
	return s.tun.writeCapsule(proto.RouteAdvertisement(routes))
}

func (s *session) readCapsules() error {
	for {
		c, err := s.tun.readCapsule()
		if err != nil {
			var m proto.MalformedError
			if errors.As(err, &m) {
				return errAbort{why: "malformed capsule stream (" + m.Error() + ")", malformed: true}
			}
			return err
		}
		switch c := c.(type) {
		case proto.Datagram:
			if err := s.clientPacket(c); err != nil {
				return err
			}
		case proto.AddressRequest:
			if err := s.tun.writeCapsule(addressAssignReply(s.lease.addrs, c)); err != nil {
				return err
			}
		case proto.Unknown:
			s.log.Debug("ignoring unknown capsule", zap.Uint64("type", c.Type))
		default:
			// Remote-access clients do not assign us addresses or
			// advertise routes (§8.1): accept and ignore.
		}
	}
}

func (s *session) readDatagrams(ctx context.Context) error {
	for {
		p, err := s.tun.receiveDatagram(ctx)
		if err != nil {
			return err
		}
		if err := s.clientPacket(p); err != nil {
			return err
		}
	}
}

func (s *session) sendToClientLoop(ctx context.Context) error {
	for {
		select {
		case q := <-s.lease.handle.toClient:
			if time.Since(q.at) > maxQueueDelay {
				s.dropped()
				continue
			}
			if err := s.sendToClient(q.pkt); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// clientPacket applies the forwarding checks to a datagram from the client
// (§7, §11) and forwards it.
func (s *session) clientPacket(payload []byte) error {
	id, pkt, err := proto.SplitContextID(payload)
	if err != nil || id != proto.ContextIDIPPacket {
		s.dropped() // unknown context ID (§5) or empty datagram
		return nil
	}
	h, ok := ip.Parse(pkt)
	if !ok {
		s.dropped()
		return nil
	}
	if !s.lease.owns(h.Src) {
		// BCP 38: never forward a source address the client was not given.
		s.dropped()
		s.log.Debug("dropping packet with spoofed source", zap.Stringer("src", h.Src))
		return nil
	}
	if s.isProbeReply(pkt, h) {
		return nil
	}
	// RFC 9484 §7.2 permits peers without our address to probe ff02::1.
	// Answer on this tunnel using a unicast source (RFC 4443 §4.2), and
	// never forward link-local multicast into the host's network.
	if h.Dst == netip.MustParseAddr("ff02::1") {
		if echo, ok := ip.Echo(pkt, h); ok && echo.Type == ip.EchoRequestV6 && s.icmpAllow() {
			if gateway := s.core.gateway(true); gateway.IsValid() {
				return s.sendToClient(append([]byte{0}, ip.EchoV6(ip.EchoReplyV6, gateway, h.Src, echo.ID, echo.Seq, echo.Data)...))
			}
		}
		return nil
	}
	if h.Fragment && s.scope.protocol != 0 {
		// A later IPv6 fragment may not show its upper-layer protocol: it
		// is the first fragment's (RFC 9484 §4.8). Unknown, it is dropped.
		if h.FirstFragment {
			s.frags.note(h)
		} else if h.ProtocolUnknown {
			p, ok := s.frags.protocol(h)
			if !ok {
				s.dropped()
				return nil
			}
			h.Protocol = p
		}
	}
	// Each tunnel is its own IP link. Link-local unicast must not cross
	// interfaces (§7.2), but can receive local ICMP error feedback (§8).
	if h.Src.IsLinkLocalUnicast() || h.Dst.IsLinkLocalUnicast() || !s.current.Load().allows(h) {
		s.dropped()
		if e := ip.DestUnreachable(pkt, s.core.gateway(!h.IsIPv4()), ip.AdminProhibited); e != nil && s.icmpAllow() {
			return s.sendToClient(append([]byte{0}, e...))
		}
		return nil
	}
	s.stats.fromClient.Add(1)
	s.core.counters.fromClient.Add(1)
	s.core.counters.bytesFromClient.Add(uint64(h.TotalLen))
	s.core.toNetwork(pkt[:h.TotalLen])
	return nil
}

// sendToClient sends a context-ID-prefixed packet to the client.
func (s *session) sendToClient(payload []byte) error {
	err := s.tun.sendDatagram(payload)
	var tooBig *quic.DatagramTooLargeError
	switch {
	case err == nil:
		s.stats.toClient.Add(1)
		s.core.counters.toClient.Add(1)
		s.core.counters.bytesToClient.Add(uint64(len(payload) - 1))
	case errors.As(err, &tooBig):
		pkt := payload[1:]
		v6 := len(pkt) > 0 && pkt[0]>>4 == 6
		// RFC 9484 §7.2: a tunnel with IPv6 must carry 1280-byte packets;
		// once QUIC DATAGRAM frames are known not to, whatever packet
		// showed it, the stream must be aborted.
		if s.lease.hasIPv6() && tooBig.MaxDatagramPayloadSize < 1+ip.IPv6MinMTU {
			return errAbort{why: "the path cannot carry 1280-byte IPv6 packets in QUIC datagrams (RFC 9484 §7.2)"}
		}
		mtu := int(tooBig.MaxDatagramPayloadSize) - 1
		// An IPv4 packet without DF is fragmented, as a router would.
		if frags := ip.Fragment(pkt, mtu); frags != nil {
			for _, f := range frags {
				if err := s.sendToClient(append([]byte{0}, f...)); err != nil {
					return err
				}
			}
			return nil
		}
		// §10.1: drop and report, never fall back to reliable delivery.
		s.dropped()
		if e := ip.PacketTooBig(pkt, s.core.gateway(v6), mtu); e != nil && s.icmpAllow() {
			s.core.toNetwork(e)
		}
	default:
		return err
	}
	return nil
}

// addressAssignReply answers an ADDRESS_REQUEST (§4.7.2): every request
// gets an entry with its ID, holding our assignment for that family or a
// rejection. The reply is the full set of assigned addresses.
func addressAssignReply(addrs []netip.Addr, requests proto.AddressRequest) proto.AddressAssign {
	reply := proto.AddressAssign{}
	for _, r := range requests {
		prefix := proto.Unspecified(r.Prefix.Addr().Is6())
		for _, a := range addrs {
			// An explicit address/prefix was granted only if it is our
			// actual assignment. Otherwise §4.7.2 requires the all-zero
			// rejection, and the existing address is included with ID zero.
			if a.Is6() == r.Prefix.Addr().Is6() && (r.Prefix.Addr().IsUnspecified() || r.Prefix == proto.Host(a)) {
				prefix = proto.Host(a)
				break
			}
		}
		reply = append(reply, proto.AssignedAddress{RequestID: r.RequestID, Prefix: prefix})
	}
	for _, a := range addrs {
		found := false
		for _, r := range reply {
			if r.Prefix == proto.Host(a) {
				found = true
				break
			}
		}
		if !found {
			reply = append(reply, proto.AssignedAddress{Prefix: proto.Host(a)})
		}
	}
	return reply
}
