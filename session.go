package masque

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/netip"
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
	return s.routes.Contains(h.Dst) && (s.protocol == 0 || h.Protocol == s.protocol || icmp)
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
	stats   stats
	// Shared by the errors sent to the client and those sent to the network
	// for its sake.
	icmpMu sync.Mutex
	icmp   *ip.RateLimit
	// The IPv6 MTU probe: its echo identifier, and closed on its reply.
	probeID    uint16
	probeReply chan struct{}
	probeOnce  sync.Once
}

func newSession(c *core, l *lease, sc scope, tun tunnel, log *zap.Logger) *session {
	return &session{core: c, lease: l, scope: sc, tun: tun, log: log, icmp: ip.NewRateLimit(),
		probeID: uint16(rand.Uint32()), probeReply: make(chan struct{})}
}

// The IPv6 MTU probe (RFC 9484 §7.2): an ICMPv6 echo request with 1232
// bytes of data, a 1280-byte packet, sent again every probeInterval (a
// datagram may be lost) until a reply, for at most probeTimeout.
var (
	probeInterval = time.Second
	probeTimeout  = 10 * time.Second
)

const probeData = ip.IPv6MinMTU - 40 - 8

func (s *session) icmpAllow() bool {
	s.icmpMu.Lock()
	defer s.icmpMu.Unlock()
	return s.icmp.Allow()
}

// How long an ending session waits for writes in progress.
const drainTimeout = 2 * time.Second

// errAbort ends the session with an aborted stream.
type errAbort struct{ why string }

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
	var abort errAbort
	aborted := errors.As(err, &abort)
	s.tun.stop(aborted)
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
	s.tun.finish(aborted)
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
	var client netip.Addr
	for _, a := range s.lease.addrs {
		if a.Is6() {
			client = a
		}
	}
	gateway := s.core.gateway(true)
	timeout := time.NewTimer(probeTimeout)
	defer timeout.Stop()
	tick := time.NewTicker(probeInterval)
	defer tick.Stop()
	for seq := uint16(0); ; seq++ {
		// Too large for the path ends the session (sendToClient).
		if err := s.sendToClient(append([]byte{0}, ip.EchoV6(ip.EchoRequestV6, gateway, client, s.probeID, seq, probeData)...)); err != nil {
			return err
		}
		select {
		case <-s.probeReply:
			s.log.Debug("the tunnel carries 1280-byte IPv6 packets")
			return nil
		case <-timeout.C:
			return errAbort{"no reply to 1280-byte ICMPv6 echo requests: the tunnel may not carry IPv6's minimum MTU (RFC 9484 §7.2)"}
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// isProbeReply reports an echo reply to the MTU probe, which goes no
// further.
func (s *session) isProbeReply(pkt []byte, h ip.Header) bool {
	if h.IsIPv4() || h.Dst != s.core.gateway(true) || s.probeReply == nil {
		return false
	}
	typ, id, ok := ip.Echo(pkt, h)
	if !ok || typ != ip.EchoReplyV6 || id != s.probeID {
		return false
	}
	s.probeOnce.Do(func() { close(s.probeReply) })
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
	return &sc
}

func (s *session) advertise() error {
	sc := s.current.Load()
	return s.tun.writeCapsule(proto.RouteAdvertisement(sc.routes.Routes(sc.protocol)))
}

func (s *session) readCapsules() error {
	for {
		c, err := s.tun.readCapsule()
		if err != nil {
			var m proto.MalformedError
			if errors.As(err, &m) {
				return errAbort{"malformed capsule stream (" + m.Error() + ")"}
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
				s.stats.dropped.Add(1)
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
		s.stats.dropped.Add(1) // unknown context ID (§5) or empty datagram
		return nil
	}
	h, ok := ip.Parse(pkt)
	if !ok {
		s.stats.dropped.Add(1)
		return nil
	}
	if !s.lease.owns(h.Src) {
		// BCP 38: never forward a source address the client was not given.
		s.stats.dropped.Add(1)
		s.log.Debug("dropping packet with spoofed source", zap.Stringer("src", h.Src))
		return nil
	}
	if s.isProbeReply(pkt, h) {
		return nil
	}
	if !s.current.Load().allows(h) {
		s.stats.dropped.Add(1)
		if e := ip.DestUnreachable(pkt, s.core.gateway(!h.IsIPv4()), ip.AdminProhibited); e != nil && s.icmpAllow() {
			return s.sendToClient(append([]byte{0}, e...))
		}
		return nil
	}
	s.stats.fromClient.Add(1)
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
	case errors.As(err, &tooBig):
		pkt := payload[1:]
		v6 := len(pkt) > 0 && pkt[0]>>4 == 6
		// RFC 9484 §7.2: a tunnel with IPv6 must carry 1280-byte packets;
		// once QUIC DATAGRAM frames are known not to, whatever packet
		// showed it, the stream must be aborted.
		if s.lease.hasIPv6() && tooBig.MaxDatagramPayloadSize < 1+ip.IPv6MinMTU {
			return errAbort{"the path cannot carry 1280-byte IPv6 packets in QUIC datagrams (RFC 9484 §7.2)"}
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
		s.stats.dropped.Add(1)
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
			if a.Is6() == r.Prefix.Addr().Is6() {
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
