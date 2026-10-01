package masque

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"

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
}

func (s *session) icmpAllow() bool {
	s.icmpMu.Lock()
	defer s.icmpMu.Unlock()
	return s.icmp.Allow()
}

// errAbort ends the session with an aborted stream.
type errAbort struct{ why string }

func (e errAbort) Error() string { return "aborted: " + e.why }

// run serves the session until the client ends it, the user is removed,
// or an error ends it. It returns why it ended.
func (s *session) run(ctx context.Context) string {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Tell the client its addresses and where it may send (§4.7).
	assigned := proto.AddressAssign{}
	for _, a := range s.lease.addrs {
		assigned = append(assigned, proto.AssignedAddress{Prefix: proto.Host(a)})
	}
	if err := s.tun.writeCapsule(assigned); err != nil {
		return err.Error()
	}
	s.current.Store(s.narrow())
	if err := s.advertise(); err != nil {
		return err.Error()
	}
	ended := make(chan error, 3)
	go func() { ended <- s.readCapsules() }()
	if s.tun.hasQUICDatagrams() {
		go func() { ended <- s.readDatagrams(ctx) }()
	}
	go func() { ended <- s.sendToClientLoop(ctx) }()
	var err error
	for err == nil {
		select {
		case err = <-ended:
		case <-s.lease.handle.revoked:
			err = errors.New(s.lease.handle.why)
		case <-ctx.Done():
			err = ctx.Err()
		case <-s.lease.handle.rescope:
			// The allowed destinations changed: the latest advertisement
			// replaces the earlier ones (§4.7.3).
			next := s.narrow()
			if !next.routes.Equal(s.current.Load().routes) {
				s.current.Store(next)
				err = s.advertise()
				s.log.Info("routes changed with the configuration", zap.Int("routes", len(next.routes.Routes(next.protocol))))
			}
		}
	}
	var abort errAbort
	if errors.As(err, &abort) {
		s.tun.abort()
	} else {
		s.tun.close()
	}
	if errors.Is(err, io.EOF) {
		return "client closed the tunnel"
	}
	return err.Error()
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
		case p := <-s.lease.handle.toClient:
			if err := s.sendToClient(p); err != nil {
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
		s.stats.dropped.Add(1)
		pkt := payload[1:]
		v6 := len(pkt) > 0 && pkt[0]>>4 == 6
		// RFC 9484 §7.1: an IPv6 tunnel must carry 1280-byte packets; if
		// QUIC DATAGRAM frames cannot, the stream must be aborted.
		if v6 && s.lease.hasIPv6() && tooBig.MaxDatagramPayloadSize < 1+ip.IPv6MinMTU {
			return errAbort{"the path cannot carry 1280-byte IPv6 packets in QUIC datagrams (RFC 9484 §7.1)"}
		}
		// §10.1: drop and report, never fall back to reliable delivery.
		mtu := int(tooBig.MaxDatagramPayloadSize) - 1
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
