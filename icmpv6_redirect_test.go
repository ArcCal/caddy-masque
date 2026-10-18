package masque

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/ArcCal/caddy-masque/internal/ip"
	"github.com/ArcCal/caddy-masque/internal/proto"
)

func TestBlockedICMPv6RedirectDoesNotElicitError(t *testing.T) {
	for _, quicDatagrams := range []bool{false, true} {
		t.Run(map[bool]string{false: "capsules", true: "QUIC datagrams"}[quicDatagrams], func(t *testing.T) {
			e := newTestEnv(t, dualStack())
			r := e.start(t, alice, quicDatagrams)
			send := func(p []byte) {
				payload := append([]byte{0}, p...)
				if quicDatagrams {
					r.tun.datagrams <- payload
				} else {
					r.tun.capsules <- proto.Datagram(payload)
				}
			}
			from, blocked := netip.MustParseAddr(r.addr(true)), netip.MustParseAddr("fd00::123")
			// A blocked Echo Request still gets useful policy feedback.
			send(ip.EchoV6(ip.EchoRequestV6, from, blocked, 42, 1, nil))
			reply := r.tun.nextPacket(t)
			h, ok := ip.Parse(reply)
			if !ok || h.Protocol != ip.ProtoICMPv6 || reply[h.PayloadOffset] != 1 || reply[h.PayloadOffset+1] != 1 {
				t.Fatalf("blocked Echo did not get administratively prohibited: %+v", h)
			}

			// The lease's address passes ingress validation. The Redirect
			// is policy-rejected before host routing; even if it is not a
			// valid neighbor-discovery announcement, it must not elicit an
			// ICMPv6 error (RFC 4443 section 2.4(e.2)).
			redirect := make([]byte, 40)
			redirect[0] = 137
			copy(redirect[8:24], netip.MustParseAddr("fe80::1").AsSlice())
			copy(redirect[24:40], netip.MustParseAddr("2001:db8::80").AsSlice())
			pseudo := make([]byte, 40)
			copy(pseudo[:16], from.AsSlice())
			copy(pseudo[16:32], blocked.AsSlice())
			binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(redirect)))
			pseudo[39] = ip.ProtoICMPv6
			binary.BigEndian.PutUint16(redirect[2:4], ip.Checksum(pseudo, redirect))
			p := packet(from.String(), blocked.String(), ip.ProtoICMPv6, redirect)
			p[7] = 255
			send(p)
			// The next packet traverses the same reader. Observing it at
			// the device establishes the Redirect was processed first.
			send(udp(r.addr(false), "1.1.1.1", 8))
			hostPacket(t, e.dev)
			r.tun.quiet(t)
			noHostPacket(t, e.dev)
		})
	}
}
