package ip

import (
	"encoding/binary"
	"testing"
)

// Redirect is informational, but RFC 4443 section 2.4(e.2) expressly
// excludes it from the messages that may elicit an ICMPv6 error.
func TestICMPv6ErrorSuppression(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  byte
		want bool
	}{
		{"destination unreachable", 1, false},
		{"packet too big", 2, false},
		{"time exceeded", 3, false},
		{"parameter problem", 4, false},
		{"echo request", EchoRequestV6, true},
		{"echo reply", EchoReplyV6, true},
		{"redirect", 137, false},
	} {
		for _, extensions := range []bool{false, true} {
			t.Run(tc.name+map[bool]string{false: "/direct", true: "/destination options"}[extensions], func(t *testing.T) {
				var chain []ext
				if extensions {
					chain = []ext{{60, []byte{0, 0, 1, 4, 0, 0, 0, 0}}}
				}
				icmp := make([]byte, 40)
				icmp[0] = tc.typ
				src, dst := addr("2001:db8::1"), addr("2001:db8::2")
				if tc.typ == 137 {
					src = addr("fe80::1")
					copy(icmp[8:24], addr("fe80::2").AsSlice())
					copy(icmp[24:40], addr("2001:db8::80").AsSlice())
				}
				binary.BigEndian.PutUint16(icmp[2:4], Checksum(pseudoHeader(src, dst, len(icmp), ProtoICMPv6), icmp))
				p := ipv6Packet(src.String(), dst.String(), chain, ProtoICMPv6, icmp)
				p[7] = 255
				for name, got := range map[string][]byte{
					"destination unreachable": DestUnreachable(p, addr("2001:db8::3"), AdminProhibited),
					"packet too big":          PacketTooBig(p, addr("2001:db8::3"), 1280),
				} {
					if (got != nil) != tc.want {
						t.Errorf("%s emitted = %v, want %v", name, got != nil, tc.want)
					}
				}
			})
		}
	}
}

func TestICMPv6ErrorSuppressionSourceAndFragmentControls(t *testing.T) {
	for _, src := range []string{"::", "ff02::1"} {
		p := EchoV6(EchoRequestV6, addr(src), addr("2001:db8::2"), 1, 1, nil)
		if DestUnreachable(p, addr("2001:db8::3"), AdminProhibited) != nil || PacketTooBig(p, addr("2001:db8::3"), 1280) != nil {
			t.Errorf("non-unicast source %s elicited an error", src)
		}
	}
	for _, offset := range []byte{0, 8} {
		frag := ext{44, []byte{0, 0, 0, offset | 1, 0, 0, 0, 7}}
		p := ipv6Packet("2001:db8::1", "2001:db8::2", []ext{frag}, ProtoICMPv6, []byte{1, 0, 0, 0, 0, 0, 0, 0})
		if DestUnreachable(p, addr("2001:db8::3"), AdminProhibited) != nil || PacketTooBig(p, addr("2001:db8::3"), 1280) != nil {
			t.Errorf("ICMPv6 error fragment at offset %d elicited an error", offset>>3)
		}
	}
}

func TestICMPv6RedirectNeverElicitsPacketTooBig(t *testing.T) {
	// Even the multicast exception for Packet Too Big does not override
	// the independent Redirect prohibition in RFC 4443 section 2.4(e.2).
	for _, src := range []string{"::", "ff02::1", "fe80::1"} {
		p := ipv6Packet(src, "ff02::1", nil, ProtoICMPv6, []byte{137, 0, 0, 0, 0, 0, 0, 0})
		if got := PacketTooBig(p, addr("2001:db8::3"), 1280); got != nil {
			t.Errorf("redirect from %s elicited an error", src)
		}
	}
}
