package ip

import "testing"

// Authenticated peers control packet bytes. Exercise header bounds and the
// ICMP/fragmentation paths together, including truncated extension headers.
func FuzzPacketProcessing(f *testing.F) {
	f.Add([]byte{})
	f.Add(ipv4Packet([4]byte{10, 89, 0, 2}, [4]byte{1, 1, 1, 1}, ProtoUDP, make([]byte, 8)))
	f.Add(ipv6Packet("fd89::2", "2606:4700::1111", nil, ProtoUDP, make([]byte, 8)))
	f.Add(ipv6Packet("fd89::2", "2606:4700::1111", []ext{{protoFragment, make([]byte, 8)}}, ProtoUDP, make([]byte, 8)))
	f.Fuzz(func(t *testing.T, packet []byte) {
		h, ok := Parse(packet)
		if !ok {
			return
		}
		if !h.Src.IsValid() || !h.Dst.IsValid() || h.Src.Is4() != h.Dst.Is4() || h.TotalLen > len(packet) || h.TotalLen < 20 || h.PayloadOffset < -1 || h.PayloadOffset > h.TotalLen {
			t.Fatalf("invalid parsed header: %+v", h)
		}
		for _, reply := range [][]byte{DestUnreachable(packet, h.Dst, AdminProhibited), PacketTooBig(packet, h.Dst, 1280)} {
			if reply != nil {
				if _, valid := Parse(reply); !valid {
					t.Fatal("generated malformed ICMP response")
				}
			}
		}
		for _, fragment := range Fragment(packet, 1280) {
			if parsed, valid := Parse(fragment); !valid || parsed.TotalLen > 1280 {
				t.Fatal("generated invalid fragment")
			}
		}
	})
}
