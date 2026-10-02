package ip

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func TestRateLimit(t *testing.T) {
	start := time.Now()
	r := &RateLimit{tokens: icmpBurst, last: start}
	n := 0
	for range 1000 {
		if r.allowAt(start) {
			n++
		}
	}
	if n != icmpBurst {
		t.Fatal(n)
	}
	later := start.Add(100 * time.Millisecond)
	n = 0
	for range 1000 {
		if r.allowAt(later) {
			n++
		}
	}
	if n != icmpRate/10 {
		t.Fatal(n)
	}
	if !r.allowAt(later.Add(time.Minute)) {
		t.Fatal("refill")
	}
}

func ipv4Packet(src, dst [4]byte, protocol byte, payload []byte) []byte {
	total := 20 + len(payload)
	p := []byte{0x45, 0, byte(total >> 8), byte(total), 0, 0, 0x40, 0, 64, protocol, 0, 0}
	p = append(p, src[:]...)
	p = append(p, dst[:]...)
	binary.BigEndian.PutUint16(p[10:12], Checksum(p))
	return append(p, payload...)
}

type ext struct {
	typ   byte
	bytes []byte
}

func ipv6Packet(src, dst string, chain []ext, protocol byte, payload []byte) []byte {
	var body []byte
	for i, e := range chain {
		b := bytes.Clone(e.bytes)
		if i+1 < len(chain) {
			b[0] = chain[i+1].typ
		} else {
			b[0] = protocol
		}
		body = append(body, b...)
	}
	body = append(body, payload...)
	first := protocol
	if len(chain) > 0 {
		first = chain[0].typ
	}
	p := []byte{0x60, 0, 0, 0, byte(len(body) >> 8), byte(len(body)), first, 64}
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	p = append(p, s[:]...)
	p = append(p, d[:]...)
	return append(p, body...)
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestParseIPv4(t *testing.T) {
	p := ipv4Packet([4]byte{10, 89, 0, 2}, [4]byte{1, 1, 1, 1}, 17, make([]byte, 8))
	h, ok := Parse(p)
	if !ok || h.Src != addr("10.89.0.2") || h.Dst != addr("1.1.1.1") || h.Protocol != 17 || h.TotalLen != 28 || h.PayloadOffset != 20 {
		t.Fatal(h)
	}
	if Checksum(p[:20]) != 0 {
		t.Fatal("checksum")
	}
}

func TestRejectsMalformed(t *testing.T) {
	if _, ok := Parse(bytes.Repeat([]byte{0x45}, 10)); ok {
		t.Error("short")
	}
	p := ipv4Packet([4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8}, 6, make([]byte, 20))
	if _, ok := Parse(p[:30]); ok {
		t.Error("truncated v4")
	}
	v6 := ipv6Packet("2001:db8::1", "2001:db8::2", nil, 6, make([]byte, 20))
	if _, ok := Parse(v6[:50]); ok {
		t.Error("truncated v6")
	}
	if _, ok := Parse(bytes.Repeat([]byte{0x70}, 60)); ok {
		t.Error("version 7")
	}
}

func TestIPv6ExtensionHeaders(t *testing.T) {
	hbh := ext{0, []byte{0, 0, 1, 4, 0, 0, 0, 0}}
	dstOpts := ext{60, []byte{0, 1, 1, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}
	h, ok := Parse(ipv6Packet("2001:db8::1", "2001:db8::2", []ext{hbh, dstOpts}, 6, make([]byte, 20)))
	if !ok || h.Protocol != 6 || h.PayloadOffset != 40+8+16 || !h.FirstFragment {
		t.Fatal(h)
	}
}

func TestIPv6Fragments(t *testing.T) {
	first := ext{44, []byte{0, 0, 0, 1, 0, 0, 0, 7}}
	h, _ := Parse(ipv6Packet("2001:db8::1", "2001:db8::2", []ext{first}, 17, make([]byte, 16)))
	if h.Protocol != 17 || !h.FirstFragment || h.PayloadOffset != 48 {
		t.Fatal(h)
	}
	later := ext{44, []byte{0, 0, 0x05, 0x00, 0, 0, 0, 7}}
	h, _ = Parse(ipv6Packet("2001:db8::1", "2001:db8::2", []ext{later}, 17, make([]byte, 16)))
	if h.Protocol != 17 || h.FirstFragment || h.PayloadOffset != -1 || !h.Fragment || h.FragmentID != 7 || h.ProtocolUnknown {
		t.Fatal(h)
	}
	// Destination Options after the Fragment header: only the first
	// fragment shows the upper layer.
	dstOpts := ext{60, []byte{0, 0, 1, 4, 0, 0, 0, 0}}
	h, _ = Parse(ipv6Packet("2001:db8::1", "2001:db8::2", []ext{first, dstOpts}, 6, make([]byte, 20)))
	if h.Protocol != 6 || !h.FirstFragment || !h.Fragment || h.ProtocolUnknown {
		t.Fatal(h)
	}
	h, _ = Parse(ipv6Packet("2001:db8::1", "2001:db8::2", []ext{later}, 60, make([]byte, 16)))
	if h.Protocol != 60 || h.FirstFragment || !h.ProtocolUnknown {
		t.Fatal(h)
	}
	if h, _ := Parse(ipv6Packet("2001:db8::1", "2001:db8::2", nil, 6, make([]byte, 20))); h.Fragment {
		t.Fatal(h)
	}
}

func TestIPv4FragNeeded(t *testing.T) {
	original := ipv4Packet([4]byte{10, 89, 0, 2}, [4]byte{93, 184, 216, 34}, 6, bytes.Repeat([]byte{0xaa}, 1400))
	e := PacketTooBig(original, addr("10.89.0.1"), 1300)
	h, ok := Parse(e)
	if !ok || h.Src != addr("10.89.0.1") || h.Dst != addr("10.89.0.2") || h.Protocol != 1 || h.TotalLen != 576 {
		t.Fatal(h)
	}
	if Checksum(e[:20]) != 0 || Checksum(e[20:]) != 0 {
		t.Fatal("checksums")
	}
	if e[20] != 3 || e[21] != 4 || binary.BigEndian.Uint16(e[26:28]) != 1300 || !bytes.Equal(e[28:48], original[:20]) {
		t.Fatal(e[20:48])
	}
}

func TestICMPv6PacketTooBig(t *testing.T) {
	original := ipv6Packet("fd89::2", "2001:db8::80", nil, 6, bytes.Repeat([]byte{0xaa}, 1400))
	e := PacketTooBig(original, addr("fd89::1"), 1300)
	h, ok := Parse(e)
	if !ok || h.Src != addr("fd89::1") || h.Dst != addr("fd89::2") || h.Protocol != 58 || len(e) != IPv6MinMTU {
		t.Fatal(h, len(e))
	}
	if Checksum(pseudoHeader(h.Src, h.Dst, len(e)-40, ProtoICMPv6), e[40:]) != 0 {
		t.Fatal("checksum")
	}
	if e[40] != 2 || e[41] != 0 || binary.BigEndian.Uint32(e[44:48]) != 1300 || !bytes.Equal(e[48:88], original[:40]) {
		t.Fatal(e[40:88])
	}
}

func TestCodes(t *testing.T) {
	v6 := ipv6Packet("2001:db8::bad", "2001:db8::80", nil, 17, make([]byte, 8))
	if e := DestUnreachable(v6, addr("fd89::1"), SourcePolicy); e[40] != 1 || e[41] != 5 {
		t.Error("v6 source policy")
	}
	if e := DestUnreachable(v6, addr("fd89::1"), PortUnreachable); e[40] != 1 || e[41] != 4 {
		t.Error("v6 port")
	}
	v4 := ipv4Packet([4]byte{10, 1, 1, 1}, [4]byte{1, 1, 1, 1}, 17, make([]byte, 8))
	if e := DestUnreachable(v4, addr("10.89.0.1"), SourcePolicy); e[20] != 3 || e[21] != 13 {
		t.Error("v4 source policy")
	}
	if e := DestUnreachable(v4, addr("10.89.0.1"), PortUnreachable); e[20] != 3 || e[21] != 3 {
		t.Error("v4 port")
	}
	if DestUnreachable(v4, addr("fd89::1"), NoRoute) != nil {
		t.Error("family mismatch")
	}
}

func TestNoErrorsAboutErrorsOrMulticast(t *testing.T) {
	gw4, gw6 := addr("10.89.0.1"), addr("fd89::1")
	icmpErr := ipv4Packet([4]byte{1, 1, 1, 1}, [4]byte{10, 89, 0, 2}, ProtoICMP, []byte{3, 1, 0, 0, 0, 0, 0, 0})
	if PacketTooBig(icmpErr, gw4, 1300) != nil {
		t.Error("error about an error")
	}
	echo := ipv4Packet([4]byte{10, 89, 0, 2}, [4]byte{1, 1, 1, 1}, ProtoICMP, []byte{8, 0, 0, 0, 0, 0, 0, 0})
	if PacketTooBig(echo, gw4, 1300) == nil {
		t.Error("echo")
	}
	v6Err := ipv6Packet("2001:db8::1", "fd89::2", nil, ProtoICMPv6, []byte{1, 0, 0, 0, 0, 0, 0, 0})
	if DestUnreachable(v6Err, gw6, NoRoute) != nil {
		t.Error("v6 error about an error")
	}
	v6Echo := ipv6Packet("fd89::2", "2001:db8::1", nil, ProtoICMPv6, []byte{128, 0, 0, 0, 0, 0, 0, 0})
	if DestUnreachable(v6Echo, gw6, NoRoute) == nil {
		t.Error("v6 echo")
	}
	mcast := ipv6Packet("fd89::2", "ff02::1", nil, 17, make([]byte, 8))
	if DestUnreachable(mcast, gw6, NoRoute) != nil {
		t.Error("multicast")
	}
	if PacketTooBig(mcast, gw6, 1280) == nil {
		t.Error("PTB for multicast is allowed")
	}
	bcast := ipv4Packet([4]byte{10, 89, 0, 2}, [4]byte{255, 255, 255, 255}, 17, make([]byte, 8))
	if PacketTooBig(bcast, gw4, 1300) != nil {
		t.Error("broadcast")
	}
}

func TestICMPv6Echo(t *testing.T) {
	src, dst := addr("fd89::1"), addr("fd89::2")
	req := EchoV6(EchoRequestV6, src, dst, 0x1234, 7, IPv6MinMTU-48)
	h, ok := Parse(req)
	if !ok || len(req) != IPv6MinMTU || h.Src != src || h.Dst != dst || h.Protocol != ProtoICMPv6 {
		t.Fatalf("request: %+v, %d bytes", h, len(req))
	}
	valid := func(p []byte, h Header) bool {
		return Checksum(pseudoHeader(h.Src, h.Dst, h.TotalLen-40, ProtoICMPv6), p[40:h.TotalLen]) == 0
	}
	if typ, id, ok := Echo(req, h); !ok || typ != EchoRequestV6 || id != 0x1234 || !valid(req, h) {
		t.Errorf("request: %d %#x %v", typ, id, ok)
	}
	req[100] = 0xab // data is echoed back
	binary.BigEndian.PutUint16(req[42:44], 0)
	binary.BigEndian.PutUint16(req[42:44], Checksum(pseudoHeader(src, dst, len(req)-40, ProtoICMPv6), req[40:]))
	reply := EchoReply(req)
	rh, ok := Parse(reply)
	if typ, id, ok2 := Echo(reply, rh); !ok || !ok2 || typ != EchoReplyV6 || id != 0x1234 || rh.Src != dst || rh.Dst != src ||
		reply[47] != 7 || reply[100] != 0xab || !valid(reply, rh) {
		t.Errorf("reply: %+v % x", rh, reply[40:48])
	}
	if EchoReply(reply) != nil {
		t.Error("a reply was answered")
	}
}
