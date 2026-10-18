// Package ip handles IPv4 and IPv6 packets: the header fields the RFC 9484
// forwarding checks need, and ICMP and ICMPv6 error messages (RFC 792,
// RFC 1812 §4.3.2, RFC 4443). It follows masque-vpn's ip module.
package ip

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"time"

	"github.com/ArcCal/caddy-masque/internal/proto"
)

const (
	ProtoICMP   = 1
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58

	protoFragment     = 44
	protoAH           = 51
	protoESP          = 50
	protoNoNextHeader = 59
)

// IPv6MinMTU is the IPv6 minimum link MTU (RFC 8200 §5).
const IPv6MinMTU = 1280

// Header holds the fields this module looks at.
type Header struct {
	Src, Dst netip.Addr
	// Upper-layer protocol; for IPv6 found by walking the extension
	// headers, as RFC 9484 §4.8 requires.
	Protocol uint8
	// Offset of the upper-layer header, or -1 if the packet lacks it.
	PayloadOffset int
	// Length of the packet according to its header.
	TotalLen int
	// False for non-initial fragments.
	FirstFragment bool
	// An IPv6 packet with a Fragment header, and its identification.
	Fragment   bool
	FragmentID uint32
	// A later IPv6 fragment whose upper-layer protocol is not in it: the
	// Fragment header names another extension header, which only the first
	// fragment carries. Protocol is that extension header's number.
	ProtocolUnknown bool
}

// IsIPv4 reports the family.
func (h Header) IsIPv4() bool { return h.Src.Is4() }

// Parse parses an IPv4 or IPv6 header; false for anything malformed.
func Parse(p []byte) (Header, bool) {
	if len(p) == 0 {
		return Header{}, false
	}
	switch p[0] >> 4 {
	case 4:
		return parseV4(p)
	case 6:
		return parseV6(p)
	}
	return Header{}, false
}

func parseV4(p []byte) (Header, bool) {
	if len(p) < 20 {
		return Header{}, false
	}
	headerLen := int(p[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(p[2:4]))
	if headerLen < 20 || total < headerLen || total > len(p) {
		return Header{}, false
	}
	// Validate before any local ICMP response or forwarding. The kernel
	// cannot discard checksum-invalid packets that policy rejects here
	// in userspace (RFC 1812 §§4.2.2.5 and 4.3.2.7).
	if Checksum(p[:headerLen]) != 0 {
		return Header{}, false
	}
	first := binary.BigEndian.Uint16(p[6:8])&0x1fff == 0
	off := -1
	if first {
		off = headerLen
	}
	return Header{
		Src:           netip.AddrFrom4([4]byte(p[12:16])),
		Dst:           netip.AddrFrom4([4]byte(p[16:20])),
		Protocol:      p[9],
		PayloadOffset: off,
		TotalLen:      total,
		FirstFragment: first,
	}, true
}

func parseV6(p []byte) (Header, bool) {
	if len(p) < 40 {
		return Header{}, false
	}
	total := 40 + int(binary.BigEndian.Uint16(p[4:6]))
	if total > len(p) {
		return Header{}, false
	}
	next := p[6]
	off := 40
	first := true
	fragment, fragID := false, uint32(0)
	// Walk the extension headers to the upper layer. ESP encrypts the rest,
	// so it counts as the upper layer.
	for proto.IsIPv6ExtensionHeader(next) && next != protoESP {
		end := min(off+8, total)
		if end-off < 2 {
			return Header{}, false
		}
		hdr := p[off:end]
		this := next
		next = hdr[0]
		switch this {
		case protoFragment:
			if len(hdr) < 8 {
				return Header{}, false
			}
			if binary.BigEndian.Uint16(hdr[2:4])>>3 != 0 {
				first = false
			}
			fragment, fragID = true, binary.BigEndian.Uint32(hdr[4:8])
			off += 8
		case protoAH:
			off += (int(hdr[1]) + 2) * 4
		default:
			off += (int(hdr[1]) + 1) * 8
		}
		if off > total {
			return Header{}, false
		}
		if !first {
			break // later fragments lack the upper-layer header
		}
	}
	payload := -1
	if first && next != protoNoNextHeader {
		payload = off
	}
	return Header{
		Src:             netip.AddrFrom16([16]byte(p[8:24])),
		Dst:             netip.AddrFrom16([16]byte(p[24:40])),
		Protocol:        next,
		PayloadOffset:   payload,
		TotalLen:        total,
		FirstFragment:   first,
		Fragment:        fragment,
		FragmentID:      fragID,
		ProtocolUnknown: !first && proto.IsIPv6ExtensionHeader(next) && next != protoESP,
	}, true
}

// Checksum is the Internet checksum (RFC 1071) over the parts, joined.
func Checksum(parts ...[]byte) uint16 {
	var sum uint32
	var odd bool
	var hi byte
	for _, part := range parts {
		for _, b := range part {
			if odd {
				sum += uint32(hi)<<8 | uint32(b)
				odd = false
			} else {
				hi, odd = b, true
			}
		}
	}
	if odd {
		sum += uint32(hi) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// RateLimit limits the ICMP errors one sender originates: RFC 4443 §2.4
// (f) requires it for ICMPv6 and RFC 1812 §4.3.2.8 asks for it for IPv4.
// A token bucket allows short bursts (enough for "packet too big" to reach
// every flow) but no sustained stream. Not safe for concurrent use.
type RateLimit struct {
	tokens float64
	last   time.Time
}

const (
	icmpRate  = 100.0 // per second
	icmpBurst = 100.0
)

// NewRateLimit starts with a full bucket.
func NewRateLimit() *RateLimit { return &RateLimit{tokens: icmpBurst, last: time.Now()} }

// Allow reports whether one more error may be sent now.
func (r *RateLimit) Allow() bool { return r.allowAt(time.Now()) }

func (r *RateLimit) allowAt(now time.Time) bool {
	elapsed := now.Sub(r.last).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	r.last = now
	r.tokens = min(r.tokens+elapsed*icmpRate, icmpBurst)
	if r.tokens >= 1 {
		r.tokens--
		return true
	}
	return false
}

// Unreachable is why a packet could not be delivered.
type Unreachable int

const (
	NoRoute         Unreachable = iota // no route to the destination
	AdminProhibited                    // forwarding is not allowed
	SourcePolicy                       // the source address is not the sender's (RFC 9484 §7.2.1)
	PortUnreachable                    // nothing listens on the port
)

// DestUnreachable is an ICMP or ICMPv6 Destination Unreachable from `from`
// to the source of original; nil when no error may be sent or from is of
// the other family.
func DestUnreachable(original []byte, from netip.Addr, why Unreachable) []byte {
	h, ok := Parse(original)
	if !ok || h.Src.Is4() != from.Is4() {
		return nil
	}
	if h.IsIPv4() {
		code := map[Unreachable]byte{NoRoute: 0, PortUnreachable: 3,
			// IPv4 has no code for a bad source; RFC 1812 uses
			// "communication administratively prohibited".
			AdminProhibited: 13, SourcePolicy: 13}[why]
		return icmpv4Error(original, h, from, 3, code, [4]byte{})
	}
	code := map[Unreachable]byte{NoRoute: 0, AdminProhibited: 1, PortUnreachable: 4, SourcePolicy: 5}[why]
	return icmpv6Error(original, h, from, 1, code, [4]byte{})
}

// PacketTooBig is ICMP Fragmentation Needed or ICMPv6 Packet Too Big
// carrying mtu.
func PacketTooBig(original []byte, from netip.Addr, mtu int) []byte {
	h, ok := Parse(original)
	if !ok || h.Src.Is4() != from.Is4() {
		return nil
	}
	if h.IsIPv4() {
		v := uint16(min(mtu, 0xffff))
		return icmpv4Error(original, h, from, 3, 4, [4]byte{0, 0, byte(v >> 8), byte(v)})
	}
	// Packet Too Big below the IPv6 minimum MTU is not meaningful.
	var rest [4]byte
	binary.BigEndian.PutUint32(rest[:], uint32(max(mtu, IPv6MinMTU)))
	return icmpv6Error(original, h, from, 2, 0, rest)
}

func icmpTypeAt(original []byte, h Header) (byte, bool) {
	if h.PayloadOffset < 0 || h.PayloadOffset >= len(original) {
		return 0, false
	}
	return original[h.PayloadOffset], true
}

func isBroadcast4(a netip.Addr) bool { return a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) }

// RFC 1812 §4.3.2.7: no errors about ICMP errors, non-initial fragments,
// or packets that do not identify a single host.
func mayICMPv4Error(original []byte, h Header) bool {
	if !h.FirstFragment || h.Src.IsUnspecified() || isBroadcast4(h.Src) || h.Src.IsMulticast() {
		return false
	}
	if isBroadcast4(h.Dst) || h.Dst.IsMulticast() {
		return false
	}
	if h.Protocol == ProtoICMP {
		// Only informational messages (echo, timestamp) may cause errors.
		t, ok := icmpTypeAt(original, h)
		return ok && (t == 0 || t == 8 || t == 13 || t == 14)
	}
	return true
}

// RFC 4443 §2.4 (e): no errors about ICMPv6 errors, from unspecified or
// multicast sources, or (except Packet Too Big) to multicast destinations.
func mayICMPv6Error(original []byte, h Header, icmpType byte) bool {
	if h.Src.IsUnspecified() || h.Src.IsMulticast() {
		return false
	}
	if h.Dst.IsMulticast() && icmpType != 2 {
		return false
	}
	if h.Protocol == ProtoICMPv6 {
		t, ok := icmpTypeAt(original, h)
		return ok && t >= 128 // below 128 are errors
	}
	return true
}

func icmpv4Error(original []byte, h Header, from netip.Addr, typ, code byte, rest [4]byte) []byte {
	if !mayICMPv4Error(original, h) {
		return nil
	}
	// Quote as much as fits in a 576-byte datagram.
	quoted := original[:min(h.TotalLen, 576-20-8)]
	total := 20 + 8 + len(quoted)
	out := make([]byte, 0, total)
	out = append(out, 0x45, 0xc0) // version 4, 20 bytes; DSCP CS6 as routers use
	out = binary.BigEndian.AppendUint16(out, uint16(total))
	out = append(out, 0, 0, 0, 0, 64, ProtoICMP, 0, 0) // id, flags, TTL 64, checksum later
	out = append(out, from.AsSlice()...)
	out = append(out, h.Src.AsSlice()...)
	binary.BigEndian.PutUint16(out[10:12], Checksum(out[:20]))
	out = append(out, typ, code, 0, 0)
	out = append(out, rest[:]...)
	out = append(out, quoted...)
	binary.BigEndian.PutUint16(out[22:24], Checksum(out[20:]))
	return out
}

func icmpv6Error(original []byte, h Header, from netip.Addr, typ, code byte, rest [4]byte) []byte {
	if !mayICMPv6Error(original, h, typ) {
		return nil
	}
	// RFC 4443 §2.4 (c): no larger than the minimum IPv6 MTU.
	quoted := original[:min(h.TotalLen, IPv6MinMTU-40-8)]
	icmpLen := 8 + len(quoted)
	out := make([]byte, 0, 40+icmpLen)
	out = append(out, 0x60, 0, 0, 0)
	out = binary.BigEndian.AppendUint16(out, uint16(icmpLen))
	out = append(out, ProtoICMPv6, 64)
	out = append(out, from.AsSlice()...)
	out = append(out, h.Src.AsSlice()...)
	out = append(out, typ, code, 0, 0)
	out = append(out, rest[:]...)
	out = append(out, quoted...)
	binary.BigEndian.PutUint16(out[42:44], Checksum(pseudoHeader(from, h.Src, icmpLen, ProtoICMPv6), out[40:]))
	return out
}

// ICMPv6 Echo Request and Echo Reply types (RFC 4443 §4).
const (
	EchoRequestV6 = 128
	EchoReplyV6   = 129
)

// EchoV6 is an ICMPv6 Echo message (RFC 4443 §4) from src to dst with the
// identifier, sequence number and data.
func EchoV6(typ byte, src, dst netip.Addr, id, seq uint16, data []byte) []byte {
	icmpLen := 8 + len(data)
	out := make([]byte, 40+icmpLen)
	out[0] = 0x60
	binary.BigEndian.PutUint16(out[4:6], uint16(icmpLen))
	out[6], out[7] = ProtoICMPv6, 64
	copy(out[8:24], src.AsSlice())
	copy(out[24:40], dst.AsSlice())
	out[40] = typ
	binary.BigEndian.PutUint16(out[44:46], id)
	binary.BigEndian.PutUint16(out[46:48], seq)
	copy(out[48:], data)
	binary.BigEndian.PutUint16(out[42:44], Checksum(pseudoHeader(src, dst, icmpLen, ProtoICMPv6), out[40:]))
	return out
}

// EchoMessage is an ICMPv6 Echo Request or Reply.
type EchoMessage struct {
	Type    byte
	ID, Seq uint16
	Data    []byte // in the packet
}

// Echo reads an ICMPv6 Echo message, p parsed as h; false for anything
// else, a fragment, or a wrong checksum.
func Echo(p []byte, h Header) (EchoMessage, bool) {
	if h.IsIPv4() || h.Protocol != ProtoICMPv6 || h.Fragment || h.PayloadOffset < 0 || h.PayloadOffset+8 > h.TotalLen {
		return EchoMessage{}, false
	}
	icmp := p[h.PayloadOffset:h.TotalLen]
	if icmp[0] != EchoRequestV6 && icmp[0] != EchoReplyV6 || icmp[1] != 0 ||
		Checksum(pseudoHeader(h.Src, h.Dst, len(icmp), ProtoICMPv6), icmp) != 0 {
		return EchoMessage{}, false
	}
	return EchoMessage{Type: icmp[0], ID: binary.BigEndian.Uint16(icmp[4:6]), Seq: binary.BigEndian.Uint16(icmp[6:8]), Data: icmp[8:]}, true
}

// EchoReply answers an ICMPv6 Echo Request as an IPv6 node does, returning
// its data unmodified (RFC 4443 §4.2), or returns nil.
func EchoReply(request []byte) []byte {
	h, ok := Parse(request)
	if !ok {
		return nil
	}
	m, ok := Echo(request, h)
	if !ok || m.Type != EchoRequestV6 {
		return nil
	}
	return EchoV6(EchoReplyV6, h.Dst, h.Src, m.ID, m.Seq, m.Data)
}

// pseudoHeader is the IPv6 pseudo-header for upper-layer checksums (RFC
// 8200 §8.1).
func pseudoHeader(src, dst netip.Addr, upperLen int, next byte) []byte {
	ph := make([]byte, 40)
	copy(ph[:16], src.AsSlice())
	copy(ph[16:32], dst.AsSlice())
	binary.BigEndian.PutUint32(ph[32:36], uint32(upperLen))
	ph[39] = next
	return ph
}

// Fragment splits an IPv4 packet into fragments of at most mtu bytes, as
// a router does (RFC 791 §3.2, RFC 1812 §5.2.6). nil when the packet may not
// be fragmented (DF set, or not IPv4) or mtu leaves no room for data.
// Options without the copied flag go in the first fragment only.
func Fragment(p []byte, mtu int) [][]byte {
	h, ok := Parse(p)
	if !ok || !h.IsIPv4() {
		return nil
	}
	p = p[:h.TotalLen]
	flags := binary.BigEndian.Uint16(p[6:8])
	if flags&0x4000 != 0 { // DF
		return nil
	}
	headerLen := int(p[0]&0x0f) * 4
	if len(p) <= mtu {
		return [][]byte{p}
	}
	firstHeader := p[:headerLen]
	laterHeader := laterFragmentHeader(firstHeader)
	data := p[headerLen:]
	baseOffset := int(flags&0x1fff) * 8
	moreAfter := flags&0x2000 != 0 // MF of the packet itself
	var out [][]byte
	for pos := 0; pos < len(data); {
		hdr := laterHeader
		if pos == 0 {
			hdr = firstHeader
		}
		room := (mtu - len(hdr)) &^ 7
		if room <= 0 {
			return nil
		}
		n := min(room, len(data)-pos)
		f := make([]byte, len(hdr)+n)
		copy(f, hdr)
		copy(f[len(hdr):], data[pos:pos+n])
		f[0] = 0x40 | byte(len(hdr)/4)
		binary.BigEndian.PutUint16(f[2:4], uint16(len(f)))
		ff := uint16((baseOffset + pos) / 8)
		if pos+n < len(data) || moreAfter {
			ff |= 0x2000
		}
		binary.BigEndian.PutUint16(f[6:8], ff)
		f[10], f[11] = 0, 0
		binary.BigEndian.PutUint16(f[10:12], Checksum(f[:len(hdr)]))
		out = append(out, f)
		pos += n
	}
	return out
}

// laterFragmentHeader is the header of fragments after the first: only
// the options with the copied flag, padded to a multiple of four bytes.
func laterFragmentHeader(h []byte) []byte {
	out := slices.Clone(h[:20])
	opts := h[20:]
	for i := 0; i < len(opts); {
		t := opts[i]
		if t == 0 { // end of options
			break
		}
		if t == 1 { // no-operation
			i++
			continue
		}
		if i+1 >= len(opts) || opts[i+1] < 2 || i+int(opts[i+1]) > len(opts) {
			break // malformed: copy nothing more
		}
		n := int(opts[i+1])
		if t&0x80 != 0 {
			out = append(out, opts[i:i+n]...)
		}
		i += n
	}
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	return out
}
