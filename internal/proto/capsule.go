// Package proto implements the wire formats of CONNECT-IP: the Capsule
// Protocol (RFC 9297 §3.2), the CONNECT-IP capsules (RFC 9484 §4.7),
// HTTP Datagram context IDs (RFC 9484 §6), request scopes (§4.6) and URI
// Templates as RFC 9484 §3 restricts them. It follows the masque-vpn Rust
// crate masque-proto, whose tests it carries over.
package proto

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"github.com/quic-go/quic-go/quicvarint"
)

// Capsule types.
const (
	TypeDatagram           = 0x00 // RFC 9297 §3.5
	TypeAddressAssign      = 0x01 // RFC 9484 §4.7.1
	TypeAddressRequest     = 0x02 // RFC 9484 §4.7.2
	TypeRouteAdvertisement = 0x03 // RFC 9484 §4.7.3
)

// ErrIncomplete means more stream data is needed.
var ErrIncomplete = errors.New("incomplete")

// MalformedError marks a message that violates the protocol; the request
// stream must be aborted.
type MalformedError string

func (e MalformedError) Error() string { return "malformed: " + string(e) }

// RawCapsule is a capsule whose value has not been interpreted yet.
type RawCapsule struct {
	Type  uint64
	Value []byte
}

// AppendCapsule appends a capsule with the given type and value.
func AppendCapsule(out []byte, capsuleType uint64, value []byte) []byte {
	out = quicvarint.Append(out, capsuleType)
	out = quicvarint.Append(out, uint64(len(value)))
	return append(out, value...)
}

// DefaultMaxValueLen is the largest capsule value a decoder buffers by
// default: enough for a DATAGRAM capsule with a maximum-size IP packet.
const DefaultMaxValueLen = 65535 + 8

// Decoder reassembles capsules from a byte stream that may split them at
// any point.
type Decoder struct {
	buf         []byte
	maxValueLen int
	// An oversized capsule of an unknown type being skipped.
	skipping    bool
	skippedType uint64
	skipRemains uint64
}

// NewDecoder limits buffered values to maxValueLen. Oversized control
// capsules are rejected; oversized DATAGRAM and unknown capsules are
// skipped as they arrive.
func NewDecoder(maxValueLen int) *Decoder {
	return &Decoder{maxValueLen: maxValueLen}
}

// Push appends newly received stream data.
func (d *Decoder) Push(data []byte) {
	if d.skipping && d.skipRemains > 0 {
		n := min(d.skipRemains, uint64(len(data)))
		data = data[n:]
		d.skipRemains -= n
	}
	d.buf = append(d.buf, data...)
}

func readVarint(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, ErrIncomplete
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, ErrIncomplete
	}
	v, l, err := quicvarint.Parse(b[:n])
	if err != nil {
		return 0, 0, ErrIncomplete
	}
	return v, l, nil
}

func knownType(t uint64) bool {
	return t == TypeDatagram || t == TypeAddressAssign || t == TypeAddressRequest || t == TypeRouteAdvertisement
}

// Next returns the next complete capsule, or ErrIncomplete if more data is
// needed.
func (d *Decoder) Next() (RawCapsule, error) {
	if d.skipping {
		if d.skipRemains != 0 {
			return RawCapsule{}, ErrIncomplete
		}
		d.skipping = false
		return RawCapsule{Type: d.skippedType}, nil
	}
	t, n1, err := readVarint(d.buf)
	if err != nil {
		return RawCapsule{}, err
	}
	l, n2, err := readVarint(d.buf[n1:])
	if err != nil {
		return RawCapsule{}, err
	}
	header := n1 + n2
	if l > uint64(d.maxValueLen) {
		if knownType(t) && t != TypeDatagram {
			return RawCapsule{}, MalformedError("capsule value exceeds size limit")
		}
		// RFC 9297: unknown types MUST be ignored, whatever their length,
		// and a DATAGRAM capsule too large to be usable SHOULD be discarded
		// without buffering its contents (§3.5); it comes out empty.
		d.buf = d.buf[header:]
		discard := min(l, uint64(len(d.buf)))
		d.buf = d.buf[discard:]
		d.skipping, d.skippedType, d.skipRemains = true, t, l-discard
		return d.Next()
	}
	if uint64(len(d.buf)-header) < l {
		return RawCapsule{}, ErrIncomplete
	}
	value := make([]byte, l)
	copy(value, d.buf[header:header+int(l)])
	d.buf = d.buf[header+int(l):]
	if len(d.buf) == 0 {
		d.buf = nil // let the backing array go
	}
	return RawCapsule{Type: t, Value: value}, nil
}

// Finish checks the end of the stream: a capsule cut off by it makes the
// message malformed (RFC 9297 §3.3).
func (d *Decoder) Finish() error {
	if len(d.buf) == 0 && (!d.skipping || d.skipRemains == 0) {
		return nil
	}
	return MalformedError("stream ended inside a capsule")
}

// Prefix is an IP address with a prefix length whose host bits are zero.
type Prefix = netip.Prefix

// NewPrefix validates the rules of RFC 9484 §4.7.1 and §4.7.2: the length
// fits the family and the bits outside the prefix are zero.
func NewPrefix(addr netip.Addr, bits int) (Prefix, error) {
	if bits < 0 || bits > addr.BitLen() {
		return Prefix{}, MalformedError("prefix length longer than address")
	}
	p := netip.PrefixFrom(addr, bits)
	if p.Masked().Addr() != addr {
		return Prefix{}, MalformedError("bits outside the prefix are not zero")
	}
	return p, nil
}

// Host is a /32 or /128 prefix for one address.
func Host(addr netip.Addr) Prefix { return netip.PrefixFrom(addr, addr.BitLen()) }

// Unspecified is 0.0.0.0/32 or ::/128: in an ADDRESS_ASSIGN it rejects a
// request; in an ADDRESS_REQUEST it asks for any address of the family.
func Unspecified(v6 bool) Prefix {
	if v6 {
		return Host(netip.IPv6Unspecified())
	}
	return Host(netip.IPv4Unspecified())
}

// IsUnspecifiedHost reports 0.0.0.0/32 and ::/128.
func IsUnspecifiedHost(p Prefix) bool {
	return p.Addr().IsUnspecified() && p.Bits() == p.Addr().BitLen()
}

// AssignedAddress is one entry of an ADDRESS_ASSIGN capsule.
type AssignedAddress struct {
	RequestID uint64 // the ADDRESS_REQUEST entry this answers, or 0
	Prefix    Prefix
}

// RequestedAddress is one entry of an ADDRESS_REQUEST capsule.
type RequestedAddress struct {
	RequestID uint64 // non-zero
	Prefix    Prefix // all-zero: any address of the family
}

// AddressRange is one entry of a ROUTE_ADVERTISEMENT capsule: an inclusive
// range and the IP protocol allowed to it (0: all).
type AddressRange struct {
	Start, End netip.Addr
	Protocol   uint8
}

// NewAddressRange checks that start and end are of one family and ordered.
func NewAddressRange(start, end netip.Addr, protocol uint8) (AddressRange, error) {
	if start.Is4() != end.Is4() {
		return AddressRange{}, MalformedError("route start and end differ in IP version")
	}
	if end.Less(start) {
		return AddressRange{}, MalformedError("route start is after route end")
	}
	return AddressRange{start, end, protocol}, nil
}

func (r AddressRange) version() int {
	if r.Start.Is4() {
		return 4
	}
	return 6
}

func (r AddressRange) overlaps(o AddressRange) bool {
	return r.version() == o.version() && r.Start.Compare(o.End) <= 0 && o.Start.Compare(r.End) <= 0
}

// ValidateRoutes checks the ordering and overlap rules of RFC 9484 §4.7.3.
func ValidateRoutes(ranges []AddressRange) error {
	for i := 1; i < len(ranges); i++ {
		a, b := ranges[i-1], ranges[i]
		var ordered bool
		switch {
		case a.version() != b.version():
			ordered = a.version() < b.version()
		case a.Protocol != b.Protocol:
			ordered = a.Protocol < b.Protocol
		default:
			ordered = a.End.Less(b.Start)
		}
		if !ordered {
			return MalformedError("routes are not ordered or overlap")
		}
	}
	// A protocol-0 range must not overlap a range for a specific protocol.
	// Checking every pair would take quadratic time, which a peer could
	// exploit with one large capsule. Within each IP version the protocol-0
	// ranges come first and are sorted and disjoint (checked above), so
	// their ends ascend with their starts: of those starting at or before a
	// range's end, only the last can reach back into it.
	for len(ranges) > 0 {
		n := 1
		for n < len(ranges) && ranges[n].version() == ranges[0].version() {
			n++
		}
		version := ranges[:n]
		ranges = ranges[n:]
		zeros := sort.Search(len(version), func(i int) bool { return version[i].Protocol != 0 })
		all, specific := version[:zeros], version[zeros:]
		for _, r := range specific {
			before := sort.Search(len(all), func(i int) bool { return r.End.Less(all[i].Start) })
			if before > 0 && all[before-1].overlaps(r) {
				return MalformedError("protocol-0 route overlaps a protocol-specific route")
			}
		}
	}
	return nil
}

// Capsule is a decoded CONNECT-IP capsule: one of *Datagram,
// AddressAssign, AddressRequest, RouteAdvertisement or Unknown.
type Capsule interface{ capsule() }

type (
	// Datagram is an HTTP Datagram payload sent on the stream (RFC 9297 §3.5).
	Datagram []byte
	// AddressAssign is the full set of addresses assigned to the receiver.
	AddressAssign []AssignedAddress
	// AddressRequest lists addresses the sender asks for.
	AddressRequest []RequestedAddress
	// RouteAdvertisement is the full set of routes the sender forwards to.
	RouteAdvertisement []AddressRange
	// Unknown is a capsule type this endpoint ignores (RFC 9297 §3.2).
	Unknown RawCapsule
)

func (Datagram) capsule()           {}
func (AddressAssign) capsule()      {}
func (AddressRequest) capsule()     {}
func (RouteAdvertisement) capsule() {}
func (Unknown) capsule()            {}

// Decode interprets a raw capsule, enforcing RFC 9484 §4.7.
func Decode(raw RawCapsule) (Capsule, error) {
	v := raw.Value
	switch raw.Type {
	case TypeDatagram:
		return Datagram(raw.Value), nil
	case TypeAddressAssign:
		list := AddressAssign{}
		for len(v) > 0 {
			id, err := takeVarint(&v)
			if err != nil {
				return nil, err
			}
			p, err := takePrefix(&v)
			if err != nil {
				return nil, err
			}
			list = append(list, AssignedAddress{id, p})
		}
		return list, nil
	case TypeAddressRequest:
		list := AddressRequest{}
		for len(v) > 0 {
			id, err := takeVarint(&v)
			if err != nil {
				return nil, err
			}
			if id == 0 {
				return nil, MalformedError("ADDRESS_REQUEST with request ID 0")
			}
			p, err := takePrefix(&v)
			if err != nil {
				return nil, err
			}
			list = append(list, RequestedAddress{id, p})
		}
		if len(list) == 0 {
			return nil, MalformedError("empty ADDRESS_REQUEST")
		}
		return list, nil
	case TypeRouteAdvertisement:
		list := RouteAdvertisement{}
		for len(v) > 0 {
			version, err := takeByte(&v)
			if err != nil {
				return nil, err
			}
			start, err := takeAddr(&v, version)
			if err != nil {
				return nil, err
			}
			end, err := takeAddr(&v, version)
			if err != nil {
				return nil, err
			}
			proto, err := takeByte(&v)
			if err != nil {
				return nil, err
			}
			r, err := NewAddressRange(start, end, proto)
			if err != nil {
				return nil, err
			}
			list = append(list, r)
		}
		if err := ValidateRoutes(list); err != nil {
			return nil, err
		}
		return list, nil
	default:
		return Unknown(raw), nil
	}
}

// Append appends the wire encoding of a capsule.
func Append(out []byte, c Capsule) []byte {
	var value []byte
	var t uint64
	switch c := c.(type) {
	case Datagram:
		t, value = TypeDatagram, c
	case AddressAssign:
		t = TypeAddressAssign
		for _, a := range c {
			value = quicvarint.Append(value, a.RequestID)
			value = appendPrefix(value, a.Prefix)
		}
	case AddressRequest:
		t = TypeAddressRequest
		for _, r := range c {
			value = quicvarint.Append(value, r.RequestID)
			value = appendPrefix(value, r.Prefix)
		}
	case RouteAdvertisement:
		if err := ValidateRoutes(c); err != nil {
			panic(fmt.Sprintf("refusing to send invalid routes: %v", err))
		}
		t = TypeRouteAdvertisement
		for _, r := range c {
			value = append(value, byte(r.version()))
			value = append(value, r.Start.AsSlice()...)
			value = append(value, r.End.AsSlice()...)
			value = append(value, r.Protocol)
		}
	case Unknown:
		t, value = c.Type, c.Value
	default:
		panic("unknown capsule")
	}
	return AppendCapsule(out, t, value)
}

// Within a complete capsule value, running out of bytes is malformed.
const truncated = MalformedError("truncated capsule value")

func takeVarint(v *[]byte) (uint64, error) {
	x, n, err := readVarint(*v)
	if err != nil {
		return 0, truncated
	}
	*v = (*v)[n:]
	return x, nil
}

func takeByte(v *[]byte) (byte, error) {
	if len(*v) == 0 {
		return 0, truncated
	}
	b := (*v)[0]
	*v = (*v)[1:]
	return b, nil
}

func takeAddr(v *[]byte, version byte) (netip.Addr, error) {
	var n int
	switch version {
	case 4:
		n = 4
	case 6:
		n = 16
	default:
		return netip.Addr{}, MalformedError("IP version is neither 4 nor 6")
	}
	if len(*v) < n {
		return netip.Addr{}, truncated
	}
	a, _ := netip.AddrFromSlice((*v)[:n])
	*v = (*v)[n:]
	return a, nil
}

func takePrefix(v *[]byte) (Prefix, error) {
	version, err := takeByte(v)
	if err != nil {
		return Prefix{}, err
	}
	a, err := takeAddr(v, version)
	if err != nil {
		return Prefix{}, err
	}
	bits, err := takeByte(v)
	if err != nil {
		return Prefix{}, err
	}
	return NewPrefix(a, int(bits))
}

func appendPrefix(out []byte, p Prefix) []byte {
	if p.Addr().Is4() {
		out = append(out, 4)
	} else {
		out = append(out, 6)
	}
	out = append(out, p.Addr().AsSlice()...)
	return append(out, byte(p.Bits()))
}

// ContextIDIPPacket is the context ID of datagrams carrying a full IP
// packet (RFC 9484 §6).
const ContextIDIPPacket = 0

// SplitContextID splits an HTTP Datagram payload into its context ID and
// the rest.
func SplitContextID(payload []byte) (uint64, []byte, error) {
	id, n, err := readVarint(payload)
	if err != nil {
		return 0, nil, MalformedError("datagram too short for a context ID")
	}
	return id, payload[n:], nil
}
