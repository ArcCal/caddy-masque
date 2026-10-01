// Package routes holds sets of IPv4 and IPv6 destinations. One set drives
// both the ROUTE_ADVERTISEMENT capsule and the per-packet destination
// check, so what is advertised and what is enforced cannot drift apart.
package routes

import (
	"net/netip"
	"slices"

	"github.com/ArcCal/caddy-masque/internal/proto"
)

// span is an inclusive range within one family.
type span struct{ lo, hi netip.Addr }

// ranges are sorted, disjoint, non-adjacent spans of one family.
type ranges []span

func (r ranges) remove(lo, hi netip.Addr) ranges {
	out := make(ranges, 0, len(r)+1)
	for _, s := range r {
		if s.hi.Less(lo) || hi.Less(s.lo) {
			out = append(out, s)
			continue
		}
		if s.lo.Less(lo) {
			out = append(out, span{s.lo, lo.Prev()})
		}
		if hi.Less(s.hi) {
			out = append(out, span{hi.Next(), s.hi})
		}
	}
	return out
}

func (r ranges) insert(lo, hi netip.Addr) ranges {
	all := append(slices.Clone(r), span{lo, hi})
	slices.SortFunc(all, func(a, b span) int { return a.lo.Compare(b.lo) })
	var merged ranges
	for _, s := range all {
		if n := len(merged); n > 0 {
			last := &merged[n-1]
			// Next() of the family's last address is the zero Addr.
			next := last.hi.Next()
			if !next.IsValid() || !next.Less(s.lo) {
				if last.hi.Less(s.hi) {
					last.hi = s.hi
				}
				continue
			}
		}
		merged = append(merged, s)
	}
	return merged
}

func (r ranges) contains(x netip.Addr) bool {
	i, _ := slices.BinarySearchFunc(r, x, func(s span, x netip.Addr) int {
		if s.hi.Less(x) {
			return -1
		}
		if x.Less(s.lo) {
			return 1
		}
		return 0
	})
	return i < len(r) && !x.Less(r[i].lo) && !r[i].hi.Less(x)
}

func (r ranges) intersect(lo, hi netip.Addr) ranges {
	var out ranges
	for _, s := range r {
		if s.hi.Less(lo) || hi.Less(s.lo) {
			continue
		}
		a, b := s.lo, s.hi
		if a.Less(lo) {
			a = lo
		}
		if hi.Less(b) {
			b = hi
		}
		out = append(out, span{a, b})
	}
	return out
}

// Set is a set of IPv4 and IPv6 addresses. The zero Set is empty.
type Set struct{ v4, v6 ranges }

var (
	first4 = netip.AddrFrom4([4]byte{})
	last4  = netip.AddrFrom4([4]byte{255, 255, 255, 255})
	first6 = netip.IPv6Unspecified()
	last6  = netip.AddrFrom16([16]byte{0: 0xff, 1: 0xff, 2: 0xff, 3: 0xff, 4: 0xff, 5: 0xff, 6: 0xff, 7: 0xff,
		8: 0xff, 9: 0xff, 10: 0xff, 11: 0xff, 12: 0xff, 13: 0xff, 14: 0xff, 15: 0xff})
)

// Everything is every IPv4 and IPv6 address.
func Everything() Set {
	return Set{ranges{{first4, last4}}, ranges{{first6, last6}}}
}

func bounds(p netip.Prefix) (bool, netip.Addr, netip.Addr) {
	p = p.Masked()
	lo := p.Addr()
	b := lo.AsSlice()
	host := lo.BitLen() - p.Bits()
	for i := len(b) - 1; i >= 0 && host > 0; i-- {
		n := min(host, 8)
		b[i] |= byte(1<<n - 1)
		host -= n
	}
	hi, _ := netip.AddrFromSlice(b)
	return lo.Is4(), lo, hi
}

func (s *Set) family(v4 bool) *ranges {
	if v4 {
		return &s.v4
	}
	return &s.v6
}

// Remove removes a prefix.
func (s *Set) Remove(p netip.Prefix) {
	v4, lo, hi := bounds(p)
	f := s.family(v4)
	*f = f.remove(lo, hi)
}

// Insert adds a prefix.
func (s *Set) Insert(p netip.Prefix) {
	v4, lo, hi := bounds(p)
	f := s.family(v4)
	*f = f.insert(lo, hi)
}

// Contains reports whether the set holds an address.
// IPv4-mapped IPv6 addresses count as IPv6 (and are blocked by default).
func (s Set) Contains(a netip.Addr) bool {
	if a.Is4() {
		return s.v4.contains(a)
	}
	return s.v6.contains(a)
}

// Intersect is the part of the set inside a prefix.
func (s Set) Intersect(p netip.Prefix) Set {
	v4, lo, hi := bounds(p)
	if v4 {
		return Set{v4: s.v4.intersect(lo, hi)}
	}
	return Set{v6: s.v6.intersect(lo, hi)}
}

// Union adds another set.
func (s Set) Union(o Set) Set {
	for _, x := range o.v4 {
		s.v4 = s.v4.insert(x.lo, x.hi)
	}
	for _, x := range o.v6 {
		s.v6 = s.v6.insert(x.lo, x.hi)
	}
	return s
}

// Families keeps only the families that are true.
func (s Set) Families(v4, v6 bool) Set {
	if !v4 {
		s.v4 = nil
	}
	if !v6 {
		s.v6 = nil
	}
	return s
}

func (s Set) HasIPv4() bool { return len(s.v4) > 0 }
func (s Set) HasIPv6() bool { return len(s.v6) > 0 }
func (s Set) IsEmpty() bool { return !s.HasIPv4() && !s.HasIPv6() }

// Routes are the set's ranges for a ROUTE_ADVERTISEMENT, all with protocol
// (0: all): IPv4 before IPv6, ascending and disjoint, as RFC 9484 §4.7.3
// requires.
func (s Set) Routes(protocol uint8) []proto.AddressRange {
	var out []proto.AddressRange
	for _, x := range append(slices.Clone(s.v4), s.v6...) {
		out = append(out, proto.AddressRange{Start: x.lo, End: x.hi, Protocol: protocol})
	}
	return out
}

// DefaultBlocked are destinations a server does not forward to unless
// configured otherwise: special-purpose and private space, including the
// VPS provider's internal network and metadata service (169.254.169.254).
var DefaultBlocked = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
	"::/127", "::ffff:0:0/96", "fc00::/7", "fe80::/10", "ff00::/8",
}
