package routes

import (
	"net/netip"
	"testing"

	"github.com/ArcCal/caddy-masque/internal/proto"
)

func serverSet() Set {
	s := Everything()
	for _, b := range DefaultBlocked {
		s.Remove(netip.MustParsePrefix(b))
	}
	s.Insert(netip.MustParsePrefix("10.89.0.1/32"))
	s.Insert(netip.MustParsePrefix("fd89::1/128"))
	return s
}

func TestBlocksPrivateSpaceButKeepsGateways(t *testing.T) {
	s := serverSet()
	for _, a := range []string{"1.1.1.1", "9.255.255.255", "11.0.0.0", "10.89.0.1", "2001:db8::1", "fd89::1", "2606:4700::1111"} {
		if !s.Contains(netip.MustParseAddr(a)) {
			t.Errorf("%s blocked", a)
		}
	}
	for _, a := range []string{"10.0.0.5", "169.254.169.254", "192.168.1.1", "255.255.255.254", "10.89.0.2",
		"::1", "fe80::1", "fd00::1", "ff02::1", "::ffff:1.2.3.4"} {
		if s.Contains(netip.MustParseAddr(a)) {
			t.Errorf("%s allowed", a)
		}
	}
}

func TestAdvertisementIsValid(t *testing.T) {
	r := serverSet().Routes(0)
	if err := proto.ValidateRoutes(r); err != nil {
		t.Fatal(err)
	}
	hasV6 := false
	for _, x := range r {
		hasV6 = hasV6 || x.Start.Is6()
	}
	if !hasV6 {
		t.Fatal("no IPv6")
	}
	if err := proto.ValidateRoutes(serverSet().Routes(17)); err != nil {
		t.Fatal(err)
	}
	// Round trip through the wire format.
	if _, err := proto.Decode(proto.RawCapsule{Type: proto.TypeRouteAdvertisement,
		Value: proto.Append(nil, proto.RouteAdvertisement(r))[3:]}); err != nil {
		t.Fatal(err)
	}
}

func TestIntersectAndFamilies(t *testing.T) {
	s := serverSet()
	one := s.Intersect(netip.MustParsePrefix("192.0.2.0/24"))
	if !one.Contains(netip.MustParseAddr("192.0.2.7")) || one.Contains(netip.MustParseAddr("192.0.3.1")) || one.HasIPv6() {
		t.Fatal(one)
	}
	if n := len(s.Intersect(netip.MustParsePrefix("10.0.0.0/8")).Routes(0)); n != 1 {
		t.Fatalf("only the gateway, got %d", n)
	}
	if s.Families(true, false).HasIPv6() {
		t.Fatal("families")
	}
	both := one.Union(s.Intersect(netip.MustParsePrefix("2001:db8::/32")))
	if !both.HasIPv4() || !both.HasIPv6() {
		t.Fatal("union")
	}
	if !s.Intersect(netip.MustParsePrefix("10.0.0.0/8")).Contains(netip.MustParseAddr("10.89.0.1")) {
		t.Fatal("gateway")
	}
}

func TestAdjacentRangesMerge(t *testing.T) {
	var s Set
	s.Insert(netip.MustParsePrefix("10.0.0.0/25"))
	s.Insert(netip.MustParsePrefix("10.0.0.128/25"))
	s.Insert(netip.MustParsePrefix("255.255.255.255/32"))
	s.Insert(netip.MustParsePrefix("255.255.255.0/24"))
	if r := s.Routes(0); len(r) != 2 || r[0].End != netip.MustParseAddr("10.0.0.255") || r[1].End != netip.MustParseAddr("255.255.255.255") {
		t.Fatal(r)
	}
}
