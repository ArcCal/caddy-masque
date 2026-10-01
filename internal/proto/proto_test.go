package proto

import (
	"bytes"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/quic-go/quic-go/quicvarint"
)

func encoded(t uint64, value []byte) []byte { return AppendCapsule(nil, t, value) }

func TestCapsulesSplitAtEveryByte(t *testing.T) {
	wire := append(encoded(0x01, []byte("hello")), encoded(0x12345678, bytes.Repeat([]byte{0xaa}, 300))...)
	d := NewDecoder(DefaultMaxValueLen)
	var got []RawCapsule
	for _, b := range wire {
		d.Push([]byte{b})
		for {
			c, err := d.Next()
			if errors.Is(err, ErrIncomplete) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, c)
		}
	}
	if err := d.Finish(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Type != 1 || string(got[0].Value) != "hello" || got[1].Type != 0x12345678 || len(got[1].Value) != 300 {
		t.Fatalf("got %v", got)
	}
}

func TestEmptyValue(t *testing.T) {
	d := NewDecoder(DefaultMaxValueLen)
	d.Push(encoded(0x03, nil))
	c, err := d.Next()
	if err != nil || len(c.Value) != 0 {
		t.Fatal(c, err)
	}
}

func TestOversizedKnownCapsuleRejectedBeforeBuffering(t *testing.T) {
	d := NewDecoder(10)
	d.Push(quicvarint.Append(quicvarint.Append(nil, 0x00), 11))
	var m MalformedError
	if _, err := d.Next(); !errors.As(err, &m) {
		t.Fatal(err)
	}
}

func TestTruncatedCapsuleAtEndIsMalformed(t *testing.T) {
	wire := encoded(0x01, []byte("hello"))
	d := NewDecoder(DefaultMaxValueLen)
	d.Push(wire[:len(wire)-1])
	if _, err := d.Next(); !errors.Is(err, ErrIncomplete) {
		t.Fatal(err)
	}
	if d.Finish() == nil {
		t.Fatal("expected malformed")
	}
}

func TestOversizedUnknownCapsulesAreSkippedWithoutBuffering(t *testing.T) {
	d := NewDecoder(10)
	d.Push(quicvarint.Append(quicvarint.Append(nil, 0x1234), 100_000))
	if _, err := d.Next(); !errors.Is(err, ErrIncomplete) {
		t.Fatal(err)
	}
	if d.Finish() == nil {
		t.Fatal("inside a skipped capsule")
	}
	for range 100 {
		d.Push(make([]byte, 1000))
		if len(d.buf) != 0 {
			t.Fatal("buffered a skipped value")
		}
	}
	d.Push(encoded(TypeDatagram, []byte("next")))
	c, err := d.Next()
	if err != nil || c.Type != 0x1234 || len(c.Value) != 0 {
		t.Fatal(c, err)
	}
	c, err = d.Next()
	if err != nil || string(c.Value) != "next" {
		t.Fatal(c, err)
	}
	if err := d.Finish(); err != nil {
		t.Fatal(err)
	}
}

func roundtrip(t *testing.T, c Capsule) {
	t.Helper()
	d := NewDecoder(DefaultMaxValueLen)
	d.Push(Append(nil, c))
	raw, err := d.Next()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, c) {
		t.Fatalf("got %#v, want %#v", got, c)
	}
}

func a(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestAddressAssign(t *testing.T) {
	p64, _ := NewPrefix(a("fd89::"), 64)
	roundtrip(t, AddressAssign{{1, Host(a("10.89.0.7"))}, {0, p64}})
	roundtrip(t, AddressAssign{})
	got := Append(nil, AddressAssign{{1, Host(a("192.0.2.1"))}})
	want := []byte{0x01, 0x07, 0x01, 0x04, 192, 0, 2, 1, 32}
	if !bytes.Equal(got, want) {
		t.Fatalf("%x", got)
	}
}

func decodeValue(t uint64, v []byte) (Capsule, error) { return Decode(RawCapsule{t, v}) }

func TestAddressRequest(t *testing.T) {
	roundtrip(t, AddressRequest{{1, Unspecified(false)}, {2, Unspecified(true)}})
	if _, err := decodeValue(0x02, []byte{0x00, 0x04, 0, 0, 0, 0, 32}); err == nil {
		t.Fatal("request ID 0")
	}
	if _, err := decodeValue(0x02, nil); err == nil {
		t.Fatal("empty request")
	}
}

func TestMalformedAddressFields(t *testing.T) {
	for _, v := range [][]byte{
		{0x00, 0x05, 1, 2, 3, 4, 32},  // IP version 5
		{0x00, 0x04, 10, 0, 0, 0, 33}, // /33
		{0x00, 0x04, 10, 0, 0, 1, 24}, // host bits set
		{0x00, 0x04, 10, 0},           // truncated
	} {
		if _, err := decodeValue(0x01, v); err == nil {
			t.Errorf("%v accepted", v)
		}
	}
}

func TestRouteAdvertisement(t *testing.T) {
	r1, _ := NewAddressRange(a("0.0.0.0"), a("9.255.255.255"), 0)
	r2, _ := NewAddressRange(a("11.0.0.0"), a("255.255.255.255"), 0)
	r3, _ := NewAddressRange(a("::"), a("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), 6)
	roundtrip(t, RouteAdvertisement{r1, r2, r3})
	roundtrip(t, RouteAdvertisement{})
	// Out of order, overlapping, and protocol 0 overlapping a protocol.
	if ValidateRoutes([]AddressRange{r2, r1}) == nil {
		t.Error("unordered")
	}
	o, _ := NewAddressRange(a("9.0.0.0"), a("12.0.0.0"), 0)
	if ValidateRoutes([]AddressRange{r1, o}) == nil {
		t.Error("overlap")
	}
	p6, _ := NewAddressRange(a("10.0.0.0"), a("10.0.0.255"), 6)
	if ValidateRoutes([]AddressRange{{a("0.0.0.0"), a("255.255.255.255"), 0}, p6}) == nil {
		t.Error("protocol 0 overlaps protocol 6")
	}
	if _, err := NewAddressRange(a("10.0.0.2"), a("10.0.0.1"), 0); err == nil {
		t.Error("start after end")
	}
	if _, err := NewAddressRange(a("10.0.0.1"), a("::1"), 0); err == nil {
		t.Error("mixed families")
	}
}

func TestUnknownCapsulesArePreserved(t *testing.T) {
	raw := RawCapsule{0x1ACE79EC, []byte("dns")}
	c, err := Decode(raw)
	if err != nil || !reflect.DeepEqual(c, Unknown(raw)) {
		t.Fatal(c, err)
	}
	roundtrip(t, c)
}

func TestContextID(t *testing.T) {
	id, rest, err := SplitContextID([]byte{0x00, 0x45, 0x00})
	if err != nil || id != 0 || !bytes.Equal(rest, []byte{0x45, 0x00}) {
		t.Fatal(id, rest, err)
	}
	id, rest, err = SplitContextID([]byte{0x40, 0x02, 0xff})
	if err != nil || id != 2 || !bytes.Equal(rest, []byte{0xff}) {
		t.Fatal(id, rest, err)
	}
	if _, _, err := SplitContextID(nil); err == nil {
		t.Fatal("empty")
	}
}

func TestTargets(t *testing.T) {
	for in, want := range map[string]string{
		"*": "*", "192.0.2.1": "192.0.2.1", "192.0.2.0/24": "192.0.2.0/24",
		"2001:db8::42": "2001:db8::42", "2001:db8::/32": "2001:db8::/32", "VPN.Example.net": "vpn.example.net",
	} {
		got, err := ParseTarget(in)
		if err != nil || got.Value() != want {
			t.Errorf("%s: %v %v", in, got.Value(), err)
		}
	}
	for _, bad := range []string{"", "192.0.2.1/33", "192.0.2.1/24", "fe80::1%eth0", "-bad.example", "a..b",
		"192.0.2.0/", "192.0.2.0/0024", "host/24", "under_score.example"} {
		if _, err := ParseTarget(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestIPProtocol(t *testing.T) {
	if p, _ := ParseIPProtocol("*"); !p.Any || p.RouteProtocol() != 0 {
		t.Error("*")
	}
	if p, _ := ParseIPProtocol("17"); p.Any || p.Number != 17 {
		t.Error("17")
	}
	if p, err := ParseIPProtocol("0"); err != nil || p.Number != 0 {
		t.Error("0")
	}
	for _, bad := range []string{"", "256", "-1", "1234", "tcp"} {
		if _, err := ParseIPProtocol(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if !IsIPv6ExtensionHeader(44) || !IsIPv6ExtensionHeader(0) || IsIPv6ExtensionHeader(6) || IsIPv6ExtensionHeader(58) {
		t.Error("extension headers")
	}
}

const defaultTemplate = "https://example.org/.well-known/masque/ip/{target}/{ipproto}/"

func tpl(t *testing.T, s string) *Template {
	t.Helper()
	x, err := ParseTemplate(s)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func TestTemplatesParse(t *testing.T) {
	for _, s := range []string{defaultTemplate, "https://proxy.example.org:4443/masque/ip?t={target}&i={ipproto}",
		"https://proxy.example.org:4443/masque/ip{?target,ipproto}", "https://masque.example.org/?user=bob"} {
		tpl(t, s)
	}
	for _, s := range []string{"/relative/{target}", "https://{host}/ip/", "https://example.org",
		"https://example.org/{+target}", "https://example.org/{#target}", "https://example.org{/target}",
		"https://example.org/{.target}", "https://example.org/{;target}", "https://example.org/{target*}",
		"https://example.org/{target:3}", "https://example.org/{target", "https://example.org/ip /x",
		"https://example.org/ip/é"} {
		if _, err := ParseTemplate(s); err == nil {
			t.Errorf("%s accepted", s)
		}
	}
}

func TestExpand(t *testing.T) {
	d := tpl(t, defaultTemplate)
	cases := []struct {
		vars map[string]string
		want string
	}{
		{map[string]string{"target": "*", "ipproto": "*"}, "/.well-known/masque/ip/*/*/"},
		{map[string]string{"target": "2001:db8::42", "ipproto": "17"}, "/.well-known/masque/ip/2001%3Adb8%3A%3A42/17/"},
		{map[string]string{"target": "192.0.2.0/24", "ipproto": "*"}, "/.well-known/masque/ip/192.0.2.0%2F24/*/"},
	}
	for _, c := range cases {
		if got := d.Expand(c.vars); got != c.want {
			t.Errorf("got %s want %s", got, c.want)
		}
	}
	q := tpl(t, "https://proxy.example.org:4443/masque/ip{?target,ipproto}")
	if got := q.Expand(map[string]string{"target": "*", "ipproto": "6"}); got != "/masque/ip?target=*&ipproto=6" {
		t.Error(got)
	}
	if got := q.Expand(nil); got != "/masque/ip" {
		t.Error(got)
	}
	lit := tpl(t, "https://proxy.example.org:4443/masque/ip?t={target}&i={ipproto}")
	if got := lit.Expand(map[string]string{"target": "*", "ipproto": "*"}); got != "/masque/ip?t=*&i=*" {
		t.Error(got)
	}
}

func TestMatch(t *testing.T) {
	d := tpl(t, defaultTemplate)
	for path, want := range map[string][2]string{
		"/.well-known/masque/ip/*/*/":                      {"*", "*"},
		"/.well-known/masque/ip/%2A/%2a/":                  {"*", "*"},
		"/.well-known/masque/ip/2001%3Adb8%3A%3A%2F32/58/": {"2001:db8::/32", "58"},
	} {
		m, ok := d.Match(path)
		if !ok || m["target"] != want[0] || m["ipproto"] != want[1] {
			t.Errorf("%s: %v %v", path, m, ok)
		}
	}
	for _, path := range []string{"/.well-known/masque/udp/1.2.3.4/443/", "/.well-known/masque/ip/*/*/extra"} {
		if _, ok := d.Match(path); ok {
			t.Errorf("%s matched", path)
		}
	}
	// Empty values are kept for the protocol layer to reject.
	for path, v := range map[string]string{"/.well-known/masque/ip//*/": "target", "/.well-known/masque/ip/*//": "ipproto"} {
		m, ok := d.Match(path)
		if val, has := m[v]; !ok || !has || val != "" {
			t.Errorf("%s: %v", path, m)
		}
	}
	if tpl(t, "https://example.org/tunnel").HasVariable("target") {
		t.Error("no variables")
	}
	q := tpl(t, "https://p.example/masque/ip{?target,ipproto}")
	if m, ok := q.Match("/masque/ip?ipproto=6&target=192.0.2.1"); !ok || m["target"] != "192.0.2.1" || m["ipproto"] != "6" {
		t.Error(m)
	}
	if m, ok := q.Match("/masque/ip"); !ok || len(m) != 0 {
		t.Error("variables are optional")
	}
	lit := tpl(t, "https://p.example/masque/ip?t={target}&i={ipproto}")
	if m, ok := lit.Match("/masque/ip?t=*&i=17"); !ok || m["target"] != "*" || m["ipproto"] != "17" {
		t.Error(m)
	}
	fixed := tpl(t, "https://masque.example.org/?user=bob")
	if _, ok := fixed.Match("/?user=bob"); !ok {
		t.Error("fixed")
	}
	if _, ok := fixed.Match("/?user=eve"); ok {
		t.Error("eve")
	}
}

func TestExpandThenMatch(t *testing.T) {
	for _, s := range []string{defaultTemplate, "https://p.example/ip{?target,ipproto}", "https://p.example/ip?t={target}&i={ipproto}"} {
		x := tpl(t, s)
		for _, c := range [][2]string{{"*", "*"}, {"2001:db8::/32", "58"}, {"vpn.example.net", "6"}} {
			path := x.Expand(map[string]string{"target": c[0], "ipproto": c[1]})
			m, ok := x.Match(path)
			if !ok || m["target"] != c[0] || m["ipproto"] != c[1] {
				t.Errorf("%s %s: %v", s, path, m)
			}
		}
	}
}
