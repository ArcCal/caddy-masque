package pool

import (
	"net/netip"
	"testing"
)

func p(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func a(s string) netip.Addr   { return netip.MustParseAddr(s) }

func TestAllocatesEveryIPv4HostOnceThenRunsOut(t *testing.T) {
	pool := New(p("10.89.0.1/29"), netip.Prefix{})
	got := map[netip.Addr]bool{}
	for range 5 {
		x, used, ok := pool.Allocate(false)
		if !ok || used || got[x] {
			t.Fatal(x, used, ok)
		}
		got[x] = true
		if x == a("10.89.0.0") || x == a("10.89.0.7") || x == a("10.89.0.1") {
			t.Fatalf("%s is reserved", x)
		}
	}
	if _, _, ok := pool.Allocate(false); ok {
		t.Fatal("/29 has 5 client addresses")
	}
	var one netip.Addr
	for x := range got {
		one = x
		break
	}
	pool.Release(one)
	if x, used, ok := pool.Allocate(false); !ok || x != one || !used {
		t.Fatal(x, used, ok)
	}
	if _, _, ok := pool.Allocate(true); ok {
		t.Fatal("no IPv6 prefix")
	}
}

func TestReturnedAddressesComeBackLastAndOldestFirst(t *testing.T) {
	pool := New(p("10.89.0.1/29"), netip.Prefix{})
	first, _, _ := pool.Allocate(false)
	second, _, _ := pool.Allocate(false)
	pool.Release(first)
	pool.Release(second)
	for range 3 {
		x, used, _ := pool.Allocate(false)
		if used || x == first || x == second {
			t.Fatal("never-used addresses come first")
		}
	}
	if x, used, _ := pool.Allocate(false); x != first || !used {
		t.Fatal("returned longest ago", x)
	}
	if x, used, _ := pool.Allocate(false); x != second || !used {
		t.Fatal(x)
	}
	if _, _, ok := pool.Allocate(false); ok {
		t.Fatal("exhausted")
	}
}

func TestClaimedAddressIsNoLongerWaitingForReuse(t *testing.T) {
	pool := New(p("10.89.0.1/30"), netip.Prefix{}) // one client address
	x, _, _ := pool.Allocate(false)
	for range 1000 {
		pool.Release(x)
		if !pool.Claim(x) {
			t.Fatal("the same user reconnects")
		}
	}
	if len(pool.v4.returned) != 0 || len(pool.v4.order) > 64 {
		t.Fatal("stale entries", len(pool.v4.order))
	}
	pool.Release(x)
	if y, used, ok := pool.Allocate(false); y != x || !used || !ok {
		t.Fatal(y)
	}
	if _, _, ok := pool.Allocate(false); ok {
		t.Fatal("exhausted")
	}
}

func TestClaimReservesFreePoolAddressesOnly(t *testing.T) {
	pool := New(p("10.89.0.1/24"), p("fd89::1/64"))
	x := a("10.89.0.9")
	if !pool.Claim(x) || pool.Claim(x) {
		t.Fatal("claim once")
	}
	for _, bad := range []string{"10.89.0.1", "10.90.0.9", "10.89.0.0", "10.89.0.255", "fd89::1", "fd90::5"} {
		if pool.Claim(a(bad)) {
			t.Errorf("%s claimed", bad)
		}
	}
	if !pool.Claim(a("fd89::abcd")) {
		t.Fatal("v6")
	}
	pool.Release(x)
	if !pool.Claim(x) {
		t.Fatal("released")
	}
}

func TestRandomIPv6InPrefix(t *testing.T) {
	net := p("fd89:6d61:7371::1/64")
	pool := New(netip.Prefix{}, net)
	x, used, _ := pool.Allocate(true)
	y, _, _ := pool.Allocate(true)
	if x == y || used || !net.Masked().Contains(x) || x == net.Addr() {
		t.Fatal(x, y)
	}
}

// Below 64 host bits a random pick could land on an address another session
// used, whose connection tracking entries are still there: such pools are
// tracked, and every reuse is reported so the server clears them first.
func TestIPv6PoolsSmallerThanA64TrackReuse(t *testing.T) {
	pool := New(netip.Prefix{}, p("fd00::1/112"))
	seen := map[netip.Addr]bool{}
	for i := range 70000 {
		a, used, ok := pool.Allocate(true)
		if !ok {
			t.Fatal("pool empty")
		}
		if seen[a] != used {
			t.Fatalf("session %d got %v: used before %v, reported %v", i, a, seen[a], used)
		}
		seen[a] = true
		pool.Release(a)
	}
	// 65 534 assignable addresses: every one was handed out once before any
	// came back.
	if len(seen) != 1<<16-2 {
		t.Fatalf("%d addresses used", len(seen))
	}
	for _, s := range []string{"fd00::1/65", "fd00::1/96"} {
		pool := New(netip.Prefix{}, p(s))
		a, used, ok := pool.Allocate(true)
		b, _, _ := pool.Allocate(true)
		if !ok || used || a == b || !p(s).Masked().Contains(a) || a == p(s).Addr() {
			t.Errorf("%s: %v %v %v %v", s, a, b, used, ok)
		}
		pool.Release(a)
		if !pool.Claim(a) || pool.Claim(a) {
			t.Errorf("%s: a returned address can be claimed once", s)
		}
	}
}

func TestSmallIPv6PrefixIsExhaustedCleanly(t *testing.T) {
	pool := New(netip.Prefix{}, p("fd89::1/126"))
	got := map[netip.Addr]bool{}
	for range 2 {
		x, _, ok := pool.Allocate(true)
		if !ok {
			t.Fatal("exhausted early")
		}
		got[x] = true
	}
	if len(got) != 2 {
		t.Fatal(got)
	}
	if _, _, ok := pool.Allocate(true); ok {
		t.Fatal("exhausted")
	}
}

func TestTinyIPv4Prefixes(t *testing.T) {
	for _, s := range []string{"10.89.0.1/32", "10.89.0.0/31"} {
		if _, _, ok := New(p(s), netip.Prefix{}).Allocate(false); ok {
			t.Errorf("%s has no client address", s)
		}
	}
}
