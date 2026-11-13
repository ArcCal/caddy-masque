package auth

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Printed by masque-vpn's masque-passwd (the Rust argon2 crate).
const (
	rustHash     = "$argon2id$v=19$m=19456,t=2,p=1$JbPnvQtCivJ9Yx0m03/vEA$Hxye9dEALbiWaLl5sS6mw31urn8oXItWrw/QXQ0k0e8"
	rustPassword = "Lz4Iwq-Zj-Nypqg4TUubfWV_"
)

var src = netip.MustParseAddr("192.0.2.1")

func TestGeneratePassword(t *testing.T) {
	const allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	seen := make(map[string]bool)
	for range 1024 {
		password := GeneratePassword()
		if len(password) != 22 {
			t.Fatalf("generated password length = %d, want 22", len(password))
		}
		for _, c := range password {
			if !strings.ContainsRune(allowed, c) {
				t.Fatalf("generated password contains unsupported character %q", c)
			}
		}
		for _, class := range []string{"ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", "0123456789", "-_"} {
			if !strings.ContainsAny(password, class) {
				t.Fatalf("generated password is missing character class %q", class)
			}
		}
		if seen[password] {
			t.Fatal("generated a duplicate password")
		}
		seen[password] = true
	}
}

func TestGeneratedPasswordHashAndBasic(t *testing.T) {
	password := GeneratePassword()
	hash := HashPassword(password)
	user, decoded, ok := ParseBasic(BasicAuthorization("laptop", password))
	if !ok || user != "laptop" || decoded != password || !verifyHash(decoded, hash) {
		t.Fatal("generated password failed the Basic authentication and hash round trip")
	}
	if verifyHash(password+"wrong", hash) {
		t.Fatal("incorrect password matched the generated password hash")
	}
}

// source is the i-th of many distinct sources.
func source(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
}

func TestHashesFromMasquePasswdVerify(t *testing.T) {
	if err := ValidateHash(rustHash); err != nil {
		t.Fatal(err)
	}
	if !verifyHash(rustPassword, rustHash) || verifyHash(rustPassword+"x", rustHash) {
		t.Fatal("cross-implementation verification")
	}
}

func TestOwnHashesVerify(t *testing.T) {
	h := HashPassword("correct horse battery")
	if err := ValidateHash(h); err != nil || !verifyHash("correct horse battery", h) || verifyHash("wrong", h) {
		t.Fatal(h, err)
	}
	if h[:30] != "$argon2id$v=19$m=19456,t=2,p=1" {
		t.Fatal(h)
	}
}

func TestBadHashes(t *testing.T) {
	for _, h := range []string{"", "plain", "$argon2i$v=19$m=19456,t=2,p=1$JbPnvQtCivJ9Yx0m03/vEA$Hxye9dEALbiWaLl5sS6mw31urn8oXItWrw/QXQ0k0e8",
		"$argon2id$v=16$m=19456,t=2,p=1$JbPnvQtCivJ9Yx0m03/vEA$Hxye9dEALbiWaLl5sS6mw31urn8oXItWrw/QXQ0k0e8",
		"$argon2id$v=19$m=99999999,t=2,p=1$JbPnvQtCivJ9Yx0m03/vEA$Hxye9dEALbiWaLl5sS6mw31urn8oXItWrw/QXQ0k0e8",
		"$argon2id$v=19$m=19456,t=2$JbPnvQtCivJ9Yx0m03/vEA$Hxye9dEALbiWaLl5sS6mw31urn8oXItWrw/QXQ0k0e8",
		"$argon2id$v=19$m=19456,t=2,p=1$!!!$Hxye9dEALbiWaLl5sS6mw31urn8oXItWrw/QXQ0k0e8"} {
		if ValidateHash(h) == nil {
			t.Errorf("%q accepted", h)
		}
	}
}

func TestBasic(t *testing.T) {
	h := BasicAuthorization("laptop", "p:a ss")
	if u, p, ok := ParseBasic(h); !ok || u != "laptop" || p != "p:a ss" {
		t.Fatal(u, p)
	}
	// RFC 7617 example.
	if u, p, ok := ParseBasic("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="); !ok || u != "Aladdin" || p != "open sesame" {
		t.Fatal(u, p)
	}
	if u, _, _ := ParseBasic("basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="); u != "Aladdin" {
		t.Fatal("scheme is case-insensitive")
	}
	for _, bad := range []string{"Bearer abc", "Basic", "Basic !!!", "Basic bm9jb2xvbg==", "\xff\xfe"} {
		if _, _, ok := ParseBasic(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestUserNames(t *testing.T) {
	for _, ok := range []string{"alice", "a.b-c_d", "x"} {
		if ValidateUserName(ok) != nil {
			t.Error(ok)
		}
	}
	for _, bad := range []string{"", ".hidden", "a:b", "a b", "é", string(make([]byte, 65))} {
		if ValidateUserName(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestVerify(t *testing.T) {
	a := New()
	a.Replace(map[string]string{"alice": rustHash})
	ctx := context.Background()
	u, ok, err := a.Verify(ctx, BasicAuthorization("alice", rustPassword), src)
	if !ok || err != nil || u.Name != "alice" {
		t.Fatal(u, ok, err)
	}
	for _, h := range []string{BasicAuthorization("alice", "nope"), BasicAuthorization("mallory", rustPassword), ""} {
		if _, ok, _ := a.Verify(ctx, h, src); ok {
			t.Errorf("%q accepted", h)
		}
	}
	// Removed, or password changed: no longer current.
	a.Replace(map[string]string{"alice": HashPassword("new")})
	if a.IsCurrent(u) {
		t.Fatal("stale user")
	}
	if _, ok, _ := a.Verify(ctx, BasicAuthorization("alice", rustPassword), src); ok {
		t.Fatal("old password")
	}
}

func TestFullQueueIsAnsweredAtOnce(t *testing.T) {
	a := New()
	a.Replace(map[string]string{"alice": rustHash})
	busy := 0
	a.OnBusy = func() { busy++ }
	// Take every slot.
	for range cap(a.slots) {
		a.slots <- struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, a.maxWaiting)
	for i := range a.maxWaiting {
		go func() {
			_, _, err := a.Verify(ctx, BasicAuthorization("alice", rustPassword), source(int(i)))
			done <- err
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for a.waiting.Load() != a.maxWaiting {
		if time.Now().After(deadline) {
			t.Fatal("not all waiting", a.waiting.Load())
		}
		time.Sleep(time.Millisecond)
	}
	if _, _, err := a.Verify(context.Background(), BasicAuthorization("alice", rustPassword), src); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if _, _, err := a.Verify(context.Background(), BasicAuthorization("alice", rustPassword), src); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if busy != 1 {
		t.Fatal("warned", busy)
	}
	if _, ok, err := a.Verify(context.Background(), "", src); ok || err != nil {
		t.Fatal("no credentials: answered as before")
	}
	// Cancelled requests leave the queue.
	cancel()
	for range a.maxWaiting {
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
	if a.waiting.Load() != 0 {
		t.Fatal(a.waiting.Load())
	}
	for range cap(a.slots) {
		<-a.slots
	}
	if _, ok, err := a.Verify(context.Background(), BasicAuthorization("alice", rustPassword), src); !ok || err != nil {
		t.Fatal(ok, err)
	}
	waitFor(t, "every source's place given back", func() bool { return a.sourcesInUse() == 0 })
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out: " + what)
		}
		time.Sleep(time.Millisecond)
	}
}

func (a *Authenticator) sourcesInUse() int {
	a.sourcesMu.Lock()
	defer a.sourcesMu.Unlock()
	n := 0
	for _, v := range a.sources {
		n += v
	}
	return n
}

// fill takes every slot and fills the queue with made-up credentials from
// distinct sources; the returned function empties it again.
func fill(t *testing.T, a *Authenticator) func() {
	t.Helper()
	for range cap(a.slots) {
		a.slots <- struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	for i := range a.maxWaiting {
		go func() {
			a.Verify(ctx, BasicAuthorization("mallory", "guess"), source(int(i)))
			done <- struct{}{}
		}()
	}
	waitFor(t, "queue full", func() bool { return a.waiting.Load() == a.maxWaiting })
	return func() {
		cancel()
		for range a.maxWaiting {
			<-done
		}
		for range cap(a.slots) {
			<-a.slots
		}
	}
}

func TestRememberedCredentialsGetInWhileAFloodFillsTheQueue(t *testing.T) {
	a := New()
	a.Replace(map[string]string{"alice": rustHash})
	header := BasicAuthorization("alice", rustPassword)
	if _, ok := a.Remembered(header); ok {
		t.Fatal("remembered before any verification")
	}
	if _, ok, err := a.Verify(context.Background(), header, src); !ok || err != nil {
		t.Fatal(ok, err)
	}
	empty := fill(t, a)
	defer empty()
	if _, _, err := a.Verify(context.Background(), BasicAuthorization("mallory", "guess"), src); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	// Alice gets in at once, from any address, also through Remembered.
	u, ok, err := a.Verify(context.Background(), header, source(1<<20))
	if !ok || err != nil || u.Name != "alice" || !a.IsCurrent(u) {
		t.Fatal(u, ok, err)
	}
	if u, ok := a.Remembered(header); !ok || u.Name != "alice" || !a.IsCurrent(u) {
		t.Fatal(u, ok)
	}
	// Only her correct password is remembered.
	wrong := BasicAuthorization("alice", "wrong")
	if _, ok := a.Remembered(wrong); ok {
		t.Fatal("wrong password remembered")
	}
	if _, _, err := a.Verify(context.Background(), wrong, src); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	for _, h := range []string{"", "Basic", BasicAuthorization("mallory", rustPassword)} {
		if _, ok := a.Remembered(h); ok {
			t.Fatalf("%q remembered", h)
		}
	}
}

func TestAChangedOrRemovedPasswordIsNotRemembered(t *testing.T) {
	a := New()
	a.Replace(map[string]string{"alice": rustHash})
	old := BasicAuthorization("alice", rustPassword)
	if _, ok, _ := a.Verify(context.Background(), old, src); !ok {
		t.Fatal("old password")
	}
	a.Replace(map[string]string{"alice": HashPassword("new-password")})
	if _, ok := a.Remembered(old); ok {
		t.Fatal("changed password remembered")
	}
	if _, ok, _ := a.Verify(context.Background(), old, src); ok {
		t.Fatal("changed password accepted")
	}
	updated := BasicAuthorization("alice", "new-password")
	if _, ok, _ := a.Verify(context.Background(), updated, src); !ok {
		t.Fatal("new password")
	}
	a.Replace(nil)
	if _, ok := a.Remembered(updated); ok {
		t.Fatal("removed user remembered")
	}
	if _, ok, _ := a.Verify(context.Background(), updated, src); ok {
		t.Fatal("removed user accepted")
	}
	// The user comes back with the same hash: the old entry is valid again,
	// as the same password would verify.
	a.Replace(map[string]string{"alice": rustHash})
	if _, ok := a.Remembered(old); !ok {
		t.Fatal("same hash, same password")
	}
}

func TestRememberedCredentialsExpire(t *testing.T) {
	a := New()
	a.Replace(map[string]string{"alice": rustHash, "bob": rustHash})
	alice := BasicAuthorization("alice", rustPassword)
	if _, ok, _ := a.Verify(context.Background(), alice, src); !ok {
		t.Fatal("alice")
	}
	tag := a.tag("alice", rustPassword)
	a.verified[tag] = remembered{rustHash, time.Now().Add(-rememberFor + time.Minute)}
	// A use renews the entry.
	if _, ok := a.Remembered(alice); !ok {
		t.Fatal("not yet expired")
	}
	if time.Since(a.verified[tag].at) > time.Minute {
		t.Fatal("use did not renew the entry")
	}
	a.verified[tag] = remembered{rustHash, time.Now().Add(-rememberFor)}
	if _, ok := a.Remembered(alice); ok {
		t.Fatal("expired entry used")
	}
	// Expired entries are dropped when another is added.
	if _, ok, _ := a.Verify(context.Background(), BasicAuthorization("bob", rustPassword), src); !ok {
		t.Fatal("bob")
	}
	if _, kept := a.verified[tag]; kept || len(a.verified) != 1 {
		t.Fatal("expired entry kept", len(a.verified))
	}
}

func TestOneSourceCannotFillTheQueue(t *testing.T) {
	a := New()
	a.Replace(map[string]string{"alice": rustHash})
	for range cap(a.slots) {
		a.slots <- struct{}{}
	}
	header := BasicAuthorization("alice", rustPassword)
	// Two addresses of one IPv6 /64 are one source.
	x, y := netip.MustParseAddr("2001:db8:1:2::10"), netip.MustParseAddr("2001:db8:1:2::20")
	type result struct {
		ok  bool
		err error
	}
	verify := func(ctx context.Context, from netip.Addr) chan result {
		c := make(chan result, 1)
		go func() {
			_, ok, err := a.Verify(ctx, header, from)
			c <- result{ok, err}
		}()
		return c
	}
	ctx, cancel := context.WithCancel(context.Background())
	var queued []chan result
	for i := range perSource {
		queued = append(queued, verify(ctx, []netip.Addr{x, y}[i%2]))
	}
	waitFor(t, "all queued", func() bool { return a.waiting.Load() == perSource })
	if _, _, err := a.Verify(context.Background(), header, y); !errors.Is(err, ErrBusy) {
		t.Fatal("the /64 has had its share:", err)
	}
	// Another source still gets a place in the queue.
	other := verify(context.Background(), netip.MustParseAddr("2001:db8:1:3::1"))
	waitFor(t, "other queued", func() bool { return a.waiting.Load() == perSource+1 })
	// Cancelled requests give their source's places back.
	cancel()
	for _, c := range queued {
		if r := <-c; !errors.Is(r.err, context.Canceled) {
			t.Fatal(r.err)
		}
	}
	again := verify(context.Background(), x)
	waitFor(t, "queued again", func() bool { return a.waiting.Load() == 2 })
	for range cap(a.slots) {
		<-a.slots
	}
	for _, c := range []chan result{other, again} {
		if r := <-c; !r.ok || r.err != nil {
			t.Fatal(r)
		}
	}
	waitFor(t, "every place given back", func() bool { return a.sourcesInUse() == 0 && len(a.sources) == 0 })
}

func TestACancelledVerificationKeepsItsPlacesUntilHashingFinishes(t *testing.T) {
	a := New()
	a.Replace(map[string]string{"alice": rustHash})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// The slot is free, so hashing starts; the cancelled context returns
	// at once while it runs.
	_, _, err := a.Verify(ctx, BasicAuthorization("alice", rustPassword), src)
	if !errors.Is(err, context.Canceled) {
		// The result can win the race only if hashing was that fast.
		t.Skip("hashing finished first:", err)
	}
	if a.sourcesInUse() != 1 || len(a.slots) != 1 {
		t.Fatal("places given back while hashing runs", a.sourcesInUse(), len(a.slots))
	}
	waitFor(t, "places given back", func() bool { return a.sourcesInUse() == 0 && len(a.slots) == 0 })
}

func TestSourcesAreAddressesOrIPv6Slash64s(t *testing.T) {
	k := func(s string) netip.Addr { return sourceKey(netip.MustParseAddr(s)) }
	if k("192.0.2.7") != k("::ffff:192.0.2.7") || k("192.0.2.7") == k("192.0.2.8") {
		t.Error("IPv4")
	}
	if k("2001:db8:1:2:aaaa::1") != k("2001:db8:1:2:bbbb::2") || k("2001:db8:1:2::1") == k("2001:db8:1:3::1") {
		t.Error("IPv6")
	}
	if k("fe80::1%eth0") != k("fe80::2") {
		t.Error("zone")
	}
}

func TestFailureLimiter(t *testing.T) {
	l := NewFailureLimiter(3, time.Minute)
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	now := time.Now()
	for i := 0; i < 3; i++ {
		if l.blockedAt(a, now) {
			t.Fatalf("blocked after %d failures", i)
		}
		l.failAt(a, now)
	}
	if !l.blockedAt(a, now.Add(30*time.Second)) {
		t.Error("not blocked after 3 failures")
	}
	if l.blockedAt(b, now) {
		t.Error("another address is blocked")
	}
	if l.blockedAt(a, now.Add(time.Minute)) {
		t.Error("still blocked after the window")
	}
	l.failAt(a, now.Add(time.Minute))
	if l.blockedAt(a, now.Add(time.Minute)) {
		t.Error("one failure in the new window blocks")
	}
	// IPv6 clients count by /64.
	x, y := netip.MustParseAddr("2001:db8:1:2::1"), netip.MustParseAddr("2001:db8:1:2:ffff::9")
	for i := 0; i < 3; i++ {
		l.failAt(x, now)
	}
	if !l.blockedAt(y, now) || l.blockedAt(netip.MustParseAddr("2001:db8:1:3::1"), now) {
		t.Error("IPv6 addresses are not grouped by /64")
	}
	// A full table does not grow, and expired entries make room.
	l = NewFailureLimiter(1, time.Minute)
	l.maxEntries = 2
	l.failAt(a, now)
	l.failAt(b, now)
	l.failAt(netip.MustParseAddr("192.0.2.3"), now)
	if len(l.m) != 2 {
		t.Errorf("%d entries, want 2", len(l.m))
	}
	l.failAt(netip.MustParseAddr("192.0.2.3"), now.Add(2*time.Minute))
	if len(l.m) != 1 || !l.blockedAt(netip.MustParseAddr("192.0.2.3"), now.Add(2*time.Minute)) {
		t.Errorf("expired entries kept: %d", len(l.m))
	}
}

func TestAuthSlotsRespectCPUAndScheduler(t *testing.T) {
	old := runtime.GOMAXPROCS(0)
	t.Cleanup(func() { runtime.GOMAXPROCS(old) })
	for _, tc := range []struct {
		name           string
		parallel, want int
	}{
		{"below_host_CPU", 1, 2},
		{"above_host_CPU", runtime.NumCPU() + 3, runtime.NumCPU() * 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime.GOMAXPROCS(tc.parallel)
			a := New()
			if cap(a.slots) != tc.want {
				t.Fatalf("GOMAXPROCS=%d NumCPU=%d slots=%d want=%d", tc.parallel, runtime.NumCPU(), cap(a.slots), tc.want)
			}
			if a.maxWaiting != int64(tc.want*waitingPerSlot) {
				t.Fatalf("waiting cap=%d", a.maxWaiting)
			}
		})
	}
}
