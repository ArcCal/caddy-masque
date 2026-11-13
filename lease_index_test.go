package masque

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ArcCal/caddy-masque/internal/auth"
)

func TestAuditRecentIndexModel(t *testing.T) {
	c := &core{recent: map[string]recentLease{}, recentByAddr: map[netip.Addr]string{}}
	model := map[string]recentLease{}
	rng := rand.New(rand.NewPCG(5, 8))
	now := time.Now()
	for step := 0; step < 10000; step++ {
		now = now.Add(71 * time.Millisecond)
		c.expireRecent(now)
		for name, r := range model {
			if now.Sub(r.at) >= reconnectGrace {
				delete(model, name)
			}
		}
		name := fmt.Sprintf("user-%d", rng.IntN(200))
		if rng.IntN(3) == 0 {
			got := c.takeRecent(name)
			want := model[name]
			delete(model, name)
			if !slices.Equal(got.addrs, want.addrs) {
				t.Fatalf("step %d take %s: %v != %v", step, name, got.addrs, want.addrs)
			}
		} else {
			var addrs []netip.Addr
			for range 1 + rng.IntN(2) {
				a := netip.AddrFrom4([4]byte{192, 0, 2, byte(1 + rng.IntN(200))})
				if slices.Contains(addrs, a) {
					continue
				}
				c.invalidateRecent(a)
				for owner, r := range model {
					kept := r.addrs[:0:0]
					for _, x := range r.addrs {
						if x != a {
							kept = append(kept, x)
						}
					}
					if len(kept) == 0 {
						delete(model, owner)
					} else {
						r.addrs = kept
						model[owner] = r
					}
				}
				addrs = append(addrs, a)
			}
			c.rememberRecent(name, addrs, now)
			model[name] = recentLease{addrs: addrs, at: now}
		}
		if len(c.recent) != len(model) || c.recentOrder.Len() != len(model) {
			t.Fatalf("step %d size: actual=%d order=%d model=%d", step, len(c.recent), c.recentOrder.Len(), len(model))
		}
		count := 0
		for name, r := range model {
			got := c.recent[name]
			if !slices.Equal(got.addrs, r.addrs) || !got.at.Equal(r.at) {
				t.Fatalf("step %d record %s differs", step, name)
			}
			for _, a := range r.addrs {
				count++
				if c.recentByAddr[a] != name {
					t.Fatalf("step %d address %v owner differs", step, a)
				}
			}
		}
		if len(c.recentByAddr) != count {
			t.Fatalf("step %d orphan index", step)
		}
	}
	for len(c.recent) > 0 {
		before := len(c.recent)
		c.expireRecent(now.Add(reconnectGrace))
		if removed := before - len(c.recent); removed < 1 || removed > 16 {
			t.Fatalf("expiry batch removed %d", removed)
		}
	}
	if len(c.recent) != 0 || len(c.recentByAddr) != 0 || c.recentOrder.Len() != 0 {
		t.Fatal("expired history retained")
	}
}

func TestAuditRecentRenewalAndInvalidation(t *testing.T) {
	c := &core{recent: map[string]recentLease{}, recentByAddr: map[netip.Addr]string{}}
	now := time.Now()
	a := netip.MustParseAddr("192.0.2.3")
	b := netip.MustParseAddr("2001:db8::3")
	snapshot := []netip.Addr{a, b}
	c.rememberRecent("alice", snapshot, now)
	c.rememberRecent("bob", []netip.Addr{netip.MustParseAddr("192.0.2.4")}, now.Add(time.Second))
	c.rememberRecent("alice", snapshot, now.Add(time.Minute))
	c.expireRecent(now.Add(reconnectGrace + time.Second))
	if len(c.recent) != 1 || len(c.recent["alice"].addrs) != 2 {
		t.Fatal("renewal lost or expired user retained")
	}
	c.invalidateRecent(a)
	if !slices.Equal(snapshot, []netip.Addr{a, b}) || !slices.Equal(c.recent["alice"].addrs, []netip.Addr{b}) {
		t.Fatal("invalidation changed other family or lease snapshot")
	}
	if _, ok := c.recentByAddr[a]; ok {
		t.Fatal("invalidated address indexed")
	}
	c.takeRecent("alice")
	if len(c.recentByAddr) != 0 || c.recentOrder.Len() != 0 {
		t.Fatal("taking record retained indexes")
	}
}

func TestAuditSessionCountsRevokeAndRelease(t *testing.T) {
	e := newTestEnv(t, dualStack())
	ctx := context.Background()
	a := e.core.acquire(ctx, alice, true, true)
	b := e.core.acquire(ctx, bob, true, true)
	if a == nil || b == nil {
		t.Fatal("initial leases")
	}
	if got := e.core.activeSessions(); !reflect.DeepEqual(got, map[string]int{"alice": 1, "bob": 1}) {
		t.Fatal(got)
	}
	e.core.setUsers(map[string]string{bob.Name: bob.Hash})
	if got := e.core.activeSessions(); !reflect.DeepEqual(got, map[string]int{"bob": 1}) {
		t.Fatal("revoked count", got)
	}
	a.release()
	if got := e.core.activeSessions(); !reflect.DeepEqual(got, map[string]int{"bob": 1}) {
		t.Fatal("revoked release changed counts", got)
	}
	e.core.setUsers(map[string]string{alice.Name: alice.Hash, bob.Name: bob.Hash})
	a = e.core.acquire(ctx, alice, true, true)
	if a == nil {
		t.Fatal("restored user")
	}
	a.release()
	b.release()
	if got := e.core.activeSessions(); len(got) != 0 || len(e.core.userSessions) != 0 {
		t.Fatal("released counts", got)
	}
}

func TestAuditConcurrentSessionLimit(t *testing.T) {
	e := newTestEnv(t, dualStack())
	e.core.maxSessions.Store(3)
	var wg sync.WaitGroup
	accepted := make(chan *lease, 24)
	for range 24 {
		wg.Go(func() {
			if l := e.core.acquire(context.Background(), alice, true, true); l != nil {
				accepted <- l
			}
		})
	}
	wg.Wait()
	close(accepted)
	var all []*lease
	for l := range accepted {
		all = append(all, l)
	}
	if len(all) != 3 || e.core.activeSessions()[alice.Name] != 3 {
		t.Fatalf("accepted=%d counts=%v", len(all), e.core.activeSessions())
	}
	for _, l := range all {
		l.release()
	}
	if len(e.core.activeSessions()) != 0 {
		t.Fatal("counts after release")
	}
}

func BenchmarkAuditAcquireHistory(b *testing.B) {
	for _, n := range []int{0, 1000, 10000} {
		b.Run(fmt.Sprintf("records_%d", n), func(b *testing.B) {
			e := newTestEnv(b, dualStack())
			e.core.forget = func([]netip.Prefix) (int, error) { return 0, nil }
			now := time.Now()
			for i := 0; i < n; i++ {
				e.core.rememberRecent(fmt.Sprintf("historical-%d", i), []netip.Addr{netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})}, now)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				l := e.core.acquire(context.Background(), alice, false, true)
				if l == nil {
					b.Fatal("acquire")
				}
				l.release()
				e.core.takeRecent(alice.Name)
			}
		})
	}
}

func BenchmarkAuditSessionLimit(b *testing.B) {
	for _, n := range []int{0, 1000, 10000} {
		b.Run(fmt.Sprintf("sessions_%d", n), func(b *testing.B) {
			c := &core{sessions: map[netip.Addr]*sessionHandle{}, userSessions: map[string]int{}}
			c.maxSessions.Store(8)
			for i := 0; i < n; i++ {
				u := auth.User{Name: fmt.Sprintf("u-%d", i/8)}
				h := &sessionHandle{id: uint64(i + 1), user: u}
				c.sessions[netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})] = h
				c.userSessions[u.Name]++
			}
			target := auth.User{Name: "new-user"}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if c.tooManySessions(target) {
					b.Fatal("limit")
				}
			}
		})
	}
}

func TestAuditExpiredDeepRecordNeedsConntrackCleanup(t *testing.T) {
	e := newTestEnv(t, &App{IPv4: "10.89.0.1/30"})
	ctx := context.Background()
	first := e.core.acquire(ctx, alice, true, false)
	if first == nil {
		t.Fatal("initial lease")
	}
	first.release()
	old := time.Now().Add(-reconnectGrace - time.Minute)
	e.core.poolMu.Lock()
	e.core.takeRecent(alice.Name)
	for i := 0; i < 40; i++ {
		e.core.rememberRecent(fmt.Sprintf("expired-%d", i), []netip.Addr{netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})}, old)
	}
	e.core.rememberRecent(alice.Name, first.addrs, old)
	e.core.poolMu.Unlock()
	e.forget.Lock()
	e.forget.err = errors.New("conntrack cleanup unavailable")
	e.forget.Unlock()
	if l := e.core.acquire(ctx, alice, true, false); l != nil {
		l.release()
		t.Fatal("expired deep record bypassed conntrack cleanup")
	}
	if calls := e.forgetCalls(); len(calls) != 1 || !slices.Equal(calls[0], []netip.Prefix{netip.PrefixFrom(first.addrs[0], 32)}) {
		t.Fatalf("cleanup calls %v", calls)
	}
	if len(e.core.recent) != 24 || e.core.recentOrder.Len() != 24 {
		t.Fatalf("bounded batch plus current user removal: %d/%d", len(e.core.recent), e.core.recentOrder.Len())
	}
	if _, ok := e.core.recentByAddr[first.addrs[0]]; ok {
		t.Fatal("failed admission retained stale owner index")
	}
	if len(e.core.activeSessions()) != 0 {
		t.Fatal("failed admission counted")
	}
	e.forget.Lock()
	e.forget.err = nil
	e.forget.Unlock()
	l := e.core.acquire(ctx, alice, true, false)
	if l == nil {
		t.Fatal("failed cleanup lost the pool address")
	}
	defer l.release()
	if len(e.forgetCalls()) != 2 {
		t.Fatal("retry skipped cleanup")
	}
}

func TestAuditPartialFamilyRollbackKeepsCountsAndIndexes(t *testing.T) {
	e := newTestEnv(t, &App{IPv4: "10.89.0.1/30", IPv6: "fd89::1/126"})
	ctx := context.Background()
	first := e.core.acquire(ctx, bob, false, true)
	second := e.core.acquire(ctx, bob, false, true)
	if first == nil || second == nil {
		t.Fatal("exhaust IPv6")
	}
	defer second.release()
	if l := e.core.acquire(ctx, alice, true, true); l != nil {
		l.release()
		t.Fatal("admitted when second family exhausted")
	}
	if got := e.core.activeSessions(); !reflect.DeepEqual(got, map[string]int{bob.Name: 2}) {
		t.Fatalf("partial allocation changed counts: %v", got)
	}
	if len(e.core.recent) != 0 || len(e.core.recentByAddr) != 0 {
		t.Fatal("partial allocation created reconnect ownership")
	}
	first.release()
	snapshot := slices.Clone(first.addrs)
	e.forget.Lock()
	e.forget.err = errors.New("conntrack cleanup unavailable")
	e.forget.Unlock()
	if l := e.core.acquire(ctx, alice, true, true); l != nil {
		l.release()
		t.Fatal("admitted despite cleanup failure")
	}
	if got := e.core.activeSessions(); !reflect.DeepEqual(got, map[string]int{bob.Name: 1}) {
		t.Fatalf("cleanup failure changed counts: %v", got)
	}
	if len(e.core.recent) != 0 || len(e.core.recentByAddr) != 0 || e.core.recentOrder.Len() != 0 {
		t.Fatal("reused address kept old reconnect indexes")
	}
	if !slices.Equal(first.addrs, snapshot) {
		t.Fatal("rollback changed old lease snapshot")
	}
	e.forget.Lock()
	e.forget.err = nil
	e.forget.Unlock()
	l := e.core.acquire(ctx, alice, true, true)
	if l == nil {
		t.Fatal("rollback lost one of the pool addresses")
	}
	defer l.release()
	if got := e.core.activeSessions(); !reflect.DeepEqual(got, map[string]int{alice.Name: 1, bob.Name: 1}) {
		t.Fatalf("retry counts: %v", got)
	}
	if calls := e.forgetCalls(); len(calls) != 2 || len(calls[0]) != 2 || len(calls[1]) != 2 {
		t.Fatalf("both rolled-back addresses need cleanup: %v", calls)
	}
}

func TestAuditSameUserLatestReleaseWins(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprintf("reverse=%v", reverse), func(t *testing.T) {
			e := newTestEnv(t, dualStack())
			ctx := context.Background()
			a := e.core.acquire(ctx, alice, true, true)
			b := e.core.acquire(ctx, alice, true, true)
			if a == nil || b == nil {
				t.Fatal("concurrent user leases")
			}
			if reverse {
				a, b = b, a
			}
			earlier, later := slices.Clone(a.addrs), slices.Clone(b.addrs)
			a.release()
			if e.core.activeSessions()[alice.Name] != 1 {
				t.Fatal("first release count")
			}
			b.release()
			if len(e.core.activeSessions()) != 0 || e.core.recentOrder.Len() != 1 || len(e.core.recentByAddr) != 2 {
				t.Fatal("latest release bookkeeping")
			}
			for _, addr := range earlier {
				if _, ok := e.core.recentByAddr[addr]; ok {
					t.Fatal("older release remains reclaimable")
				}
			}
			l := e.core.acquire(ctx, alice, true, true)
			if l == nil {
				t.Fatal("reconnect")
			}
			defer l.release()
			if !slices.Equal(l.addrs, later) || !slices.Equal(a.addrs, earlier) || !slices.Equal(b.addrs, later) {
				t.Fatal("latest release or immutable snapshots lost")
			}
			if len(e.forgetCalls()) != 0 {
				t.Fatal("same-owner reconnect cleared conntrack")
			}
		})
	}
}

func TestAuditRenewedLiveTailSurvivesBacklogDrain(t *testing.T) {
	c := &core{recent: map[string]recentLease{}, recentByAddr: map[netip.Addr]string{}}
	now := time.Now()
	old := now.Add(-reconnectGrace - time.Minute)
	for i := 0; i < 40; i++ {
		c.rememberRecent(fmt.Sprintf("expired-%d", i), []netip.Addr{netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})}, old)
	}
	live := netip.MustParseAddr("2001:db8::1")
	c.rememberRecent("live", []netip.Addr{live}, now)
	if len(c.recent) != 25 {
		t.Fatalf("first expiry batch: %d", len(c.recent))
	}
	renewed := now.Add(time.Second)
	c.rememberRecent("live", []netip.Addr{live}, renewed)
	if len(c.recent) != 9 || !c.recent["live"].at.Equal(renewed) || c.recentOrder.Back().Value != "live" {
		t.Fatal("renewal did not retain live tail")
	}
	c.expireRecent(now.Add(2 * time.Second))
	if len(c.recent) != 1 || len(c.recentByAddr) != 1 || c.recentByAddr[live] != "live" {
		t.Fatal("draining backlog removed live tail")
	}
	c.expireRecent(renewed.Add(reconnectGrace))
	if len(c.recent) != 0 || len(c.recentByAddr) != 0 || c.recentOrder.Len() != 0 {
		t.Fatal("renewed entry did not expire")
	}
}

// Run with -test.benchtime=1x so every sample measures one admission-time
// expiration batch after a complete idle backlog, not an already empty cache.
func BenchmarkAuditExpireBacklog(b *testing.B) {
	for _, n := range []int{16, 1000, 10000} {
		b.Run(fmt.Sprintf("records_%d", n), func(b *testing.B) {
			c := &core{recent: map[string]recentLease{}, recentByAddr: map[netip.Addr]string{}}
			now := time.Now()
			old := now.Add(-reconnectGrace - time.Minute)
			for i := 0; i < n; i++ {
				c.rememberRecent(fmt.Sprintf("expired-%d", i), []netip.Addr{netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})}, old)
			}
			if b.N != 1 {
				b.Fatal("requires -test.benchtime=1x")
			}
			b.ReportAllocs()
			b.ResetTimer()
			c.expireRecent(now)
		})
	}
}

func TestAuditSessionLimitRejectsBeforePoolWork(t *testing.T) {
	e := newTestEnv(t, &App{IPv4: "10.89.0.1/29"})
	e.core.maxSessions.Store(1)
	first := e.core.acquire(context.Background(), alice, true, false)
	if first == nil {
		t.Fatal("initial lease")
	}
	defer first.release()
	for range 10 {
		if l := e.core.acquire(context.Background(), alice, true, false); l != nil {
			l.release()
			t.Fatal("admitted over limit")
		}
	}
	if calls := e.forgetCalls(); len(calls) != 0 {
		t.Errorf("rejected admissions cleared conntrack: %v", calls)
	}
	if len(e.core.recent) != 0 {
		t.Error("rejected admissions changed reconnect history")
	}
	e.core.poolMu.Lock()
	addr, used, ok := e.core.pool.Allocate(false)
	if ok {
		e.core.pool.Release(addr)
	}
	e.core.poolMu.Unlock()
	if !ok || used {
		t.Fatalf("rejected admissions consumed never-used pool history: addr=%v used=%v ok=%v", addr, used, ok)
	}
	if got := e.core.activeSessions(); len(got) != 1 || got[alice.Name] != 1 {
		t.Fatal("rejected counts", got)
	}
}
