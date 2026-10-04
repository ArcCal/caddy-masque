package masque

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestSessionAdmissionIncludesPendingConntrack(t *testing.T) {
	e := newTestEnv(t, &App{IPv4: "10.89.0.1/30"})
	c := e.core
	c.maxTotalSessions.Store(1)
	c.maxSessions.Store(1)
	first := c.acquire(context.Background(), alice, true, false)
	if first == nil {
		t.Fatal("initial lease refused")
	}
	first.release()
	entered, finish := make(chan struct{}), make(chan struct{})
	c.forget = func(_ []netip.Prefix) (int, error) {
		close(entered)
		<-finish
		return 1, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var finishOnce sync.Once
	unblock := func() { finishOnce.Do(func() { close(finish) }) }
	defer unblock()
	result := make(chan *lease, 1)
	go func() { result <- c.acquire(ctx, bob, true, false) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("connection tracking cleanup did not start")
	}
	if !c.tooManySessions(bob) {
		t.Fatal("pending lease does not count toward per-user limit")
	}
	// Even another user must be refused before address allocation/cleanup.
	if got := c.acquire(context.Background(), alice, true, false); got != nil {
		got.release()
		t.Fatal("pending lease does not count toward total limit")
	}
	cancel()
	unblock()
	if got := <-result; got != nil {
		got.release()
		t.Fatal("cancelled acquisition was registered")
	}
	if c.tooManySessions(bob) {
		t.Fatal("cancelled acquisition leaked per-user reservation")
	}
	c.forget = func(_ []netip.Prefix) (int, error) { return 1, nil }
	next := c.acquire(context.Background(), alice, true, false)
	if next == nil {
		t.Fatal("cancelled acquisition leaked addresses or global reservation")
	}
	next.release()
}

func TestSessionAdmissionConcurrentAndRevoked(t *testing.T) {
	e := newTestEnv(t, &App{IPv6: "fd89::1/64"})
	c := e.core
	c.maxTotalSessions.Store(3)
	c.maxSessions.Store(2)
	var wg sync.WaitGroup
	leases := make(chan *lease, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := alice
			if i%2 == 0 {
				u = bob
			}
			if l := c.acquire(context.Background(), u, true, true); l != nil {
				leases <- l
			}
		}(i)
	}
	wg.Wait()
	close(leases)
	got := []*lease{}
	counts := map[string]int{}
	for l := range leases {
		got = append(got, l)
		counts[l.handle.user.Name]++
	}
	if len(got) != 3 || counts[alice.Name] > 2 || counts[bob.Name] > 2 {
		t.Fatalf("concurrent admission: total %d, users %v", len(got), counts)
	}
	c.setUsers(map[string]string{})
	c.setUsers(map[string]string{alice.Name: alice.Hash, bob.Name: bob.Hash})
	if l := c.acquire(context.Background(), alice, true, true); l != nil {
		l.release()
		t.Fatal("revocation released admission before session cleanup")
	}
	for _, l := range got {
		// Concurrent duplicate cleanup must be harmless, including counters.
		wg.Add(2)
		go func() { defer wg.Done(); l.release() }()
		go func() { defer wg.Done(); l.release() }()
	}
	wg.Wait()
	c.sessMu.RLock()
	reserved, users := c.reservedSessions, len(c.sessionCounts)
	c.sessMu.RUnlock()
	if reserved != 0 || users != 0 {
		t.Fatalf("cleanup leaked admission: %d/%d", reserved, users)
	}
	if l := c.acquire(context.Background(), alice, true, true); l == nil {
		t.Fatal("no recovery after cleanup")
	} else {
		l.release()
	}
}

func TestQueueBudgetSharedAndReleased(t *testing.T) {
	e := newTestEnv(t, &App{})
	c := e.core
	c.queueBudget.limit = 64
	a, b := c.acquire(context.Background(), alice, true, false), c.acquire(context.Background(), bob, true, false)
	if a == nil || b == nil {
		t.Fatal("missing leases")
	}
	defer a.release()
	defer b.release()
	pkt := make([]byte, 40)
	pkt[0] = 7
	a.handle.enqueue(c, pkt)
	pkt[0] = 9
	b.handle.enqueue(c, pkt)
	if len(b.handle.toClient) != 0 || c.counters.dropped.Load() != 1 || c.queueBudget.used.Load() != 41 {
		t.Fatal("aggregate queue budget not enforced")
	}
	q := <-a.handle.toClient
	if q.pkt[0] != 0 || q.pkt[1] != 7 {
		t.Fatal("queued packet was not copied with context ID 0")
	}
	q.release() // same operation as sendToClientLoop dequeue
	b.handle.enqueue(c, pkt)
	if len(b.handle.toClient) != 1 {
		t.Fatal("queue capacity did not recover on dequeue")
	}
	b.release()
	b.handle.enqueue(c, pkt)
	if c.queueBudget.used.Load() != 0 || len(b.handle.toClient) != 0 {
		t.Fatal("closed queue leaked memory reservation")
	}
	// Local queue capacity also counts drops without reserving/copying.
	a.handle.toClient = make(chan queued, 1)
	a.handle.enqueue(c, pkt)
	a.handle.enqueue(c, pkt)
	if c.counters.dropped.Load() != 2 || c.queueBudget.used.Load() != 41 {
		t.Fatal("full queue accounting")
	}
	a.release()
	if c.queueBudget.used.Load() != 0 {
		t.Fatal("lease cleanup leaked queued packets")
	}
}

func TestQueueCleanupRacesWithEnqueue(t *testing.T) {
	e := newTestEnv(t, &App{})
	c := e.core
	l := c.acquire(context.Background(), alice, true, false)
	if l == nil {
		t.Fatal("no lease")
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 100; j++ {
				l.handle.enqueue(c, slices.Repeat([]byte{1}, 100))
			}
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); <-start; l.release() }()
	close(start)
	wg.Wait()
	if c.queueBudget.used.Load() != 0 || len(l.handle.toClient) != 0 {
		t.Fatal("enqueue after cleanup retained packets")
	}
}

func TestCaddyGlobalSessionLimit(t *testing.T) {
	e := newCaddyEnv(t)
	cfg := masqueConfig("alice")
	cfg["max_total_sessions"] = 1
	if err := e.load(cfg); err != nil {
		t.Fatal(err)
	}
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			first := tr.dial(e, t, testPassword, anyTarget)
			if first.status != tr.ok {
				t.Fatal(first.status)
			}
			second := tr.dial(e, t, testPassword, anyTarget)
			second.close()
			if second.status != http.StatusServiceUnavailable {
				t.Fatalf("full server: %d, want 503", second.status)
			}
			first.close()
			waitNoSessions(t)
			third := tr.dial(e, t, testPassword, anyTarget)
			if third.status != tr.ok {
				t.Fatalf("server after cleanup: %d", third.status)
			}
			third.close()
			waitNoSessions(t)
		})
	}
}
