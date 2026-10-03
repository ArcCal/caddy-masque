package auth

import (
	"net/netip"
	"sync"
	"time"
)

// FailureLimiter stops a client address that keeps presenting wrong
// credentials: after max failures within a window, its requests that carry
// credentials are not verified (the caller treats them as it does requests
// without credentials) until the window has passed. Hashing is slow on
// purpose, and the generated passwords cannot be guessed, but a user-chosen
// password can, and every attempt costs the server CPU and memory.
//
// Clients are told apart by source (see sourceKey). Clients behind one
// shared address share the budget, so a short window bounds how long one of
// them can lock the others out; credentials verified recently still get in
// (see Authenticator.Remembered).
type FailureLimiter struct {
	max    int
	window time.Duration

	mu sync.Mutex
	m  map[netip.Addr]*failures
	// Entries are dropped when expired; at the cap, new addresses are not
	// tracked (the limiter fails open) so the table stays small.
	maxEntries int
}

type failures struct {
	n     int
	start time.Time
}

// NewFailureLimiter allows max failures per window.
func NewFailureLimiter(max int, window time.Duration) *FailureLimiter {
	return &FailureLimiter{max: max, window: window, m: map[netip.Addr]*failures{}, maxEntries: 10000}
}

// sourceKey is what counts as one client: an IPv4 address, or the /64 of
// an IPv6 address, since one host usually has a whole /64 to choose from.
func sourceKey(a netip.Addr) netip.Addr {
	a = a.Unmap().WithZone("")
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.Addr()
	}
	return a
}

// Blocked reports whether the address has used up its failures.
func (l *FailureLimiter) Blocked(a netip.Addr) bool {
	return l.blockedAt(a, time.Now())
}

func (l *FailureLimiter) blockedAt(a netip.Addr, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.m[sourceKey(a)]
	return f != nil && now.Sub(f.start) < l.window && f.n >= l.max
}

// Fail records a failed verification.
func (l *FailureLimiter) Fail(a netip.Addr) { l.failAt(a, time.Now()) }

func (l *FailureLimiter) failAt(a netip.Addr, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := sourceKey(a)
	f := l.m[k]
	if f != nil && now.Sub(f.start) >= l.window {
		f = nil
	}
	if f == nil {
		if _, tracked := l.m[k]; !tracked && len(l.m) >= l.maxEntries {
			for k, v := range l.m {
				if now.Sub(v.start) >= l.window {
					delete(l.m, k)
				}
			}
			if len(l.m) >= l.maxEntries {
				return
			}
		}
		f = &failures{start: now}
		l.m[k] = f
	}
	f.n++
}
