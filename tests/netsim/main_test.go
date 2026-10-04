package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRateLimitsBurstsAndCanBeRemoved(t *testing.T) {
	now := time.Unix(1000, 0)
	p := &params{delay: 60 * time.Millisecond, rate: 4_000_000}
	due := packetDue(now, time.Time{}, 1000, p)
	for range 500 {
		due = packetDue(now, due, 1000, p)
	}
	if got := due.Sub(now); got != 1060*time.Millisecond {
		t.Fatalf("500 queued 1000-byte packets must consume one second at 4 Mbit/s: %v", got)
	}
	if got := packetDue(now, time.Time{}, 65535, p).Sub(now); got != 131070*time.Microsecond {
		t.Fatalf("an idle link must still charge the first packet's bandwidth: %v", got)
	}
	p.rate = 0
	if got := packetDue(due, due, 1000, p).Sub(due); got != p.delay {
		t.Fatalf("removed rate still delayed packet: %v", got)
	}
}

func TestRateParameters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "params")
	for _, rate := range []string{"4000000", "0", "-1", "1000000000001", "invalid"} {
		if err := os.WriteFile(path, []byte("delay=60ms\nrate="+rate+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		p, err := readParams(path)
		valid := rate == "4000000" || rate == "0"
		if valid != (err == nil) {
			t.Fatalf("rate %q: params=%v, err=%v", rate, p, err)
		}
	}
}
