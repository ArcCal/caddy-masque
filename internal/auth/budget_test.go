package auth

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestMemoryBudgetRejectsUnaffordableHash(t *testing.T) {
	if _, err := NewWithMemory(MinMemoryBudgetKiB - 1); err == nil {
		t.Fatal("accepted a budget smaller than the unknown-user verification")
	}
	large := strings.Replace(rustHash, "m=19456", "m=1048576", 1)
	if err := ValidateHashWithMemory(large, DefaultMemoryBudgetKiB); err == nil {
		t.Fatal("hash exceeding the total budget passed validation")
	}
	a := New()
	a.Replace(map[string]string{"alice": large})
	if _, _, err := a.Verify(context.Background(), BasicAuthorization("alice", "guess"), src); !errors.Is(err, ErrBusy) {
		t.Fatal("runtime defense did not reject the oversized hash:", err)
	}
	if len(a.slots) != 0 || a.waiting.Load() != 0 || a.sourcesInUse() != 0 || a.memoryInUse.Load() != 0 {
		t.Fatal("unaffordable hash reserved resources")
	}
}

func TestMemoryAdmissionCancellationAndRecovery(t *testing.T) {
	a, err := NewWithMemory(MinMemoryBudgetKiB)
	if err != nil {
		t.Fatal(err)
	}
	a.Replace(map[string]string{"alice": rustHash})
	if cap(a.slots) != 2*runtime.GOMAXPROCS(0) {
		t.Fatal("CPU admission ignores the runtime's CPU quota")
	}
	// Occupy all memory, leaving CPU places available: the request must
	// wait without hashing, then return its CPU/source places on cancellation.
	if !a.memory.TryAcquire(int64(MinMemoryBudgetKiB)) {
		t.Fatal("initial memory reservation failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, err := a.Verify(ctx, BasicAuthorization("alice", rustPassword), src)
		done <- err
	}()
	waitFor(t, "memory admission queued", func() bool { return a.waiting.Load() == 1 })
	if a.memoryInUse.Load() != 0 {
		t.Fatal("hash started without a memory reservation")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(a.slots) != 0 || a.waiting.Load() != 0 || a.sourcesInUse() != 0 {
		t.Fatal("cancelled memory admission leaked reservations")
	}
	a.memory.Release(int64(MinMemoryBudgetKiB))
	if _, ok, err := a.Verify(context.Background(), BasicAuthorization("alice", rustPassword), src); !ok || err != nil {
		t.Fatal("legitimate login did not recover:", ok, err)
	}
	waitFor(t, "hash resources released", func() bool { return a.memoryInUse.Load() == 0 && len(a.slots) == 0 })
	if !a.memory.TryAcquire(int64(MinMemoryBudgetKiB)) {
		t.Fatal("memory remained reserved after verification")
	}
	a.memory.Release(int64(MinMemoryBudgetKiB))
}

func TestCancelledHashRetainsMemoryUntilFinished(t *testing.T) {
	a := New()
	a.Replace(map[string]string{"alice": rustHash})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := a.Verify(ctx, BasicAuthorization("alice", rustPassword), src)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// The caller can leave immediately; the real hash is still protected.
	if a.memoryInUse.Load() != defaultMemory || len(a.slots) != 1 {
		t.Fatal("cancelled caller released resources before hashing finished")
	}
	waitFor(t, "cancelled hash finishes", func() bool { return a.memoryInUse.Load() == 0 && len(a.slots) == 0 && a.sourcesInUse() == 0 })
	// A fresh caller can verify afterwards; no semaphore weight leaked.
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, ok, err := a.Verify(ctx, BasicAuthorization("alice", rustPassword), src); !ok || err != nil {
		t.Fatal(ok, err)
	}
}

func TestMemoryAdmissionDeadline(t *testing.T) {
	a, err := NewWithMemory(MinMemoryBudgetKiB)
	if err != nil {
		t.Fatal(err)
	}
	a.Replace(map[string]string{"alice": rustHash})
	if !a.memory.TryAcquire(int64(MinMemoryBudgetKiB)) {
		t.Fatal("cannot fill memory budget")
	}
	defer a.memory.Release(int64(MinMemoryBudgetKiB))
	started := time.Now()
	_, _, err = a.Verify(context.Background(), BasicAuthorization("alice", rustPassword), src)
	if !errors.Is(err, ErrBusy) || time.Since(started) < maxAdmissionWait || time.Since(started) > maxAdmissionWait+2*time.Second {
		t.Fatalf("admission deadline: %v, %v", err, time.Since(started))
	}
	if len(a.slots) != 0 || a.waiting.Load() != 0 || a.sourcesInUse() != 0 || a.memoryInUse.Load() != 0 {
		t.Fatal("timed out admission leaked resources")
	}
}
