package masque

import (
	"sync"
	"testing"
	"time"
)

type blockingRepair struct {
	entered, release chan struct{}
	once             sync.Once
}

func (r *blockingRepair) Repair() []string {
	r.once.Do(func() { close(r.entered) })
	<-r.release
	return nil
}

func TestDestructWaitsForHostRepair(t *testing.T) {
	e := newTestEnv(t, &App{})
	r := &blockingRepair{entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	unblock := func() { release.Do(func() { close(r.release) }) }
	defer unblock()
	e.core.startHostWatcher(r, time.Millisecond)
	select {
	case <-r.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("host repair did not start")
	}
	done := make(chan struct{})
	go func() { _ = e.core.Destruct(); close(done) }()
	<-e.core.ctx.Done()
	select {
	case <-e.dev.closed:
		t.Error("network closed while firewall repair was still in progress")
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not finish after repair returned")
	}
}
