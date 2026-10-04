package masque

import (
	"strings"
	"testing"

	"github.com/ArcCal/caddy-masque/internal/auth"
)

func TestResourceConfiguration(t *testing.T) {
	a := &App{IPv4: "10.89.0.1/24"}
	if err := a.parse(); err != nil {
		t.Fatal(err)
	}
	if a.cfg.authMemoryKiB != auth.DefaultMemoryBudgetKiB || a.cfg.queueMemoryBytes != DefaultQueueMemoryBytes {
		t.Fatal("unexpected default budgets")
	}
	for _, app := range []App{
		{AuthMemoryMiB: -1}, {AuthMemoryMiB: 18}, {AuthMemoryMiB: 1025},
		{QueueMemoryMiB: -1}, {QueueMemoryMiB: 1025}, {MaxTotalSessions: -1},
		{Users: []User{{"alice", strings.Replace(testHash, "m=19456", "m=1048576", 1)}}},
	} {
		app.IPv4 = a.IPv4
		if err := app.parse(); err == nil {
			t.Errorf("accepted invalid budget/hash: %+v", app)
		}
	}
	for _, budget := range []int{19, 64, 1024} {
		a := &App{IPv4: "10.89.0.1/24", AuthMemoryMiB: budget, Users: []User{{"alice", testHash}}}
		if err := a.parse(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCaddyMemoryBudgetChangeRequiresRestart(t *testing.T) {
	for _, setting := range []string{"auth_memory_mib", "queue_memory_mib"} {
		t.Run(setting, func(t *testing.T) {
			e := newCaddyEnv(t)
			if err := e.load(masqueConfig("alice")); err != nil {
				t.Fatal(err)
			}
			c := e.dialH2(t, testPassword, anyTarget)
			defer c.close()
			v4, _ := opening(t, c)
			changed := masqueConfig("alice")
			changed[setting] = 32
			if err := e.load(changed); err == nil || !strings.Contains(err.Error(), "restart Caddy") {
				t.Fatalf("budget change: %v", err)
			}
			p := udp(v4.String(), "1.1.1.1", 16)
			if err := c.send(p); err != nil {
				t.Fatal(err)
			}
			hostPacket(t, e.dev)
		})
	}
}

func TestCaddySessionBudgetCanReload(t *testing.T) {
	e := newCaddyEnv(t)
	cfg := masqueConfig("alice")
	cfg["max_total_sessions"] = 1
	if err := e.load(cfg); err != nil {
		t.Fatal(err)
	}
	first := e.dialH2(t, testPassword, anyTarget)
	defer first.close()
	opening(t, first)
	cfg["max_total_sessions"] = 2
	if err := e.load(cfg); err != nil {
		t.Fatal(err)
	}
	second := e.dialH2(t, testPassword, anyTarget)
	defer second.close()
	if second.status != 200 {
		t.Fatal(second.status)
	}
}
