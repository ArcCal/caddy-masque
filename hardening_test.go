package masque

import (
	"net/http"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

func init() {
	// Tests send many wrong passwords from one address; the throttle has
	// tests of its own.
	loginFailures = 1 << 20
}

func TestCaddyLoginThrottle(t *testing.T) {
	loginFailures = 3
	t.Cleanup(func() { loginFailures = 1 << 20 })
	e := newCaddyEnv(t)
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	// The limit is per client address, whatever the transport.
	tr := transports[1]
	for i := 0; i < 3; i++ {
		tr.dial(e, t, "wrong password!!", anyTarget).close()
	}
	// Throttled: even the right password is not checked, and the answer is
	// the site's, like for any request without credentials.
	got := tr.dial(e, t, testPassword, anyTarget)
	if got.status != http.StatusOK || got.body != "cover page" {
		t.Errorf("throttled client: %d %q", got.status, got.body)
	}
}

func TestCaddyMaxSessions(t *testing.T) {
	e := newCaddyEnv(t)
	cfg := masqueConfig("alice")
	cfg["max_sessions"] = 2
	if err := e.load(cfg); err != nil {
		t.Fatal(err)
	}
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			a, b := tr.dial(e, t, testPassword, anyTarget), tr.dial(e, t, testPassword, anyTarget)
			if a.status != tr.ok || b.status != tr.ok {
				t.Fatalf("first two sessions: %d, %d", a.status, b.status)
			}
			if c := tr.dial(e, t, testPassword, anyTarget); c.status != http.StatusTooManyRequests {
				t.Errorf("third session: %d, want 429", c.status)
			}
			a.close()
			waitNoSessionsOf(t, 1)
			c := tr.dial(e, t, testPassword, anyTarget)
			if c.status != tr.ok {
				t.Errorf("session after one ended: %d", c.status)
			}
			c.close()
			b.close()
			waitNoSessions(t)
		})
	}
}

// waitNoSessionsOf waits until the cores hold n sessions.
func waitNoSessionsOf(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < 60; i++ {
		got := 0
		cores.Range(func(_ any, v any) bool {
			for _, c := range v.(*core).activeSessions() {
				got += c
			}
			return true
		})
		if got == n {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("sessions did not drop to %d", n)
}

func TestMetrics(t *testing.T) {
	c, err := newCore(tunnelConfig{}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	c.counters.sessionsStarted.Add(2)
	c.counters.authFailures.Add(3)
	c.counters.bytesToClient.Add(1500)
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(newCollector(c)); err != nil {
		t.Fatal(err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]float64{}
	for _, f := range families {
		for _, m := range f.Metric {
			name := f.GetName()
			for _, l := range m.Label {
				name += "/" + l.GetValue()
			}
			values[name] = m.GetCounter().GetValue()
		}
	}
	if values["caddy_masque_sessions_started_total"] != 2 || values["caddy_masque_auth_failures_total"] != 3 ||
		values["caddy_masque_bytes_total/to_client"] != 1500 {
		t.Errorf("metrics: %v", values)
	}
}

// The metrics reach the registry of the running configuration, which Caddy's
// admin endpoint (/metrics) and the metrics directive serve.
func TestMetricsInCaddyRegistry(t *testing.T) {
	e := newCaddyEnv(t)
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	c := e.dialH2(t, testPassword, anyTarget)
	defer c.close()
	ctx := caddy.ActiveContext()
	families, err := ctx.GetMetricsRegistry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == "caddy_masque_sessions_active" {
			if len(f.Metric) != 1 || f.Metric[0].GetGauge().GetValue() != 1 {
				t.Errorf("sessions_active: %v", f.Metric)
			}
			return
		}
	}
	t.Error("no caddy_masque_sessions_active in the registry")
}
