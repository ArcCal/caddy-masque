package masque

import (
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
)

// counters are the totals since the core started. Packets are the IP packets
// of tunnels (not their QUIC or TLS framing); the counters outlive reloads,
// like the core.
type counters struct {
	sessionsStarted, authFailures, throttled atomic.Uint64
	toClient, fromClient, dropped            atomic.Uint64
	bytesToClient, bytesFromClient           atomic.Uint64
}

// collector exports the core's state to Caddy's metrics endpoint (the
// `metrics` directive). Every configuration has a registry of its own, so a
// collector reading the shared core is registered in each.
type collector struct {
	core                                                        *core
	active, started, failures, throttled, packets, bytes, drops *prometheus.Desc
}

func newCollector(c *core) *collector {
	d := func(name, help string, labels ...string) *prometheus.Desc {
		return prometheus.NewDesc("caddy_masque_"+name, help, labels, nil)
	}
	return &collector{core: c,
		active:    d("sessions_active", "Tunnels open now, by user.", "user"),
		started:   d("sessions_started_total", "Tunnels opened."),
		failures:  d("auth_failures_total", "CONNECT-IP requests with wrong credentials."),
		throttled: d("auth_throttled_total", "Requests with credentials not checked because their address failed too often."),
		packets:   d("packets_total", "IP packets forwarded, by direction.", "direction"),
		bytes:     d("bytes_total", "Bytes of IP packets forwarded, by direction.", "direction"),
		drops:     d("packets_dropped_total", "IP packets dropped: not allowed, spoofed source, queue too slow or too long."),
	}
}

func (m *collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{m.active, m.started, m.failures, m.throttled, m.packets, m.bytes, m.drops} {
		ch <- d
	}
}

func (m *collector) Collect(ch chan<- prometheus.Metric) {
	c := m.core
	counter := func(d *prometheus.Desc, v uint64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, float64(v), labels...)
	}
	counter(m.started, c.counters.sessionsStarted.Load())
	counter(m.failures, c.counters.authFailures.Load())
	counter(m.throttled, c.counters.throttled.Load())
	counter(m.packets, c.counters.toClient.Load(), "to_client")
	counter(m.packets, c.counters.fromClient.Load(), "from_client")
	counter(m.bytes, c.counters.bytesToClient.Load(), "to_client")
	counter(m.bytes, c.counters.bytesFromClient.Load(), "from_client")
	counter(m.drops, c.counters.dropped.Load())
	for user, n := range c.activeSessions() {
		ch <- prometheus.MustNewConstMetric(m.active, prometheus.GaugeValue, float64(n), user)
	}
}

// activeSessions counts the sessions of each configured user.
func (c *core) activeSessions() map[string]int {
	c.sessMu.RLock()
	defer c.sessMu.RUnlock()
	seen := map[uint64]bool{}
	out := map[string]int{}
	for _, s := range c.sessions {
		if !seen[s.id] {
			seen[s.id] = true
			out[s.user.Name]++
		}
	}
	return out
}
