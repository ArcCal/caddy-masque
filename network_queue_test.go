package masque

import (
	"context"
	"encoding/binary"
	"io"
	"net/netip"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

type queueNetworkDevice struct {
	packet           []byte
	remaining, index int
	sequence         bool
	cancel           context.CancelFunc
}

func (d *queueNetworkDevice) Read(out []byte) (int, error) {
	if d.remaining == 0 {
		d.cancel()
		return 0, io.EOF
	}
	d.remaining--
	n := copy(out, d.packet)
	if d.sequence {
		binary.BigEndian.PutUint32(out[28:], uint32(d.index))
		d.index++
	}
	return n, nil
}
func (*queueNetworkDevice) Write(p []byte) (int, error) { return len(p), nil }
func (*queueNetworkDevice) Close() error                { return nil }

func queueTestCore(count int, sequence bool) (*core, *sessionHandle) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &sessionHandle{id: 1, toClient: make(chan queued, queueLen)}
	c := &core{ctx: ctx, cancel: cancel, done: make(chan struct{}), sessions: map[netip.Addr]*sessionHandle{netip.MustParseAddr("10.89.0.2"): s}}
	c.net = &queueNetworkDevice{packet: udp("192.0.2.1", "10.89.0.2", 1252), remaining: count, sequence: sequence, cancel: cancel}
	return c, s
}

func TestNetworkQueueOverflowAccountingAndOwnership(t *testing.T) {
	c, s := queueTestCore(queueLen+1, true)
	defer c.cancel()
	c.readNetwork()
	if got := c.counters.dropped.Load(); got != 1 {
		t.Errorf("overflow drops=%d, want1", got)
	}
	if got := s.stats.dropped.Load(); got != 1 {
		t.Errorf("per-session overflow drops=%d, want1", got)
	}
	if len(s.toClient) != queueLen {
		t.Fatalf("queued=%d", len(s.toClient))
	}
	for i := range queueLen {
		q := <-s.toClient
		if len(q.pkt) != 1281 || q.pkt[0] != 0 || q.at.IsZero() {
			t.Fatalf("invalid queued packet%d", i)
		}
		if got := binary.BigEndian.Uint32(q.pkt[29:]); got != uint32(i) {
			t.Fatalf("queued payload%d changed to%d", i, got)
		}
	}
	registry := prometheus.NewRegistry()
	if err := registry.Register(newCollector(c)); err != nil {
		t.Fatal(err)
	}
	metrics, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, metric := range metrics {
		if metric.GetName() == "caddy_masque_packets_dropped_total" {
			found = true
			if got := metric.Metric[0].Counter.GetValue(); got != 1 {
				t.Errorf("exported overflow drops=%v, want1", got)
			}
		}
	}
	if !found {
		t.Fatal("drop metric missing")
	}
}

func BenchmarkNetworkReadFullQueue(b *testing.B) {
	c, s := queueTestCore(b.N, false)
	defer c.cancel()
	for range queueLen {
		s.toClient <- queued{}
	}
	b.ReportAllocs()
	b.SetBytes(1280)
	b.ResetTimer()
	c.readNetwork()
	b.StopTimer()
}
