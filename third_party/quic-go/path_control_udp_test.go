package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/testdata"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"
	"github.com/stretchr/testify/require"
)

func reviewPathTLS() (*tls.Config, *tls.Config) {
	s := testdata.GetTLSConfig()
	s.NextProtos = []string{"path-control-review"}
	c := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: testdata.GetRootCA(), ServerName: "localhost", NextProtos: s.NextProtos}
	return s, c
}

func reviewPathConfig(rec *events.Recorder) *Config {
	return &Config{EnableDatagrams: true, DisablePathMTUDiscovery: true, Tracer: func(context.Context, bool, ConnectionID) qlogwriter.Trace { return &events.Trace{Recorder: rec} }}
}

func TestReviewTwoChallengesOneRealUDPPacket(t *testing.T) {
	sTLS, cTLS := reviewPathTLS()
	var sent, received events.Recorder
	ln, err := Listen(newUDPConnLocalhost(t), sTLS, reviewPathConfig(&sent))
	require.NoError(t, err)
	defer ln.Close()
	tr := &Transport{Conn: newUDPConnLocalhost(t), ConnectionIDLength: 4}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := tr.Dial(ctx, ln.Addr(), cTLS, reviewPathConfig(&received))
	require.NoError(t, err)
	defer c.CloseWithError(0, "")
	s, err := ln.Accept(ctx)
	require.NoError(t, err)
	defer s.CloseWithError(0, "")
	c.getPathManager() // unsolicited response matching is harmlessly ignored
	a, b := [8]byte{1, 2, 3, 4}, [8]byte{5, 6, 7, 8}
	c.framer.controlFrameMutex.Lock()
	c.framer.controlFrames = append(c.framer.controlFrames, &wire.PathChallengeFrame{Data: a}, &wire.PathChallengeFrame{Data: b})
	c.framer.controlFrameMutex.Unlock()
	c.scheduleSending()
	require.Eventually(t, func() bool {
		for _, e := range sent.Events(qlog.PacketReceived{}) {
			count := 0
			for _, f := range e.(qlog.PacketReceived).Frames {
				if p, ok := f.Frame.(*qlog.PathChallengeFrame); ok && (p.Data == a || p.Data == b) {
					count++
				}
			}
			if count == 2 {
				return true
			}
		}
		return false
	}, time.Second, time.Millisecond, "server must receive both challenges in one authentic packet")
	require.Eventually(t, func() bool {
		seen := map[[8]byte]bool{}
		for _, e := range received.Events(qlog.PacketReceived{}) {
			for _, f := range e.(qlog.PacketReceived).Frames {
				if p, ok := f.Frame.(*qlog.PathResponseFrame); ok {
					seen[p.Data] = true
				}
			}
		}
		return seen[a] && seen[b]
	}, time.Second, time.Millisecond, "each received challenge requires its own echoed response")
	require.NoError(t, c.SendDatagram([]byte("still usable")))
	p, err := s.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("still usable"), p)
}

func TestReviewPreviousPathProbeRealUDP(t *testing.T) {
	for _, dead := range []bool{false, true} {
		t.Run(map[bool]string{false: "old viable", true: "old dead"}[dead], func(t *testing.T) {
			sTLS, cTLS := reviewPathTLS()
			var serverEvents events.Recorder
			ln, err := Listen(newUDPConnLocalhost(t), sTLS, reviewPathConfig(&serverEvents))
			require.NoError(t, err)
			defer ln.Close()
			front, old, fresh := newUDPConnLocalhost(t), newUDPConnLocalhost(t), newUDPConnLocalhost(t)
			var route atomic.Pointer[net.UDPConn]
			route.Store(old)
			var peer atomic.Pointer[net.UDPAddr]
			var armed atomic.Bool
			oldPackets := make(chan []byte, 64)
			var wg sync.WaitGroup
			wg.Add(3)
			go func() {
				defer wg.Done()
				buf := make([]byte, 65535)
				for {
					n, addr, err := front.ReadFromUDP(buf)
					if err != nil {
						return
					}
					peer.Store(addr)
					_, _ = route.Load().WriteToUDP(buf[:n], ln.Addr().(*net.UDPAddr))
				}
			}()
			for _, socket := range []*net.UDPConn{old, fresh} {
				go func(socket *net.UDPConn) {
					defer wg.Done()
					buf := make([]byte, 65535)
					for {
						n, _, err := socket.ReadFromUDP(buf)
						if err != nil {
							return
						}
						if socket == old && armed.Load() {
							select {
							case oldPackets <- bytes.Clone(buf[:n]):
							default:
							}
							if dead {
								continue
							}
						}
						if addr := peer.Load(); addr != nil {
							_, _ = front.WriteToUDP(buf[:n], addr)
						}
					}
				}(socket)
			}
			defer func() { front.Close(); old.Close(); fresh.Close(); wg.Wait() }()
			tr := &Transport{Conn: newUDPConnLocalhost(t), ConnectionIDLength: 4}
			defer tr.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			c, err := tr.Dial(ctx, front.LocalAddr(), cTLS, &Config{EnableDatagrams: true, DisablePathMTUDiscovery: true})
			require.NoError(t, err)
			defer c.CloseWithError(0, "")
			s, err := ln.Accept(ctx)
			require.NoError(t, err)
			defer s.CloseWithError(0, "")
			require.NoError(t, c.SendDatagram([]byte("settle")))
			_, err = s.ReceiveDatagram(ctx)
			require.NoError(t, err)
			time.Sleep(75 * time.Millisecond)
			armed.Store(true)
			route.Store(fresh)
			require.NoError(t, c.SendDatagram([]byte("migration")))
			_, err = s.ReceiveDatagram(ctx)
			require.NoError(t, err)
			var observed []byte
			var previousToken [8]byte
			require.Eventually(t, func() bool {
				for {
					var packet []byte
					select {
					case packet = <-oldPackets:
					default:
						return false
					}
					if len(packet) < 1200 {
						continue // a delayed ordinary ACK is not the probe
					}
					cid, err := wire.ParseConnectionID(packet, 4)
					if err != nil {
						continue
					}
					for _, e := range serverEvents.Events(qlog.PacketSent{}) {
						p := e.(qlog.PacketSent)
						if p.Header.DestConnectionID != cid || p.Raw.Length != len(packet) {
							continue
						}
						for _, f := range p.Frames {
							if challenge, ok := f.Frame.(*qlog.PathChallengeFrame); ok {
								observed = packet
								previousToken = challenge.Data
								return true
							}
						}
					}
				}
			}, time.Second, time.Millisecond, "a padded PATH_CHALLENGE must reach the previously active UDP path")
			require.Eventually(t, func() bool { return s.RemoteAddr().String() == fresh.LocalAddr().String() }, time.Second, time.Millisecond, "valid rebinding must complete even when the old path is dead")
			if !dead {
				// The relay now forwards all client sends through fresh, so
				// this also exercises receipt of the old token on another path.
				require.Eventually(t, func() bool {
					for _, e := range serverEvents.Events(qlog.PacketReceived{}) {
						for _, f := range e.(qlog.PacketReceived).Frames {
							if response, ok := f.Frame.(*qlog.PathResponseFrame); ok && response.Data == previousToken {
								return true
							}
						}
					}
					return false
				}, time.Second, time.Millisecond, "a response on another path must complete old-path validation")
			}
			require.NoError(t, s.SendDatagram([]byte("after migration")))
			p, err := c.ReceiveDatagram(ctx)
			require.NoError(t, err)
			require.Equal(t, []byte("after migration"), p)
			t.Logf("previous-path UDP datagram=%d bytes; old dead=%v; new address=%s", len(observed), dead, s.RemoteAddr())
		})
	}
}
