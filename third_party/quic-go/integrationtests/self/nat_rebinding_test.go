package self_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	quicproxy "github.com/quic-go/quic-go/integrationtests/tools/proxy"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/require"
)

func TestNATRebinding(t *testing.T) {
	tr, tracer := newPacketTracer()
	tlsConf := getTLSConfig()
	f, err := os.CreateTemp(t.TempDir(), "keylog-")
	require.NoError(t, err)
	defer f.Close()
	tlsConf.KeyLogWriter = f
	server, err := quic.Listen(
		newUDPConnLocalhost(t),
		tlsConf,
		getQuicConfig(&quic.Config{
			Tracer: func(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace { return tracer },
		}),
	)
	require.NoError(t, err)
	defer server.Close()

	newPath := newUDPConnLocalhost(t)
	clientUDPConn := newUDPConnLocalhost(t)

	oldPathRTT := scaleDuration(10 * time.Millisecond)
	newPathRTT := scaleDuration(20 * time.Millisecond)
	proxy := quicproxy.Proxy{
		ServerAddr: server.Addr().(*net.UDPAddr),
		Conn:       newUDPConnLocalhost(t),
	}
	var mx sync.Mutex
	var switchedPath bool
	var dataTransferred int
	proxy.DelayPacket = func(dir quicproxy.Direction, _, _ net.Addr, b []byte) time.Duration {
		mx.Lock()
		defer mx.Unlock()

		if dir == quicproxy.DirectionOutgoing {
			dataTransferred += len(b)
			if dataTransferred > len(PRData)/3 {
				if !switchedPath {
					if err := proxy.SwitchConn(clientUDPConn.LocalAddr().(*net.UDPAddr), newPath); err != nil {
						panic(fmt.Sprintf("failed to switch connection: %s", err))
					}
					switchedPath = true
				}
			}
		}
		if switchedPath {
			return newPathRTT
		}
		return oldPathRTT
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, clientUDPConn, proxy.LocalAddr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)

	serverConn, err := server.Accept(ctx)
	require.NoError(t, err)
	defer serverConn.CloseWithError(0, "")

	go func() {
		str, err := serverConn.OpenUniStream()
		require.NoError(t, err)
		go func() {
			defer str.Close()
			_, err = str.Write(PRData)
			require.NoError(t, err)
		}()
	}()

	str, err := conn.AcceptUniStream(ctx)
	require.NoError(t, err)
	str.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, err := io.ReadAll(str)
	require.NoError(t, err)
	require.Equal(t, PRData, data)
	conn.CloseWithError(0, "")

	// check that a PATH_CHALLENGE was sent
	var pathChallenges [][8]byte
	for _, p := range tr.getSentShortHeaderPackets() {
		for _, f := range p.frames {
			switch fr := f.Frame.(type) {
			case *qlog.PathChallengeFrame:
				pathChallenges = append(pathChallenges, fr.Data)
			}
		}
	}
	require.NotEmpty(t, pathChallenges)

	// check that a PATH_RESPONSE with the correct data was received
	var foundPathResponse bool
	for _, p := range tr.getRcvdShortHeaderPackets() {
		for _, f := range p.frames {
			switch fr := f.Frame.(type) {
			case *qlog.PathResponseFrame:
				// A small first probe is followed by a distinct full-size MTU
				// probe. Every response must match a challenge actually sent.
				require.Contains(t, pathChallenges, fr.Data)
				foundPathResponse = true
			}
		}
	}
	require.True(t, foundPathResponse)
}

func TestNATRebindingAmplificationLimit(t *testing.T) {
	server, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(&quic.Config{EnableDatagrams: true, DisablePathMTUDiscovery: true}))
	require.NoError(t, err)
	defer server.Close()
	newPath := newUDPConnLocalhost(t)
	clientUDPConn := newUDPConnLocalhost(t)
	var armed atomic.Bool
	var incoming atomic.Int64
	firstReply := make(chan int, 10)
	proxy := quicproxy.Proxy{
		ServerAddr: server.Addr().(*net.UDPAddr),
		Conn:       newUDPConnLocalhost(t),
		DropPacket: func(dir quicproxy.Direction, _, _ net.Addr, b []byte) bool {
			if !armed.Load() {
				return false
			}
			if dir == quicproxy.DirectionIncoming {
				// Forward just one authentic client packet on the fresh path.
				return !incoming.CompareAndSwap(0, int64(len(b)))
			}
			select {
			case firstReply <- len(b):
			default:
			}
			// Keep the client from validating / authorizing any further traffic.
			return true
		},
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, clientUDPConn, proxy.LocalAddr(), getTLSClientConfig(), getQuicConfig(&quic.Config{EnableDatagrams: true, DisablePathMTUDiscovery: true}))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	sconn, err := server.Accept(ctx)
	require.NoError(t, err)
	defer sconn.CloseWithError(0, "")
	require.NoError(t, conn.SendDatagram([]byte("settle")))
	_, err = sconn.ReceiveDatagram(ctx)
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond) // drain handshake ACKs and NEW_CONNECTION_IDs
	require.NoError(t, proxy.SwitchConn(clientUDPConn.LocalAddr().(*net.UDPAddr), newPath))
	armed.Store(true)
	require.NoError(t, conn.SendDatagram([]byte{1}))
	select {
	case sent := <-firstReply:
		received := incoming.Load()
		require.Greater(t, received, int64(0))
		t.Logf("fresh-path received UDP bytes=%d, server first reply UDP bytes=%d, allowed=%d", received, sent, 3*received)
		require.LessOrEqual(t, int64(sent), 3*received, "new unvalidated path exceeds the three-times received byte limit")
	case <-ctx.Done():
		t.Fatal("no fresh-path reply observed")
	}
}

func TestPathValidationOnCurrentPath(t *testing.T) {
	server, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}))
	require.NoError(t, err)
	defer server.Close()
	tr := &quic.Transport{Conn: newUDPConnLocalhost(t)}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := tr.Dial(ctx, server.Addr(), getTLSClientConfig(), getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	sconn, err := server.Accept(ctx)
	require.NoError(t, err)
	defer sconn.CloseWithError(0, "")
	time.Sleep(50 * time.Millisecond)
	path, err := conn.AddPath(tr)
	require.NoError(t, err)
	defer path.Close()
	err = path.Probe(ctx)
	require.NoError(t, err, "RFC9000 section8.2.2 requires a PATH_RESPONSE on the current path")
}

func TestNATRebindingCrossPathResponse(t *testing.T) {
	for _, size := range []int{1, 1000} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			server, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), getQuicConfig(&quic.Config{
				EnableDatagrams: true, DisablePathMTUDiscovery: true,
			}))
			require.NoError(t, err)
			defer server.Close()
			front, oldPath, newPath := newUDPConnLocalhost(t), newUDPConnLocalhost(t), newUDPConnLocalhost(t)
			defer front.Close()
			defer oldPath.Close()
			defer newPath.Close()
			clientUDP := newUDPConnLocalhost(t)
			clientAddr := clientUDP.LocalAddr().(*net.UDPAddr)
			serverAddr := server.Addr().(*net.UDPAddr)
			// Initially use the old path; stage 1 forwards exactly one packet on
			// the new path, stage 2 routes every PATH_RESPONSE over the old one.
			var stage atomic.Int32
			var newReceived atomic.Int64
			newReplies := make(chan int, 32)
			go func() {
				buf := make([]byte, 65536)
				for {
					n, _, err := front.ReadFromUDP(buf)
					if err != nil {
						return
					}
					socket := oldPath
					if stage.CompareAndSwap(1, 2) || stage.Load() == 3 {
						socket = newPath
						newReceived.Add(int64(n))
					}
					if _, err := socket.WriteToUDP(buf[:n], serverAddr); err != nil {
						return
					}
				}
			}()
			for _, socket := range []*net.UDPConn{oldPath, newPath} {
				go func(socket *net.UDPConn) {
					buf := make([]byte, 65536)
					for {
						n, _, err := socket.ReadFromUDP(buf)
						if err != nil {
							return
						}
						if socket == newPath {
							select {
							case newReplies <- n:
							default:
							}
						}
						if _, err := front.WriteToUDP(buf[:n], clientAddr); err != nil {
							return
						}
					}
				}(socket)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			client, err := quic.Dial(ctx, clientUDP, front.LocalAddr(), getTLSClientConfig(), getQuicConfig(&quic.Config{
				EnableDatagrams: true, DisablePathMTUDiscovery: true,
			}))
			require.NoError(t, err)
			defer client.CloseWithError(0, "")
			peer, err := server.Accept(ctx)
			require.NoError(t, err)
			defer peer.CloseWithError(0, "")
			require.NoError(t, client.SendDatagram([]byte("settle")))
			_, err = peer.ReceiveDatagram(ctx)
			require.NoError(t, err)
			time.Sleep(100 * time.Millisecond)
			stage.Store(1)
			require.NoError(t, client.SendDatagram(make([]byte, size)))
			got, err := peer.ReceiveDatagram(ctx)
			require.NoError(t, err)
			require.Len(t, got, size)
			select {
			case n := <-newReplies:
				require.LessOrEqual(t, int64(n), 3*newReceived.Load())
				if size == 1 {
					require.Less(t, n, 1200)
				} else {
					require.Equal(t, 1200, n)
				}
			case <-ctx.Done():
				t.Fatal("no path challenge on new path")
			}
			if size == 1 {
				select {
				case n := <-newReplies:
					require.Equal(t, 1200, n, "cross-path response must trigger a full-size probe on the original challenged path")
				case <-ctx.Done():
					t.Fatal("no full-size MTU revalidation after the response arrived on the old path")
				}
			}
			// Both address and MTU validation replies travel over the old path.
			// A later non-probing packet on the new path must still migrate.
			time.Sleep(50 * time.Millisecond)
			stage.Store(3)
			require.NoError(t, client.SendDatagram([]byte("after migration")))
			got, err = peer.ReceiveDatagram(ctx)
			require.NoError(t, err)
			require.Equal(t, []byte("after migration"), got)
			require.Eventually(t, func() bool { return peer.RemoteAddr().String() == newPath.LocalAddr().String() }, time.Second, time.Millisecond)
			require.NoError(t, peer.SendDatagram([]byte("return traffic")))
			got, err = client.ReceiveDatagram(ctx)
			require.NoError(t, err)
			require.Equal(t, []byte("return traffic"), got)
		})
	}
}

// Probing the new path after a NAT rebinding uses one of the client's connection IDs.
// Unless the server retires the old connection ID when switching to the new path,
// it runs out of connection IDs after a few rebindings, and can't switch paths anymore, see
// https://github.com/quic-go/quic-go/issues/5965.
func TestNATRebindingRepeated(t *testing.T) {
	var serverEvents events.Recorder
	server, err := quic.Listen(
		newUDPConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{Tracer: newTracer(&serverEvents)}),
	)
	require.NoError(t, err)
	defer server.Close()

	clientUDPConn := newUDPConnLocalhost(t)
	proxy := quicproxy.Proxy{
		ServerAddr: server.Addr().(*net.UDPAddr),
		Conn:       newUDPConnLocalhost(t),
	}
	require.NoError(t, proxy.Start())
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// unlike quic.Dial, the Transport uses non-zero-length connection IDs
	tr := &quic.Transport{Conn: clientUDPConn, ConnectionIDLength: 8}
	defer tr.Close()
	conn, err := tr.Dial(ctx, proxy.LocalAddr(), getTLSClientConfig(), getQuicConfig(nil))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")
	sconn, err := server.Accept(ctx)
	require.NoError(t, err)
	defer sconn.CloseWithError(0, "")
	go func() {
		for {
			str, err := sconn.AcceptStream(context.Background())
			if err != nil {
				return
			}
			go func() {
				defer str.Close()
				io.Copy(str, str)
			}()
		}
	}()

	// rebind more often than the client provides connection IDs at any given time
	for range 8 {
		require.NoError(t, proxy.SwitchConn(clientUDPConn.LocalAddr().(*net.UDPAddr), newUDPConnLocalhost(t)))
		// The server sends to the old address until it switches to the new path,
		// so receiving the echo means that it switched.
		str, err := conn.OpenStream()
		require.NoError(t, err)
		str.SetDeadline(time.Now().Add(scaleDuration(2 * time.Second)))
		_, err = str.Write([]byte("foobar"))
		require.NoError(t, err)
		require.NoError(t, str.Close())
		data, err := io.ReadAll(str)
		require.NoError(t, err)
		require.Equal(t, []byte("foobar"), data)
	}
	requireConnIDsNotLinkable(t, serverEvents.Events())
}
