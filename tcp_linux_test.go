package masque

import (
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Tunnels over HTTP/1.1 and HTTP/2 get the TCP settings that notice a
// vanished client within about 30 seconds, through Caddy's listeners.
func TestTunnelsOverTCPGetShortTimeouts(t *testing.T) {
	var mu sync.Mutex
	var tuned []net.Conn
	old := tuneTunnelConn
	tuneTunnelConn = func(c net.Conn) error {
		err := old(c)
		if err != nil {
			t.Errorf("tuning %T: %v", c, err)
		}
		mu.Lock()
		tuned = append(tuned, c)
		mu.Unlock()
		return err
	}
	t.Cleanup(func() { tuneTunnelConn = old })
	e := newCaddyEnv(t)
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	for _, tr := range transports[1:] {
		t.Run(tr.name, func(t *testing.T) {
			mu.Lock()
			tuned = nil
			mu.Unlock()
			c := tr.dial(e, t, testPassword, anyTarget)
			defer c.close()
			if c.status != tr.ok {
				t.Fatal(c.status)
			}
			var conn net.Conn
			waitFor := time.Now().Add(5 * time.Second)
			for conn == nil {
				if time.Now().After(waitFor) {
					t.Fatal("tunnel connection not tuned")
				}
				mu.Lock()
				if len(tuned) > 0 {
					conn = tuned[0]
				}
				mu.Unlock()
				time.Sleep(time.Millisecond)
			}
			tc, ok := tcpConnOf(conn)
			if !ok {
				t.Fatalf("%T", conn)
			}
			raw, err := tc.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			for name, opt := range map[string]struct {
				level, opt, want int
			}{
				"SO_KEEPALIVE":     {unix.SOL_SOCKET, unix.SO_KEEPALIVE, 1},
				"TCP_KEEPIDLE":     {unix.IPPROTO_TCP, unix.TCP_KEEPIDLE, 10},
				"TCP_KEEPINTVL":    {unix.IPPROTO_TCP, unix.TCP_KEEPINTVL, 5},
				"TCP_KEEPCNT":      {unix.IPPROTO_TCP, unix.TCP_KEEPCNT, 4},
				"TCP_USER_TIMEOUT": {unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, 30000},
			} {
				var got int
				var gerr error
				if err := raw.Control(func(fd uintptr) { got, gerr = unix.GetsockoptInt(int(fd), opt.level, opt.opt) }); err != nil || gerr != nil {
					t.Fatal(name, err, gerr)
				}
				if got != opt.want {
					t.Errorf("%s = %d, want %d", name, got, opt.want)
				}
			}
		})
	}
	waitNoSessions(t)
}
