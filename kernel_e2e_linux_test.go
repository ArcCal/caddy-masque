package masque

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ArcCal/caddy-masque/internal/ip"
)

// TestCaddyRealKernelTraffic runs only in a disposable, empty network
// namespace. Real Caddy/TUN/NAT traffic reaches a UDP origin in a second
// namespace; the origin reports the source it sees, verifying both NAT and
// return routing instead of merely checking that firewall rules exist.
func TestCaddyRealKernelTraffic(t *testing.T) {
	if os.Getenv("MASQUE_TEST_KERNEL") != "1" {
		t.Skip("requires explicit opt-in inside an isolated network namespace")
	}
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
	}
	links, err := exec.Command("ip", "-o", "link", "show").Output()
	if err != nil || len(strings.Split(strings.TrimSpace(string(links)), "\n")) != 1 || !strings.Contains(string(links), ": lo:") {
		t.Fatal("requires an empty network namespace with only loopback")
	}
	peer := fmt.Sprintf("mq-origin-%d", os.Getpid())
	run("netns", "add", peer)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", peer).Run() })
	run("link", "set", "lo", "up")
	run("link", "add", "mq-wan", "type", "veth", "peer", "name", "mq-peer")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "mq-wan").Run() })
	run("link", "set", "mq-peer", "netns", peer)
	for _, args := range [][]string{
		{"addr", "add", "198.18.0.1/30", "dev", "mq-wan"},
		{"-6", "addr", "add", "2001:db8:5::1/64", "dev", "mq-wan", "nodad"},
		{"link", "set", "mq-wan", "up"},
		{"route", "add", "192.0.2.80/32", "via", "198.18.0.2"},
		{"-6", "route", "add", "2001:db8:80::80/128", "via", "2001:db8:5::2"},
	} {
		run(args...)
	}
	for _, args := range [][]string{
		{"link", "set", "lo", "up"},
		{"addr", "add", "198.18.0.2/30", "dev", "mq-peer"},
		{"-6", "addr", "add", "2001:db8:5::2/64", "dev", "mq-peer", "nodad"},
		{"addr", "add", "192.0.2.80/32", "dev", "lo"},
		{"-6", "addr", "add", "2001:db8:80::80/128", "dev", "lo", "nodad"},
		{"link", "set", "mq-peer", "up"},
	} {
		run(append([]string{"netns", "exec", peer, "ip"}, args...)...)
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	origin := exec.Command("ip", "netns", "exec", peer, executable,
		"-test.run=^TestKernelUDPOrigin$", "-test.timeout=60s")
	origin.Env = append(os.Environ(), "MASQUE_TEST_ORIGIN=1")
	origin.Stderr = os.Stderr
	out, err := origin.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := origin.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = origin.Process.Kill(); _ = origin.Wait() })
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(out)
		for scanner.Scan() {
			if scanner.Text() == "ORIGIN_READY" {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("origin exited before becoming ready")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("origin did not become ready")
	}

	// Reuse the TLS/HTTP clients, but retain the real device and conntrack
	// implementations for this test. Cleanup stops Caddy before topology removal.
	realOpen, realForget := openDevice, forgetConntrack
	e := newCaddyEnv(t)
	openDevice, forgetConntrack = realOpen, realForget
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	exchange := func(t *testing.T, v4, v6 netip.Addr, send func([]byte) error, recv func() ([]byte, error)) {
		t.Helper()
		for _, family := range []struct {
			local          netip.Addr
			remote, source string
		}{
			{v4, "192.0.2.80", "198.18.0.1"},
			{v6, "2001:db8:80::80", "2001:db8:5::1"},
		} {
			payload := "kernel-nat-" + family.remote
			if err := send(kernelUDPPacket(family.local, netip.MustParseAddr(family.remote), []byte(payload))); err != nil {
				t.Fatal(err)
			}
			type result struct {
				packet []byte
				err    error
			}
			done := make(chan result, 1)
			go func() { p, err := recv(); done <- result{p, err} }()
			select {
			case got := <-done:
				if got.err != nil {
					t.Fatal(got.err)
				}
				h, ok := ip.Parse(got.packet)
				if !ok || h.Protocol != ip.ProtoUDP || h.Src.String() != family.remote || h.Dst != family.local || h.PayloadOffset < 0 || h.TotalLen < h.PayloadOffset+8 {
					t.Fatalf("invalid return routing: %x", got.packet)
				}
				body := string(got.packet[h.PayloadOffset+8 : h.TotalLen])
				if want := family.source + "|" + payload; body != want {
					t.Fatalf("origin saw %q, want %q", body, want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no packet returned through real TUN/NAT")
			}
		}
	}
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			c := tr.dial(e, t, testPassword, anyTarget)
			defer c.close()
			if c.status != tr.ok {
				t.Fatalf("status %d", c.status)
			}
			v4, v6 := opening(t, c)
			exchange(t, v4, v6, c.send, c.recv)
		})
		waitNoSessions(t)
	}
	t.Run("independent connect-ip-go client", func(t *testing.T) {
		conn, _, err := e.dialConnectIPGo(t, testPassword, anyTarget)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		assigned, err := conn.ReceiveAddressAssignment(ctx)
		if err != nil || len(assigned) != 2 {
			t.Fatalf("assignments: %v: %v", assigned, err)
		}
		if _, err := conn.Routes(ctx); err != nil {
			t.Fatal(err)
		}
		exchange(t, assigned[0].IPPrefix.Addr(), assigned[1].IPPrefix.Addr(),
			func(p []byte) error {
				icmp, err := conn.WritePacket(p)
				if err == nil && icmp != nil {
					return fmt.Errorf("client rejected packet: %x", icmp)
				}
				return err
			}, func() ([]byte, error) {
				buf := make([]byte, 65535)
				n, err := readPacket(conn, buf)
				return buf[:n], err
			})
	})
}

// Subprocess origin for TestCaddyRealKernelTraffic. This helper never runs in
// the ordinary suite and uses only documentation addresses in a test namespace.
func TestKernelUDPOrigin(t *testing.T) {
	if os.Getenv("MASQUE_TEST_ORIGIN") != "1" {
		t.Skip("subprocess helper for isolated kernel test")
	}
	for _, endpoint := range []struct{ network, address string }{
		{"udp4", "192.0.2.80:34567"}, {"udp6", "[2001:db8:80::80]:34567"},
	} {
		addr, err := net.ResolveUDPAddr(endpoint.network, endpoint.address)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := net.ListenUDP(endpoint.network, addr)
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			buf := make([]byte, 65535)
			for {
				n, from, err := conn.ReadFromUDP(buf)
				if err != nil {
					return
				}
				_, _ = conn.WriteToUDP(append([]byte(from.IP.String()+"|"), buf[:n]...), from)
			}
		}()
	}
	fmt.Println("ORIGIN_READY")
	select {}
}

func kernelUDPPacket(src, dst netip.Addr, payload []byte) []byte {
	u := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(u[0:2], 42100)
	binary.BigEndian.PutUint16(u[2:4], 34567)
	binary.BigEndian.PutUint16(u[4:6], uint16(len(u)))
	copy(u[8:], payload)
	var pseudo []byte
	if src.Is4() {
		pseudo = append(append(src.AsSlice(), dst.AsSlice()...), 0, ip.ProtoUDP, byte(len(u)>>8), byte(len(u)))
	} else {
		pseudo = make([]byte, 40)
		copy(pseudo[:16], src.AsSlice())
		copy(pseudo[16:32], dst.AsSlice())
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(u)))
		pseudo[39] = ip.ProtoUDP
	}
	checksum := ip.Checksum(pseudo, u)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(u[6:8], checksum)
	return packet(src.String(), dst.String(), ip.ProtoUDP, u)
}
