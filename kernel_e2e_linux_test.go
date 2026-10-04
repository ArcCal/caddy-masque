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
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
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
	exchange := func(t *testing.T, v4, v6 netip.Addr, clientHop int, send func([]byte) error, recv func() ([]byte, error)) {
		t.Helper()
		receive := func() []byte {
			t.Helper()
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
				return got.packet
			case <-time.After(5 * time.Second):
				t.Fatal("no packet returned through real TUN/NAT")
			}
			return nil
		}
		for _, family := range []struct {
			local                   netip.Addr
			remote, source, gateway string
		}{
			{v4, "192.0.2.80", "198.18.0.1", "10.89.0.1"},
			{v6, "2001:db8:80::80", "2001:db8:5::1", "fd89::1"},
		} {
			for _, ttl := range []byte{64, 255} {
				payload := "kernel-nat-" + family.remote
				outgoing := kernelUDPPacket(family.local, netip.MustParseAddr(family.remote), []byte(payload))
				setKernelHopLimit(outgoing, ttl)
				if err := send(outgoing); err != nil {
					t.Fatal(err)
				}
				got := receive()
				h, ok := ip.Parse(got)
				if !ok || h.Protocol != ip.ProtoUDP || h.Src.String() != family.remote || h.Dst != family.local || h.PayloadOffset < 0 || h.TotalLen < h.PayloadOffset+8 {
					t.Fatalf("invalid return routing: %x", got)
				}
				body := string(got[h.PayloadOffset+8 : h.TotalLen])
				if want := fmt.Sprintf("%s|%d|%s", family.source, int(ttl)-1-clientHop, payload); body != want {
					t.Fatalf("origin saw %q, want %q", body, want)
				}
				if gotTTL := kernelHopLimit(got); gotTTL != 63 {
					t.Fatalf("return TTL/Hop Limit=%d, want 63", gotTTL)
				}
				t.Logf("%s: outbound %d -> origin %d; return 64 -> client 63", family.remote, ttl, int(ttl)-1-clientHop)
			}
			// connect-ip-go decrements before writing and rejects TTL=1
			// itself. The raw wire clients let us test the proxy's boundary.
			if clientHop != 0 {
				continue
			}
			expiring := kernelUDPPacket(family.local, netip.MustParseAddr(family.remote), []byte("must-not-arrive"))
			setKernelHopLimit(expiring, 1)
			if err := send(expiring); err != nil {
				t.Fatal(err)
			}
			got := receive()
			h, ok := ip.Parse(got)
			proto, typ := uint8(ip.ProtoICMP), byte(11)
			if family.local.Is6() {
				proto, typ = ip.ProtoICMPv6, 3
			}
			if !ok || h.Dst != family.local || h.Protocol != proto || h.PayloadOffset < 0 || h.TotalLen < h.PayloadOffset+8 || got[h.PayloadOffset] != typ || got[h.PayloadOffset+1] != 0 {
				t.Fatalf("missing ICMP Time Exceeded for hop=1: %x", got)
			}
			quoted, ok := ip.Parse(got[h.PayloadOffset+8 : h.TotalLen])
			if !ok || quoted.Src != family.local || quoted.Dst.String() != family.remote {
				t.Fatalf("invalid ICMP quotation: %x", got)
			}
			// TTL=1 is valid for a local destination. Locally generated
			// replies must not acquire a forwarding decrement.
			echo := kernelEchoRequest(family.local, netip.MustParseAddr(family.gateway))
			setKernelHopLimit(echo, 1)
			if err := send(echo); err != nil {
				t.Fatal(err)
			}
			got = receive()
			h, ok = ip.Parse(got)
			replyType := byte(0)
			if family.local.Is6() {
				replyType = ip.EchoReplyV6
			}
			if !ok || h.Dst != family.local || h.Src.String() != family.gateway || h.Protocol != proto || h.PayloadOffset < 0 || h.TotalLen < h.PayloadOffset+8 || got[h.PayloadOffset] != replyType || kernelHopLimit(got) != 64 {
				t.Fatalf("local echo with hop=1 failed or was decremented: %x", got)
			}
			t.Logf("%s: hop=1 forwarded packet returned ICMP Time Exceeded; local echo reply kept hop=64", family.remote)
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
			exchange(t, v4, v6, 0, c.send, c.recv)
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
		exchange(t, assigned[0].IPPrefix.Addr(), assigned[1].IPPrefix.Addr(), 1,
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
		var read func([]byte) (int, int, net.Addr, error)
		var write func([]byte, net.Addr) (int, error)
		if endpoint.network == "udp4" {
			pc := ipv4.NewPacketConn(conn)
			if err := pc.SetControlMessage(ipv4.FlagTTL, true); err != nil {
				t.Fatal(err)
			}
			if err := pc.SetTTL(64); err != nil {
				t.Fatal(err)
			}
			read = func(b []byte) (int, int, net.Addr, error) {
				n, cm, from, err := pc.ReadFrom(b)
				if cm == nil {
					return n, 0, from, fmt.Errorf("missing IPv4 TTL: %w", err)
				}
				return n, cm.TTL, from, err
			}
			write = func(b []byte, to net.Addr) (int, error) { return pc.WriteTo(b, nil, to) }
		} else {
			pc := ipv6.NewPacketConn(conn)
			if err := pc.SetControlMessage(ipv6.FlagHopLimit, true); err != nil {
				t.Fatal(err)
			}
			if err := pc.SetHopLimit(64); err != nil {
				t.Fatal(err)
			}
			read = func(b []byte) (int, int, net.Addr, error) {
				n, cm, from, err := pc.ReadFrom(b)
				if cm == nil {
					return n, 0, from, fmt.Errorf("missing IPv6 Hop Limit: %w", err)
				}
				return n, cm.HopLimit, from, err
			}
			write = func(b []byte, to net.Addr) (int, error) { return pc.WriteTo(b, nil, to) }
		}
		go func() {
			buf := make([]byte, 65535)
			for {
				n, ttl, from, err := read(buf)
				if err != nil {
					return
				}
				_, _ = write(append([]byte(fmt.Sprintf("%s|%d|", from.(*net.UDPAddr).IP, ttl)), buf[:n]...), from)
			}
		}()
	}
	fmt.Println("ORIGIN_READY")
	select {}
}

func kernelHopLimit(p []byte) byte {
	if p[0]>>4 == 4 {
		return p[8]
	}
	return p[7]
}

func setKernelHopLimit(p []byte, ttl byte) {
	if p[0]>>4 == 4 {
		p[8], p[10], p[11] = ttl, 0, 0
		binary.BigEndian.PutUint16(p[10:12], ip.Checksum(p[:20]))
	} else {
		p[7] = ttl
	}
}

func kernelEchoRequest(src, dst netip.Addr) []byte {
	if src.Is6() {
		return ip.EchoV6(ip.EchoRequestV6, src, dst, 123, 1, []byte("local-hop-one"))
	}
	body := []byte{8, 0, 0, 0, 0, 123, 0, 1}
	body = append(body, []byte("local-hop-one")...)
	binary.BigEndian.PutUint16(body[2:4], ip.Checksum(body))
	return packet(src.String(), dst.String(), ip.ProtoICMP, body)
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
