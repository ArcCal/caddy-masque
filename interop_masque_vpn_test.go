package masque

// Exercise an unmodified masque-vpn executable, including its TLS, HTTP
// transports, capsule parser and userspace IP stack. The server's TUN is
// simulated; privileged kernel forwarding is checked by the separate CI tests.

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArcCal/caddy-masque/internal/ip"
)

func TestInteropMasqueVPNClient(t *testing.T) {
	clientBinary := os.Getenv("MASQUE_TEST_CLIENT")
	if clientBinary == "" {
		t.Skip("set MASQUE_TEST_CLIENT to the unmodified masque-client executable")
	}
	for _, transport := range []string{"h3", "h2", "http/1.1"} {
		for _, ipv6 := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/ipv6=%v", transport, ipv6), func(t *testing.T) {
				e := newCaddyEnv(t)
				if err := e.load(masqueConfig("alice")); err != nil {
					t.Fatal(err)
				}
				ca := filepath.Join(t.TempDir(), "ca.pem")
				if err := os.WriteFile(ca, []byte(e.cert.caPEM), 0600); err != nil {
					t.Fatal(err)
				}
				port := freePort(t)
				config := fmt.Sprintf(`uri_template = "https://127.0.0.1:%d/.well-known/masque/ip/{target}/{ipproto}/"
username = "alice"
password = %q
server_name = "vpn.test"
ca = %q
transport = %q
mode = "socks"
ipv6 = %v
dns = ["1.1.1.1"]
[socks]
listen = ["127.0.0.1:%d"]
`, e.port, testPassword, ca, transport, ipv6, port)
				logPath := filepath.Join(t.TempDir(), "client.log")
				log, err := os.Create(logPath)
				if err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(clientBinary, "-c", "-")
				cmd.Env = append(os.Environ(), "RUST_LOG=info")
				cmd.Stdin = strings.NewReader(config)
				cmd.Stdout, cmd.Stderr = log, log
				if err := cmd.Start(); err != nil {
					log.Close()
					t.Fatal(err)
				}
				ended := make(chan error, 1)
				go func() { ended <- cmd.Wait() }()
				t.Cleanup(func() {
					_ = cmd.Process.Signal(syscall.SIGTERM)
					select {
					case <-ended:
					case <-time.After(3 * time.Second):
						_ = cmd.Process.Kill()
						<-ended
					}
					log.Close()
					if t.Failed() {
						b, _ := os.ReadFile(logPath)
						t.Logf("masque-client: %s", b)
					}
				})
				var control net.Conn
				deadline := time.Now().Add(10 * time.Second)
				for time.Now().Before(deadline) {
					control, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
					if err == nil {
						break
					}
					time.Sleep(25 * time.Millisecond)
				}
				if err != nil {
					t.Fatalf("client SOCKS listener: %v", err)
				}
				defer control.Close()
				_ = control.SetDeadline(time.Now().Add(5 * time.Second))
				if _, err := control.Write([]byte{5, 1, 0}); err != nil {
					t.Fatal(err)
				}
				greeting := make([]byte, 2)
				if _, err := io.ReadFull(control, greeting); err != nil || !slices.Equal(greeting, []byte{5, 0}) {
					t.Fatalf("SOCKS greeting: %x, %v", greeting, err)
				}
				// RFC 1928 UDP ASSOCIATE: the connection stays open throughout.
				if _, err := control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
					t.Fatal(err)
				}
				response := make([]byte, 10)
				if _, err := io.ReadFull(control, response); err != nil || !slices.Equal(response[:4], []byte{5, 0, 0, 1}) {
					t.Fatalf("UDP ASSOCIATE: %x, %v", response, err)
				}
				relay := &net.UDPAddr{IP: net.IP(response[4:8]), Port: int(binary.BigEndian.Uint16(response[8:10]))}
				udpConn, err := net.DialUDP("udp4", nil, relay)
				if err != nil {
					t.Fatal(err)
				}
				defer udpConn.Close()
				echo := func(remote string) {
					t.Helper()
					addr := netip.MustParseAddr(remote)
					request := []byte{0, 0, 0, 1}
					if addr.Is6() {
						request[3] = 4
					}
					request = append(request, addr.AsSlice()...)
					request = append(request, 0, 7) // synthetic UDP echo, no Internet dependency
					payload := []byte("real masque-vpn client interoperability")
					request = append(request, payload...)
					if _, err := udpConn.Write(request); err != nil {
						t.Fatal(err)
					}
					got := hostPacket(t, e.dev)
					h, ok := ip.Parse(got)
					if !ok || h.Dst != addr || h.Protocol != ip.ProtoUDP {
						t.Fatalf("outgoing IP packet: %x", got)
					}
					head := 20
					pool := netip.MustParsePrefix("10.89.0.0/24")
					if addr.Is6() {
						head, pool = 40, netip.MustParsePrefix("fd89::/64")
					}
					if !pool.Contains(h.Src) || len(got) != head+8+len(payload) || binary.BigEndian.Uint16(got[head+2:head+4]) != 7 || !slices.Equal(got[head+8:], payload) {
						t.Fatalf("outgoing UDP packet: %x", got)
					}
					udp := make([]byte, 8+len(payload))
					binary.BigEndian.PutUint16(udp[:2], 7)
					copy(udp[2:4], got[head:head+2])
					binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
					copy(udp[8:], payload)
					pseudo := append(slices.Clone(addr.AsSlice()), h.Src.AsSlice()...)
					if addr.Is4() {
						pseudo = append(pseudo, 0, ip.ProtoUDP, byte(len(udp)>>8), byte(len(udp)))
					} else {
						pseudo = append(pseudo, 0, 0, byte(len(udp)>>8), byte(len(udp)), 0, 0, 0, ip.ProtoUDP)
					}
					checksum := ip.Checksum(pseudo, udp)
					if checksum == 0 {
						checksum = 0xffff
					}
					binary.BigEndian.PutUint16(udp[6:8], checksum)
					e.dev.fromHost <- packet(remote, h.Src.String(), ip.ProtoUDP, udp)
					_ = udpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
					buf := make([]byte, 1500)
					n, err := udpConn.Read(buf)
					if err != nil || !slices.Equal(buf[:n], request) {
						t.Fatalf("SOCKS UDP reply: %x, %v", buf[:n], err)
					}
				}
				echo("1.1.1.1")
				if ipv6 {
					echo("2606:4700::1111")
				}
				if transport == "h3" && !ipv6 {
					// The server still assigns IPv6. A client which disables its
					// use must answer the 1280-byte MTU probe for that address.
					time.Sleep(probeTimeout + time.Second)
					echo("1.1.1.1")
				}
			})
		}
	}
}
