package hostnet

import (
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Run only in a disposable network namespace, never in a production host:
// sudo unshare --net env MASQUE_TEST_HOSTNET=1 ./hostnet.test -test.run TestHostNetworkLifecycle
func TestHostNetworkLifecycle(t *testing.T) {
	if os.Getenv("MASQUE_TEST_HOSTNET") != "1" {
		t.Skip("requires explicit opt-in inside an isolated network namespace")
	}
	for _, command := range []string{"ip", "nft"} {
		if _, err := exec.LookPath(command); err != nil {
			t.Fatal(err)
		}
	}
	// An empty namespace is the precondition: refuse to touch a host with
	// interfaces other than loopback or an existing module firewall table.
	links, err := exec.Command("ip", "-o", "link", "show").Output()
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(string(links)), "\n"); len(lines) != 1 || !strings.Contains(lines[0], ": lo:") {
		t.Fatal("not an empty network namespace")
	}
	if exec.Command("nft", "list", "table", "inet", NFTTable).Run() == nil {
		t.Fatal("existing module firewall table")
	}
	readSysctl := func(key string) string {
		t.Helper()
		b, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(key, ".", "/"))
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}
	keys := []string{"net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"}
	before := []string{readSysctl(keys[0]), readSysctl(keys[1])}
	n, err := Open(Config{Interface: "mq-test", IPv4: netip.MustParsePrefix("10.89.0.1/29"), IPv6: netip.MustParsePrefix("fd89::1/64"), MTU: 1400, Manage: true})
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = n.Close()
		}
	}()
	for _, key := range keys {
		if got := readSysctl(key); got != "1" {
			t.Fatalf("%s = %s", key, got)
		}
	}
	if out, err := exec.Command("ip", "-o", "addr", "show", "dev", n.Name()).CombinedOutput(); err != nil || !strings.Contains(string(out), "10.89.0.1/29") || !strings.Contains(string(out), "fd89::1/64") {
		t.Fatalf("tunnel addresses: %s (%v)", out, err)
	}
	if err := run(nil, "nft", "delete", "table", "inet", NFTTable); err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if err := SetSysctl(key, "0"); err != nil {
			t.Fatal(err)
		}
	}
	if repairs := n.Repair(); len(repairs) != 3 {
		t.Fatalf("expected firewall and both forwarding repairs, got %v", repairs)
	}
	if out, err := exec.Command("nft", "list", "table", "inet", NFTTable).CombinedOutput(); err != nil || !strings.Contains(string(out), "masquerade") || !strings.Contains(string(out), "chain input") {
		t.Fatalf("repaired rules: %s (%v)", out, err)
	}
	// A TUN reader must finish when the device is closed. IPv6 setup can
	// enqueue router solicitations, so drain packets until Read fails rather
	// than assuming that its first result was blocked before Close.
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 65535)
		for {
			if _, err := n.Read(buf); err != nil {
				done <- err
				return
			}
		}
	}()
	if err := n.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed TUN read succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TUN reader blocked after close")
	}
	if exec.Command("ip", "link", "show", "dev", "mq-test").Run() == nil {
		t.Error("TUN device survived close")
	}
	if exec.Command("nft", "list", "table", "inet", NFTTable).Run() == nil {
		t.Error("firewall table survived close")
	}
	for i, key := range keys {
		if got := readSysctl(key); got != before[i] {
			t.Errorf("%s = %s after close, want %s", key, got, before[i])
		}
	}
}
