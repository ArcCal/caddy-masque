package masque

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap/zaptest"

	"github.com/ArcCal/caddy-masque/internal/hostnet"
)

// Signal handling exits the process, so exercise it in a separate test process.
func TestSeriousLifecycleGracefulExit(t *testing.T) {
	for _, mode := range []string{"fresh-h2", "reload-h2", "handler-removed-h2", "empty-http-h2", "caddy-h3-capsules"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSeriousLifecycleExitHelper$", "-test.v")
			root := t.TempDir()
			cmd.Env = append(os.Environ(), "CADDY_MASQUE_LIFECYCLE_EXIT_MODE="+mode,
				"TMPDIR="+root, "XDG_CONFIG_HOME="+root, "XDG_DATA_HOME="+root)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("graceful exit for %s failed: %v\n%s", mode, err, out)
			}
			t.Logf("graceful exit for %s completed", mode)
		})
	}
}

func TestSeriousLifecycleExitHelper(t *testing.T) {
	mode := os.Getenv("CADDY_MASQUE_LIFECYCLE_EXIT_MODE")
	if mode == "" {
		t.Skip("subprocess helper")
	}
	caddy.TrapSignals()
	e := newCaddyEnv(t)
	cfg := masqueConfig("alice")
	if mode == "caddy-h3-capsules" {
		cfg["http3"] = false
	}
	if err := e.load(cfg); err != nil {
		t.Fatal(err)
	}
	var client *tunnelClient
	if mode == "caddy-h3-capsules" {
		client = seriousLifecycleCapsuleH3(t, e)
	} else {
		client = e.dialH2(t, testPassword, anyTarget)
	}
	if client.status != http.StatusOK {
		t.Fatalf("tunnel status %d", client.status)
	}
	v4, _ := opening(t, client)
	if mode == "caddy-h3-capsules" {
		// A normal H3 client closes its connection after the server finishes
		// its last request; quic-go's graceful shutdown waits for that close.
		go func() {
			for {
				if _, err := client.capsule(); err != nil {
					client.close()
					return
				}
			}
		}()
	}
	if mode == "reload-h2" || mode == "handler-removed-h2" || mode == "empty-http-h2" {
		reloaded := e.config(cfg)
		if mode != "reload-h2" {
			var config map[string]any
			if err := json.Unmarshal(reloaded, &config); err != nil {
				t.Fatal(err)
			}
			servers := config["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
			if mode == "empty-http-h2" {
				delete(servers, "vpn")
			} else {
				servers["vpn"].(map[string]any)["routes"] = []any{map[string]any{"handle": []any{map[string]any{"handler": "static_response", "body": "cover page"}}}}
			}
			var err error
			reloaded, err = json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := caddy.Load(reloaded, true); err != nil {
			t.Fatal(err)
		}
		// Complete an ordinary packet exchange after reload before exiting.
		e.dev.fromHost <- udp("1.1.1.1", v4.String(), 10)
		if _, err := client.recv(); err != nil {
			t.Fatalf("preserved tunnel failed after reload: %v", err)
		}
		// Ensure the old server's asynchronous shutdown callback has run.
		time.Sleep(100 * time.Millisecond)
	}
	go func() {
		time.Sleep(5 * time.Second)
		stack := make([]byte, 1<<20)
		n := runtime.Stack(stack, true)
		_, _ = fmt.Fprintf(os.Stderr, "graceful exit exceeded five seconds for %s\n%s", mode, stack[:n])
		os.Exit(73)
	}()
	process, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	// The server must finish its normal shutdown while the client stays open.
	select {}
}

func TestSeriousLifecycleCanceledCoreRejectsLease(t *testing.T) {
	e := newTestEnv(t, dualStack())
	e.core.cancel()
	if l := e.core.acquire(context.Background(), alice, true, false); l != nil {
		l.release()
		t.Fatal("a stopped core accepted a new session")
	}
}

func TestSeriousLifecycleShutdownRejectsDelayedLease(t *testing.T) {
	e := newTestEnv(t, &App{IPv4: "10.89.0.1/30"})
	first := e.core.acquire(context.Background(), alice, true, false)
	if first == nil {
		t.Fatal("no initial lease")
	}
	first.release()
	started, proceed := make(chan struct{}), make(chan struct{})
	e.core.forget = func([]netip.Prefix) (int, error) {
		close(started)
		<-proceed
		return 0, nil
	}
	result := make(chan *lease, 1)
	go func() { result <- e.core.acquire(context.Background(), bob, true, false) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		close(proceed)
		t.Fatal("acquisition did not reach connection-tracking cleanup")
	}
	e.core.cancel()
	e.core.revokeAll("server shutting down")
	close(proceed)
	select {
	case l := <-result:
		if l != nil {
			l.release()
			t.Error("an in-flight request registered a session after shutdown")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("acquisition did not finish")
	}
}

func TestSeriousLifecycleInterfaceChangeNeedsRestart(t *testing.T) {
	e := newCaddyEnv(t)
	oldOpen := openDevice
	opens := 0
	openDevice = func(cfg hostnet.Config) (device, error) {
		opens++
		return oldOpen(cfg)
	}
	t.Cleanup(func() { openDevice = oldOpen })
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	client := e.dialH2(t, testPassword, anyTarget)
	defer client.close()
	v4, _ := opening(t, client)
	cfg := masqueConfig("alice")
	cfg["interface"] = "other0"
	err := e.load(cfg)
	if err == nil || !strings.Contains(err.Error(), "restart") {
		t.Errorf("interface change: %v, want restart requirement", err)
	}
	if opens != 1 {
		t.Errorf("opened %d networks; rejected reload must not open another", opens)
	}
	if err == nil {
		return
	}
	e.dev.fromHost <- udp("1.1.1.1", v4.String(), 10)
	if _, err := client.recv(); err != nil {
		t.Fatalf("existing tunnel failed after rejected interface change: %v", err)
	}
	client.close()
	if err := caddy.Stop(); err != nil {
		t.Fatal(err)
	}
	// A genuine stop releases the shared core; the changed interface may
	// then start with a fresh device rather than sharing the old one.
	e.dev = newFakeDevice()
	if err := e.load(cfg); err != nil {
		t.Fatalf("interface change after stopping: %v", err)
	}
	if opens != 2 {
		t.Errorf("opened %d networks after restart, want 2", opens)
	}
}

func seriousLifecycleCapsuleH3(t *testing.T, e *caddyEnv) *tunnelClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, fmt.Sprintf("127.0.0.1:%d", e.port), http3.ConfigureTLSConfig(e.tlsConfig("h3")), &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	cc := (&http3.Transport{}).NewClientConn(conn)
	select {
	case <-cc.ReceivedSettings():
	case <-ctx.Done():
		t.Fatal("no HTTP/3 SETTINGS")
	}
	str, err := cc.OpenRequestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(e.url(anyTarget))
	req := &http.Request{Method: http.MethodConnect, Proto: "connect-ip", Host: u.Host, URL: u,
		Header: http.Header{"Capsule-Protocol": {"?1"}, "Authorization": {authorization(testPassword)}}}
	if err := str.SendRequestHeader(req); err != nil {
		t.Fatal(err)
	}
	resp, err := str.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	client := &tunnelClient{status: resp.StatusCode, close: func() { conn.CloseWithError(0, "") }}
	streamClient(client, str, str)
	return client
}

type seriousLifecycleRepairDevice struct {
	*fakeDevice
	started       chan struct{}
	releaseRepair chan struct{}
	finished      chan struct{}
	closed        atomic.Bool
	postClose     atomic.Bool
	once          sync.Once
}

func (d *seriousLifecycleRepairDevice) Repair() []string {
	d.once.Do(func() { close(d.started) })
	<-d.releaseRepair
	if d.closed.Load() {
		d.postClose.Store(true)
	}
	close(d.finished)
	return nil
}

func (d *seriousLifecycleRepairDevice) Close() error {
	d.closed.Store(true)
	return d.fakeDevice.Close()
}

func TestSeriousLifecycleShutdownWaitsForRepair(t *testing.T) {
	app := dualStack()
	if err := app.parse(); err != nil {
		t.Fatal(err)
	}
	c, err := newCore(app.cfg, zaptest.NewLogger(t))
	if err != nil {
		t.Fatal(err)
	}
	d := &seriousLifecycleRepairDevice{fakeDevice: newFakeDevice(), started: make(chan struct{}), releaseRepair: make(chan struct{}), finished: make(chan struct{})}
	oldOpen := openDevice
	openDevice = func(hostnet.Config) (device, error) { return d, nil }
	defer func() { openDevice = oldOpen }()
	c.forget = func([]netip.Prefix) (int, error) { return 0, nil }
	if err := c.start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-d.started:
	case <-time.After(hostCheckInterval + 3*time.Second):
		close(d.releaseRepair)
		_ = c.Destruct()
		t.Fatal("repair did not start")
	}
	destructed := make(chan struct{})
	go func() {
		_ = c.Destruct()
		close(destructed)
	}()
	select {
	case <-destructed:
		t.Error("destruction completed while Repair was still in flight")
	case <-time.After(100 * time.Millisecond):
	}
	close(d.releaseRepair)
	select {
	case <-destructed:
	case <-time.After(3 * time.Second):
		t.Fatal("destruction did not finish after repair returned")
	}
	<-d.finished
	if d.postClose.Load() {
		t.Error("Repair performed work after the device was closed")
	}
}
