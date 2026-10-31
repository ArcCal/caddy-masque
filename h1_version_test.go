package masque

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

// RFC 9110 §7.8 requires servers to ignore Upgrade in HTTP/1.0 requests.
// Even valid CONNECT-IP credentials must therefore leave this request to
// the ordinary site instead of opening an HTTP/1.1 Upgrade tunnel.
func TestCaddyHTTP10IgnoresUpgrade(t *testing.T) {
	e := newCaddyEnv(t)
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := e.dialTCP(ctx, e.tlsConfig("http/1.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.0\r\nHost: vpn.test:%d\r\nConnection: Upgrade\r\nUpgrade: connect-ip\r\n"+
		"Capsule-Protocol: ?1\r\nAuthorization: %s\r\n\r\n", anyTarget, e.port, authorization(testPassword)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// Check status before reading: a wrongly accepted tunnel has no EOF.
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP/1.0 with Upgrade: status %d, want %d (ordinary site)", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "cover page" {
		t.Errorf("HTTP/1.0 with Upgrade: body %q, want cover page", body)
	}
	if got := resp.Header.Get("Capsule-Protocol"); got != "" {
		t.Errorf("HTTP/1.0 with Upgrade: Capsule-Protocol %q", got)
	}
	if got := resp.Header.Get("Upgrade"); got != "" {
		t.Errorf("HTTP/1.0 with Upgrade: Upgrade %q", got)
	}
	waitNoSessions(t)
}

// RFC 9110 Section 7.8: a server that receives Upgrade with a 100-continue
// expectation must send 100 (Continue) before 101 (Switching Protocols).
func TestCaddyUpgradeWithExpectContinue(t *testing.T) {
	e := newCaddyEnv(t)
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := e.dialTCP(ctx, e.tlsConfig("http/1.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: vpn.test:%d\r\nConnection: Upgrade\r\nUpgrade: connect-ip\r\n"+
		"Capsule-Protocol: ?1\r\nExpect: 100-Continue\r\nAuthorization: %s\r\n\r\n", anyTarget, e.port, authorization(testPassword)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	for _, want := range []int{http.StatusContinue, http.StatusSwitchingProtocols} {
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != want {
			t.Fatalf("status %d, want %d", resp.StatusCode, want)
		}
	}
	c := &tunnelClient{status: http.StatusSwitchingProtocols, close: func() { conn.Close() }}
	streamClient(c, br, conn)
	opening(t, c)
	c.close()
	waitNoSessions(t)
}
