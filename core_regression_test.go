package masque

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/ArcCal/caddy-masque/internal/ip"
	"github.com/ArcCal/caddy-masque/internal/proto"
)

func TestStagedCoreConfigurationDoesNotChangeLiveState(t *testing.T) {
	e := newTestEnv(t, dualStack())
	old := e.app
	old.users = map[string]string{alice.Name: alice.Hash, bob.Name: bob.Hash}
	e.core.activate(old)
	r := e.start(t, alice, true)
	mtuProbe := false
	next := &App{allowed: old.allowed, users: map[string]string{bob.Name: bob.Hash}, MaxSessions: 1, MTUProbe: &mtuProbe}
	next.allowed.Remove(netip.MustParsePrefix("1.1.1.1/32"))
	assertOld := func() {
		t.Helper()
		if !e.core.auth.IsCurrent(alice) || !e.core.allowed.Load().Contains(netip.MustParseAddr("1.1.1.1")) ||
			e.core.noMTUProbe.Load() || e.core.maxSessions.Load() != DefaultMaxSessions {
			t.Fatal("uncommitted candidate changed active authentication, routes, or limits")
		}
		select {
		case <-r.lease.handle.revoked:
			t.Fatal("uncommitted candidate revoked an existing session")
		default:
		}
		p := udp(r.addr(false), "1.1.1.1", 10)
		r.tun.datagrams <- append([]byte{0}, p...)
		if got := hostPacket(t, e.dev); !slices.Equal(got, p) {
			t.Fatal("old tunnel stopped forwarding under its active routes")
		}
	}
	e.core.activate(next)
	e.core.activate(next)
	assertOld()
	if len(e.core.owners) != 2 {
		t.Fatal("activation registered an owner more than once")
	}
	// A later app failed. Its Stop names Caddy's still-current old app,
	// then Cleanup discards this staged candidate.
	e.core.commit(old)
	e.core.deactivate(next)
	assertOld()
	// Cleanup or failed provisioning must not allow a stale commit to apply
	// a candidate that never completed startup or is no longer registered.
	e.core.commit(next)
	assertOld()
}

func TestCoreCommitPublishesCandidateAndSurvivesOldCleanup(t *testing.T) {
	e := newTestEnv(t, dualStack())
	old := e.app
	old.users = map[string]string{alice.Name: alice.Hash, bob.Name: bob.Hash}
	e.core.activate(old)
	removed, kept := e.start(t, alice, true), e.start(t, bob, true)
	mtuProbe := false
	next := &App{allowed: old.allowed, users: map[string]string{bob.Name: bob.Hash}, MaxSessions: 3, MTUProbe: &mtuProbe}
	e.core.activate(next)
	e.core.commit(next)
	if why := removed.waitEnd(t); why != "user removed or password changed" {
		t.Fatalf("removed user ended: %s", why)
	}
	if e.core.auth.IsCurrent(alice) || !e.core.auth.IsCurrent(bob) || !e.core.noMTUProbe.Load() || e.core.maxSessions.Load() != 3 {
		t.Fatal("committed policy did not apply")
	}
	// Successful publication stops and cleans up the previous app. Neither
	// a repeated commit nor that cleanup may restore the previous users.
	e.core.commit(next)
	e.core.deactivate(old)
	if e.core.auth.IsCurrent(alice) || !e.core.auth.IsCurrent(bob) || e.core.active != next {
		t.Fatal("old cleanup overwrote the committed configuration")
	}
	p := udp(kept.addr(false), "1.1.1.1", 10)
	kept.tun.datagrams <- append([]byte{0}, p...)
	if got := hostPacket(t, e.dev); !slices.Equal(got, p) {
		t.Fatal("unchanged user lost its existing tunnel")
	}
}

func TestCoreRouteWithdrawalWaitsForCommit(t *testing.T) {
	e := newTestEnv(t, dualStack())
	old := e.app
	old.users = map[string]string{alice.Name: alice.Hash, bob.Name: bob.Hash}
	e.core.activate(old)
	r := e.start(t, alice, true)
	next := &App{allowed: old.allowed, users: old.users}
	next.allowed.Remove(netip.MustParsePrefix("1.1.1.1/32"))
	e.core.activate(next)
	p := udp(r.addr(false), "1.1.1.1", 10)
	r.tun.datagrams <- append([]byte{0}, p...)
	hostPacket(t, e.dev)
	e.core.commit(next)
	if why := r.waitEnd(t); why != "the new configuration withdraws routes of the tunnel" {
		t.Fatalf("route withdrawal ended tunnel: %s", why)
	}
}

// RFC 9484 §4.7.2 distinguishes rejection from an unsolicited assignment.
// In particular, an assigned host inside a requested prefix does not mean
// the proxy has granted that entire prefix.
func TestExplicitAddressRequests(t *testing.T) {
	for _, assigned := range []string{"10.89.0.5", "fd89::5"} {
		a := netip.MustParseAddr(assigned)
		for _, tc := range []struct {
			name      string
			requested netip.Prefix
			granted   bool
		}{
			{"existing host", proto.Host(a), true},
			{"different host", proto.Host(a.Next()), false},
			{"containing prefix", netip.PrefixFrom(a, a.BitLen()-8).Masked(), false},
			{"no preference", proto.Unspecified(a.Is6()), true},
		} {
			t.Run(assigned+"/"+tc.name, func(t *testing.T) {
				got := addressAssignReply([]netip.Addr{a}, proto.AddressRequest{{RequestID: 9, Prefix: tc.requested}})
				want := proto.AddressAssign{{RequestID: 9, Prefix: proto.Host(a)}}
				if !tc.granted {
					want = proto.AddressAssign{{RequestID: 9, Prefix: proto.Unspecified(a.Is6())}, {Prefix: proto.Host(a)}}
				}
				if !slices.Equal(got, want) {
					t.Fatalf("got %+v, want %+v", got, want)
				}
			})
		}
	}
}

func TestOptionalQueryVariables(t *testing.T) {
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			e := newCaddyEnv(t)
			e.handler = map[string]any{"template": "/ip{?target,ipproto}"}
			if err := e.load(masqueConfig("alice")); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{"/ip", "/ip?target=*", "/ip?ipproto=6"} {
				c := tr.dial(e, t, testPassword, path)
				if c.status != tr.ok {
					t.Errorf("%s: status %d, want %d", path, c.status, tr.ok)
				} else {
					opening(t, c)
				}
				c.close()
			}
			for _, path := range []string{"/ip?target=", "/ip?ipproto=", "/ip?target=%FF", "/ip?ipproto=%FF"} {
				c := tr.dial(e, t, testPassword, path)
				if c.status != http.StatusBadRequest {
					t.Errorf("%s: status %d, want 400", path, c.status)
				}
				c.close()
			}
		})
	}
}

func TestChecksumInvalidClientPacketsAreSilentlyDiscarded(t *testing.T) {
	e := newTestEnv(t, &App{IPv4: "10.89.0.1/24"})
	r := e.start(t, alice, true)
	for _, dst := range []string{"192.168.1.1", "1.1.1.1"} {
		p := udp(r.addr(false), dst, 10)
		p[10] ^= 1
		r.tun.datagrams <- append([]byte{0}, p...)
		noHostPacket(t, e.dev)
		r.tun.quiet(t)
	}
	// A bad packet must not end the session or suppress the next valid one.
	p := udp(r.addr(false), "1.1.1.1", 10)
	r.tun.datagrams <- append([]byte{0}, p...)
	if got := hostPacket(t, e.dev); !slices.Equal(got, p) {
		t.Fatal("valid packet changed")
	}
}

func TestLinkLocalUnicastDoesNotCrossTunnel(t *testing.T) {
	e := newTestEnv(t, dualStack())
	r := e.start(t, alice, true)
	for _, v6 := range []bool{false, true} {
		linkLocal := "169.254.1.2"
		if v6 {
			linkLocal = "fe80::2"
		}
		r.tun.datagrams <- append([]byte{0}, udp(r.addr(v6), linkLocal, 10)...)
		noHostPacket(t, e.dev)
		reply := r.tun.nextPacket(t)
		h, ok := ip.Parse(reply)
		protocol, typ, code := uint8(ip.ProtoICMP), byte(3), byte(13)
		if v6 {
			protocol, typ, code = ip.ProtoICMPv6, 1, 1
		}
		if !ok || h.Dst.String() != r.addr(v6) || h.Protocol != protocol || h.PayloadOffset < 0 ||
			reply[h.PayloadOffset] != typ || reply[h.PayloadOffset+1] != code {
			t.Fatalf("expected local administratively prohibited feedback, got %x", reply)
		}
		e.dev.fromHost <- udp(linkLocal, r.addr(v6), 10)
		r.tun.quiet(t)
	}
}

// Cover responses can stream normally, but must never announce successful
// extended CONNECT unless the module actually establishes the tunnel.
func TestRefusalResponseStatus(t *testing.T) {
	for _, major := range []int{1, 2, 3} {
		for _, mode := range []string{"implicit", "explicit", "copy", "flush", "empty", "error", "redirect"} {
			t.Run(fmt.Sprintf("h%d/%s", major, mode), func(t *testing.T) {
				r := httptest.NewRequest(http.MethodConnect, "https://vpn.test/", nil)
				r.ProtoMajor = major
				w := httptest.NewRecorder()
				err := serveRefusal(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
					w.Header().Set("Content-Type", "text/plain")
					switch mode {
					case "explicit":
						w.WriteHeader(http.StatusAccepted)
					case "error":
						w.WriteHeader(http.StatusForbidden)
					case "redirect":
						w.WriteHeader(http.StatusTemporaryRedirect)
					case "flush":
						if err := http.NewResponseController(w).Flush(); err != nil {
							return err
						}
					case "empty":
						return nil
					}
					if mode == "copy" {
						_, err := io.Copy(w, &onlyReader{body: []byte("cover page")})
						return err
					}
					_, err := io.WriteString(w, "cover page")
					return err
				}))
				if err != nil {
					t.Fatal(err)
				}
				want := http.StatusOK
				if major >= 2 {
					want = http.StatusNotFound
				}
				if mode == "error" {
					want = http.StatusForbidden
				} else if mode == "redirect" {
					want = http.StatusTemporaryRedirect
				} else if mode == "explicit" && major == 1 {
					want = http.StatusAccepted
				}
				if w.Code != want || (mode != "empty" && w.Body.String() != "cover page") {
					t.Fatalf("status %d body %q, want status %d", w.Code, w.Body.String(), want)
				}
			})
		}
	}
}

func TestCaddyErrorPagesCannotAcceptRefusedConnect(t *testing.T) {
	e := newCaddyEnv(t)
	e.server = map[string]any{
		"routes": []any{map[string]any{"handle": []any{
			e.handlerConfig(),
			map[string]any{"handler": "error", "status_code": 404, "error": "missing site resource"},
		}}},
		"errors": map[string]any{"routes": []any{map[string]any{"handle": []any{
			map[string]any{"handler": "static_response", "status_code": 200, "body": "site error page"},
		}}}},
	}
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			c := tr.dial(e, t, "wrong password!!", anyTarget)
			defer c.close()
			want := http.StatusNotFound
			if tr.ok == http.StatusSwitchingProtocols {
				want = http.StatusOK
			}
			if c.status != want || c.body != "site error page" {
				t.Fatalf("status %d body %q, want %d with site error page", c.status, c.body, want)
			}
		})
	}
}

type onlyReader struct{ body []byte }

func (r *onlyReader) Read(p []byte) (int, error) {
	if len(r.body) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.body)
	r.body = r.body[n:]
	return n, nil
}

func TestAnonymousMalformedHTTP1Upgrade(t *testing.T) {
	for _, tc := range []struct {
		name, method, connection string
		content                  bool
	}{
		{"wrong method", http.MethodPost, "Upgrade", false},
		{"no connection token", http.MethodGet, "close", false},
		{"content headers", http.MethodGet, "Upgrade", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "https://vpn.test/", nil)
			r.Header.Set("Upgrade", "connect-ip")
			r.Header.Set("Connection", tc.connection)
			if tc.content {
				r.Header.Set("Content-Length", "0")
			}
			w := httptest.NewRecorder()
			h := &Handler{}
			err := h.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				t.Fatal("malformed upgrade reached website handler")
				return nil
			}))
			if err != nil || w.Code != http.StatusBadRequest {
				t.Fatalf("status %d err %v, want 400", w.Code, err)
			}
		})
	}
}
