package masque

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddytls"

	"github.com/ArcCal/caddy-masque/internal/proto"
)

const testHash = "$argon2id$v=19$m=19456,t=2,p=1$JbPnvQtCivJ9Yx0m03/vEA$Hxye9dEALbiWaLl5sS6mw31urn8oXItWrw/QXQ0k0e8"

func parseGlobal(t *testing.T, input string) (*App, error) {
	t.Helper()
	v, err := parseGlobalOption(caddyfile.NewTestDispenser(input), nil)
	if err != nil {
		return nil, err
	}
	app := new(App)
	if err := json.Unmarshal(v.(httpcaddyfile.App).Value, app); err != nil {
		t.Fatal(err)
	}
	return app, nil
}

func TestCaddyfileGlobalOption(t *testing.T) {
	app, err := parseGlobal(t, `masque {
		interface vpn0
		ipv4 10.9.0.1/24
		ipv6 fd09::1/64
		mtu 1400
		manage_network off
		block 10.0.0.0/8 192.168.0.0/16
		block fc00::/7
		allow_client_to_client
		allow_host_access
		max_sessions 3
		auth_memory 64
		max_total_sessions 256
		queue_memory 16
		http3 off
		mtu_probe off
		user alice `+testHash+`
		user bob `+testHash+`
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if app.Interface != "vpn0" || app.IPv4 != "10.9.0.1/24" || app.IPv6 != "fd09::1/64" || app.MTU != 1400 ||
		*app.ManageNetwork || *app.HTTP3 || *app.MTUProbe || !app.AllowClientToClient || !app.AllowHostAccess || app.MaxSessions != 3 || app.sessionLimit() != 3 || len(app.Users) != 2 ||
		app.AuthMemoryMiB != 64 || app.MaxTotalSessions != 256 || app.QueueMemoryMiB != 16 ||
		app.Users[1].Name != "bob" || app.Users[1].PasswordHash != testHash ||
		strings.Join(*app.BlockedDestinations, " ") != "10.0.0.0/8 192.168.0.0/16 fc00::/7" {
		t.Errorf("parsed %+v", app)
	}
	if err := app.parse(); err != nil {
		t.Error(err)
	}

	app, err = parseGlobal(t, "masque {\n ipv4 10.9.0.1/24\n block none\n}")
	if err != nil || app.BlockedDestinations == nil || len(*app.BlockedDestinations) != 0 {
		t.Errorf("block none: %v %v", app, err)
	}
	if app, err = parseGlobal(t, "masque {\n ipv4 10.9.0.1/24\n max_sessions unlimited\n}"); err != nil || app.sessionLimit() != 0 {
		t.Errorf("max_sessions unlimited: %+v %v", app, err)
	}
	app, err = parseGlobal(t, "masque {\n ipv4 10.9.0.1/24\n}")
	if err == nil && (app.sessionLimit() != DefaultMaxSessions) {
		t.Errorf("default sessions %d", app.sessionLimit())
	}
	app, err = parseGlobal(t, "masque {\n ipv4 10.9.0.1/24\n}")
	if err != nil || app.BlockedDestinations != nil || app.ManageNetwork != nil || app.HTTP3 != nil || app.MTUProbe != nil {
		t.Errorf("defaults: %+v %v", app, err)
	}
}

func TestCaddyfileGlobalOptionErrors(t *testing.T) {
	for _, input := range []string{
		"masque extra",
		"masque {\n bogus\n}",
		"masque {\n ipv4\n}",
		"masque {\n ipv4 10.9.0.1/24 10.8.0.1/24\n}",
		"masque {\n ipv4 10.9.0.1/24\n ipv4 10.8.0.1/24\n}",
		"masque {\n mtu big\n}",
		"masque {\n manage_network maybe\n}",
		"masque {\n http3\n}",
		"masque {\n mtu_probe sometimes\n}",
		"masque {\n allow_client_to_client yes\n}",
		"masque {\n allow_host_access yes\n}",
		"masque {\n max_sessions 0\n}",
		"masque {\n max_sessions many\n}",
		"masque {\n auth_memory 18\n}",
		"masque {\n auth_memory 1025\n}",
		"masque {\n auth_memory many\n}",
		"masque {\n queue_memory 0\n}",
		"masque {\n queue_memory 1025\n}",
		"masque {\n max_total_sessions unlimited\n}",
		"masque {\n max_total_sessions 0\n}",
		"masque {\n block\n}",
		"masque {\n user alice\n}",
		"masque {\n user alice hash extra\n}",
	} {
		if _, err := parseGlobal(t, input); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
	if _, err := parseGlobalOption(caddyfile.NewTestDispenser("masque"), httpcaddyfile.App{}); err == nil {
		t.Error("accepted a second masque option")
	}
}

func TestCaddyfileHandlerDirective(t *testing.T) {
	parse := func(input string) (*Handler, error) {
		h, err := parseHandlerDirective(httpcaddyfile.Helper{Dispenser: caddyfile.NewTestDispenser(input)})
		if err != nil {
			return nil, err
		}
		return h.(*Handler), nil
	}
	if h, err := parse("masque"); err != nil || h.Template != "" {
		t.Errorf("%+v %v", h, err)
	}
	if h, err := parse("masque /vpn/{target}/{ipproto}/"); err != nil || h.Template != "/vpn/{target}/{ipproto}/" {
		t.Errorf("%+v %v", h, err)
	}
	for _, input := range []string{"masque /a /b", "masque {\n x\n}"} {
		if _, err := parse(input); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
}

func TestAppSettings(t *testing.T) {
	no := false
	for _, c := range []struct {
		app App
		ok  bool
	}{
		{App{IPv4: "10.89.0.1/24"}, true},
		{App{IPv4: "10.89.0.1/24", IPv6: "fd89::1/64", MTU: 1280}, true},
		{App{IPv4: "10.89.0.1/30"}, true},
		{App{}, false},
		{App{IPv4: "10.89.0.0/24"}, false}, // the network, not an address in it
		{App{IPv4: "10.89.0.255/24"}, false},
		{App{IPv4: "10.89.0.1/31"}, false},
		{App{IPv4: "169.254.89.1/24"}, false},
		{App{IPv4: "127.0.0.1/24"}, false},
		{App{IPv4: "224.0.0.1/24"}, false},
		{App{IPv4: "10.89.0.1/24", IPv6: "fe80::1/64"}, false},
		{App{IPv4: "10.89.0.1/24", IPv6: "fd89::1/127"}, false},
		{App{IPv4: "10.89.0.1/24", IPv6: "fd89::1/126"}, true},
		{App{IPv4: "fd89::1/64"}, false}, // wrong family
		{App{IPv4: "10.89.0.1/24", IPv6: "10.9.0.1/24"}, false},
		{App{IPv4: "10.89.0.1/24", IPv6: "::ffff:10.9.0.1/120"}, false},
		{App{IPv4: "10.89.0.1"}, false},
		{App{IPv4: "10.89.0.1/24", MTU: 575}, false},
		{App{IPv4: "10.89.0.1/24", MTU: 576}, true},
		{App{IPv4: "10.89.0.1/24", IPv6: "fd89::1/64", MTU: 1279}, false},
		{App{IPv4: "10.89.0.1/24", MTU: 1501}, false},
		{App{IPv4: "10.89.0.1/24", Interface: "a-very-long-name0"}, false},
		{App{IPv4: "10.89.0.1/24", Interface: "vpn.0"}, true},
		{App{IPv4: "10.89.0.1/24", Interface: "."}, false},
		{App{IPv4: "10.89.0.1/24", Interface: ".."}, false},
		{App{IPv4: "10.89.0.1/24", Interface: "vpn/0"}, false},
		{App{IPv4: "10.89.0.1/24", Interface: "vpn:0"}, false},
		{App{IPv4: "10.89.0.1/24", Interface: "vpn 0"}, false},
		{App{IPv4: "10.89.0.1/24", Users: []User{{"alice", testHash}, {"alice", testHash}}}, false},
		{App{IPv4: "10.89.0.1/24", Users: []User{{"bad name", testHash}}}, false},
		{App{IPv4: "10.89.0.1/24", Users: []User{{"alice", "plain"}}}, false},
		{App{IPv4: "10.89.0.1/24", BlockedDestinations: &[]string{"10.0.0.0/33"}}, false},
		{App{IPv4: "10.89.0.1/24", ManageNetwork: &no}, true},
	} {
		err := c.app.parse()
		if (err == nil) != c.ok {
			t.Errorf("%+v: %v", c.app, err)
		}
	}
}

func TestAllowedDestinations(t *testing.T) {
	check := func(app *App, reachable, unreachable []string) {
		t.Helper()
		if err := app.parse(); err != nil {
			t.Fatal(err)
		}
		for _, a := range reachable {
			if !app.allowed.Contains(netip.MustParseAddr(a)) {
				t.Errorf("%s is blocked", a)
			}
		}
		for _, a := range unreachable {
			if app.allowed.Contains(netip.MustParseAddr(a)) {
				t.Errorf("%s is allowed", a)
			}
		}
	}
	// IPv4 only: no IPv6 destination at all.
	check(&App{IPv4: "10.89.0.1/24"}, []string{"1.1.1.1", "10.89.0.1"},
		[]string{"10.89.0.2", "10.0.0.1", "192.168.1.1", "2606:4700::1111", "169.254.169.254"})
	check(&App{IPv4: "10.89.0.1/24", IPv6: "fd89::1/64"}, []string{"2606:4700::1111", "fd89::1"},
		[]string{"fd89::2", "fd00::1", "fe80::1", "::1", "::ffff:1.1.1.1"})
	// An empty blocked list still keeps link-local addresses and other
	// clients out.
	check(&App{IPv4: "10.89.0.1/24", BlockedDestinations: &[]string{}}, []string{"10.0.0.1", "192.168.1.1"},
		[]string{"169.254.169.254", "10.89.0.7"})
	check(&App{IPv4: "10.89.0.1/24", AllowClientToClient: true}, []string{"10.89.0.7", "10.89.0.1"},
		[]string{"10.0.0.1", "10.89.1.1"})
}

func TestTakeOverHTTP3(t *testing.T) {
	https := &caddyhttp.Server{Listen: []string{":443"}, TLSConnPolicies: caddytls.ConnectionPolicies{{}}}
	app := &App{httpApp: &caddyhttp.App{Servers: map[string]*caddyhttp.Server{
		"https": https,
		"h2only": {Listen: []string{":8443"}, Protocols: []string{"h1", "h2"},
			TLSConnPolicies: caddytls.ConnectionPolicies{{}}},
		"plain": {Listen: []string{":80"}},
		"mixed": {Listen: []string{"tcp4/127.0.0.1:9443", ":9444", "unix//run/x.sock"},
			ListenProtocols: [][]string{{"h1", "h3"}, nil, nil}, TLSConnPolicies: caddytls.ConnectionPolicies{{}}},
		"range": {Listen: []string{":10443-10445"}, TLSConnPolicies: caddytls.ConnectionPolicies{{}}},
	}}}
	if err := app.takeOverHTTP3(); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, a := range app.h3Addrs {
		got = append(got, a.server+" "+a.network+" "+a.hostport)
	}
	want := map[string]bool{
		"https udp :443": true, "mixed udp4 127.0.0.1:9443": true, "mixed udp :9444": true,
		"range udp :10443": true, "range udp :10444": true, "range udp :10445": true,
	}
	if len(got) != len(want) {
		t.Errorf("serving %v", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected %q", g)
		}
	}
	for name, srv := range app.httpApp.Servers {
		for _, p := range append(srv.Protocols, func() (all []string) {
			for _, lp := range srv.ListenProtocols {
				all = append(all, lp...)
			}
			return
		}()...) {
			if p == "h3" {
				t.Errorf("%s still has h3", name)
			}
		}
	}
	if strings.Join(https.Protocols, ",") != "h1,h2" {
		t.Errorf("default protocols became %v", https.Protocols)
	}
	if !app.h3Ports[443] || app.h3Ports[8443] || app.h3Ports[80] {
		t.Errorf("ports %v", app.h3Ports)
	}
}

func TestConnectIPRequests(t *testing.T) {
	req := func(proto string, major int, method string, header http.Header) *http.Request {
		r, _ := http.NewRequestWithContext(context.Background(), method, "https://vpn.test/", nil)
		r.Proto, r.ProtoMajor = proto, major
		for k, v := range header {
			r.Header[k] = v
		}
		return r
	}
	for _, c := range []struct {
		r    *http.Request
		want bool
	}{
		{req("connect-ip", 3, http.MethodConnect, nil), true},
		{req("websocket", 3, http.MethodConnect, nil), false},
		{req("HTTP/3.0", 3, http.MethodGet, nil), false},
		{req("HTTP/2.0", 2, http.MethodConnect, http.Header{":protocol": {"connect-ip"}}), true},
		{req("HTTP/2.0", 2, http.MethodConnect, http.Header{":protocol": {"connect-udp"}}), false},
		{req("HTTP/2.0", 2, http.MethodConnect, nil), false},
		{req("HTTP/1.1", 1, http.MethodGet, http.Header{"Connection": {"keep-alive, Upgrade"}, "Upgrade": {"Connect-IP"}}), true},
		{req("HTTP/1.1", 1, http.MethodGet, http.Header{"Connection": {"upgrade"}, "Upgrade": {"websocket"}}), false},
		{req("HTTP/1.1", 1, http.MethodGet, nil), false},
	} {
		if got, ok := connectIPRequest(c.r); ok != c.want || ok && !got.wellFormed {
			t.Errorf("%s %s %v: %v %+v", c.r.Proto, c.r.Method, c.r.Header, ok, got)
		}
	}
	// Requests for connect-ip that are malformed (§4.2).
	for _, r := range []*http.Request{
		req("HTTP/1.1", 1, http.MethodGet, http.Header{"Upgrade": {"connect-ip"}}),
		req("HTTP/1.1", 1, http.MethodPost, http.Header{"Connection": {"upgrade"}, "Upgrade": {"connect-ip"}}),
	} {
		if got, ok := connectIPRequest(r); !ok || got.wellFormed {
			t.Errorf("%s %v: %v %+v", r.Method, r.Header, ok, got)
		}
	}
}

func TestCarriesContent(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "https://vpn.test/", nil)
	if carriesContent(r) {
		t.Error("no content")
	}
	for _, h := range []string{"Content-Length", "Content-Type", "Transfer-Encoding"} {
		r.Header = http.Header{h: {"0"}}
		if !carriesContent(r) {
			t.Errorf("%s", h)
		}
	}
}

func TestResolveScope(t *testing.T) {
	app := &App{IPv4: "10.89.0.1/24", IPv6: "fd89::1/64"}
	if err := app.parse(); err != nil {
		t.Fatal(err)
	}
	c := &core{}
	c.allowed.Store(&app.allowed)
	h := &Handler{app: &App{core: c}}
	parse := func(target, ipproto string) (scope, *rejection) {
		tg, err := proto.ParseTarget(target)
		if err != nil {
			t.Fatal(err)
		}
		p, err := proto.ParseIPProtocol(ipproto)
		if err != nil {
			t.Fatal(err)
		}
		return h.resolveScope(context.Background(), tg, p)
	}
	sc, rej := parse("*", "*")
	if rej != nil || !sc.routes.HasIPv4() || !sc.routes.HasIPv6() || sc.protocol != 0 {
		t.Errorf("full scope: %+v %+v", sc, rej)
	}
	sc, rej = parse("192.0.2.0/24", "17")
	if rej != nil || sc.routes.HasIPv6() || !sc.routes.Contains(netip.MustParseAddr("192.0.2.9")) ||
		sc.routes.Contains(netip.MustParseAddr("192.0.3.1")) || sc.protocol != 17 {
		t.Errorf("prefix scope: %+v %+v", sc, rej)
	}
	if _, rej = parse("192.168.0.0/16", "*"); rej == nil || rej.status != http.StatusForbidden {
		t.Errorf("blocked scope: %+v", rej)
	}
	if _, rej = parse("*", "0"); rej == nil || rej.status != http.StatusBadRequest {
		t.Errorf("hop-by-hop options as ipproto: %+v", rej)
	}
	if _, rej = parse("does-not-exist.invalid", "*"); rej == nil || rej.status != http.StatusBadGateway || rej.proxyError == "" {
		t.Errorf("unresolvable name: %+v", rej)
	}
	if sc, rej = parse("localhost", "*"); rej == nil || rej.status != http.StatusForbidden {
		// localhost resolves to loopback addresses, which are blocked.
		t.Errorf("localhost: %+v %+v", sc, rej)
	}
}

func TestAddressAssignReplyKeepsRequestIDs(t *testing.T) {
	v4, v6 := netip.MustParseAddr("10.89.0.5"), netip.MustParseAddr("fd89::5")
	reply := addressAssignReply([]netip.Addr{v4, v6}, proto.AddressRequest{{RequestID: 1, Prefix: proto.Unspecified(true)}})
	want := proto.AddressAssign{{RequestID: 1, Prefix: proto.Host(v6)}, {Prefix: proto.Host(v4)}}
	if len(reply) != 2 || reply[0] != want[0] || reply[1] != want[1] {
		t.Errorf("reply %v", reply)
	}
}
