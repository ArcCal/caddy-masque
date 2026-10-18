// Package masque is a Caddy module that serves CONNECT-IP (RFC 9484): the
// IP proxying of MASQUE, over HTTP/3, HTTP/2 and HTTP/1.1, with the
// certificates and websites Caddy manages. It is the server of masque-vpn
// written in Go; masque-vpn's client works with it unchanged.
//
// The masque app owns the tunnel (TUN device, addresses, users) and serves
// HTTP/3 with HTTP Datagrams (RFC 9297) for Caddy's HTTPS servers, whose own
// HTTP/3 has datagrams off. The masque handler, placed in a site's routes,
// answers CONNECT-IP requests and passes everything else on.
package masque

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	_ "github.com/caddy-dns/cloudflare"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"

	"github.com/ArcCal/caddy-masque/internal/auth"
	"github.com/ArcCal/caddy-masque/internal/routes"
	"github.com/ArcCal/caddy-masque/internal/xconnect"
)

func init() {
	caddy.RegisterModule(App{})
}

// Defaults of the tunnel.
const (
	DefaultInterface = "masque0"
	DefaultMTU       = 1350
)

// User is a user allowed to connect.
type User struct {
	Name string `json:"name"`
	// Argon2id hash in PHC format, as printed by `caddy masque-passwd` or
	// masque-vpn's masque-passwd.
	PasswordHash string `json:"password_hash"`
}

// App is the masque app: the tunnel and its users.
type App struct {
	// TUN device name.
	Interface string `json:"interface,omitempty"`
	// The server's own IPv4 tunnel address with its prefix, which is the
	// client pool, for example 10.89.0.1/24.
	IPv4 string `json:"ipv4,omitempty"`
	// The same for IPv6; leave out to offer IPv4 only.
	IPv6 string `json:"ipv6,omitempty"`
	MTU  int    `json:"mtu,omitempty"`
	// Leave forwarding and NAT (sysctls, nftables) alone when false.
	ManageNetwork *bool `json:"manage_network,omitempty"`
	// Destinations clients may not reach; nil means routes.DefaultBlocked.
	BlockedDestinations *[]string `json:"blocked_destinations,omitempty"`
	// Let clients reach the host's own services through the tunnel (the
	// server's tunnel address and its public addresses), not just ping it.
	AllowHostAccess bool `json:"allow_host_access,omitempty"`
	// Let clients reach each other's tunnel addresses.
	AllowClientToClient bool   `json:"allow_client_to_client,omitempty"`
	Users               []User `json:"users,omitempty"`
	// Sessions one user may have at a time; 0 means the default
	// (DefaultMaxSessions), -1 no limit. A user who uses up the client
	// address pool would lock the others out.
	MaxSessions int `json:"max_sessions,omitempty"`
	// Serve HTTP/3 with datagrams for the HTTPS servers (default true). When
	// off, Caddy keeps its own HTTP/3, which does not announce HTTP
	// Datagrams, so CONNECT-IP over it carries packets in DATAGRAM capsules
	// on the request stream (RFC 9297 §3.5), as over HTTP/2 and HTTP/1.1.
	HTTP3 *bool `json:"http3,omitempty"`
	// Check that a tunnel with IPv6 over QUIC datagrams carries 1280-byte
	// packets with an ICMPv6 echo request, ending it without a reply (RFC
	// 9484 §7.2; default true). Turn it off only when clients are known to
	// connect directly, with no HTTP intermediary: then the padded QUIC
	// Initial packets are enough.
	MTUProbe *bool `json:"mtu_probe,omitempty"`

	ctx         caddy.Context
	log         *zap.Logger
	cfg         tunnelConfig
	users       map[string]string
	allowed     routes.Set
	core        *core
	coreKey     string
	released    bool     // the core's pool reference
	listeners   []string // keys in the listener pool
	h3Listeners []*h3Listener
	httpApp     *caddyhttp.App
	// The UDP addresses whose HTTP/3 this app serves, and their ports.
	h3Addrs []h3Addr
	h3Ports map[int]bool
}

type h3Addr struct{ server, network, hostport string }

// sessionLimit is the sessions one user may have, 0 for no limit.
func (a *App) sessionLimit() int {
	switch {
	case a.MaxSessions == 0:
		return DefaultMaxSessions
	case a.MaxSessions < 0:
		return 0
	}
	return a.MaxSessions
}

// CaddyModule returns the Caddy module information.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "masque", New: func() caddy.Module { return new(App) }}
}

// Provision implements caddy.Provisioner: it checks the configuration and
// takes HTTP/3 over from the HTTPS servers.
func (a *App) Provision(ctx caddy.Context) error {
	a.ctx = ctx
	a.log = ctx.Logger()
	if err := a.parse(); err != nil {
		return err
	}
	if !xconnect.Enabled() {
		a.log.Warn("GODEBUG turns extended CONNECT off: CONNECT-IP over HTTP/2 is refused; remove http2xconnect=0 from it")
	}
	if a.HTTP3 == nil || *a.HTTP3 {
		httpAny, err := ctx.App("http")
		if err != nil {
			return err
		}
		a.httpApp = httpAny.(*caddyhttp.App)
		if err := a.takeOverHTTP3(); err != nil {
			return err
		}
	}
	// The app owns one host network and one nftables table. All tunnel
	// settings, including its interface, must match across reloads.
	a.coreKey = "masque-core"
	val, _, err := cores.LoadOrNew(a.coreKey, func() (caddy.Destructor, error) {
		return newCore(a.cfg, a.log)
	})
	if err != nil {
		return err
	}
	a.core = val.(*core)
	if err := ctx.GetMetricsRegistry().Register(newCollector(a.core)); err != nil {
		a.log.Warn("could not register the masque metrics", zap.Error(err))
	}
	if a.core.cfg != a.cfg {
		_, _ = cores.Delete(a.coreKey)
		a.released = true
		return errors.New("masque: the tunnel settings (interface, ipv4, ipv6, mtu, manage_network, allow_host_access) changed; restart Caddy to apply them")
	}
	// Caddy emits stopping before any app stops. HTTP shutdown may wait
	// for tunnels retained from an earlier configuration, even when this
	// configuration has no masque handler or HTTP server left. Cleanup
	// would run too late to end them.
	events, err := ctx.App("events")
	if err != nil {
		return err
	}
	if err := events.(*caddyevents.App).On("stopping", shutdownHandler{core: a.core}); err != nil {
		return err
	}
	return nil
}

type shutdownHandler struct{ core *core }

func (h shutdownHandler) Handle(context.Context, caddy.Event) error {
	if caddy.Exiting() {
		h.core.shutdown("server shutting down")
	}
	return nil
}

func (a *App) parse() error {
	a.cfg.iface = a.Interface
	if a.cfg.iface == "" {
		a.cfg.iface = DefaultInterface
	}
	if len(a.cfg.iface) > 15 {
		return fmt.Errorf("masque: interface name %q is longer than 15 characters", a.cfg.iface)
	}
	if a.IPv4 == "" {
		return errors.New("masque: ipv4 is required, for example 10.89.0.1/24")
	}
	var err error
	if a.cfg.ipv4, err = hostPrefix(a.IPv4, false); err != nil {
		return err
	}
	if a.IPv6 != "" {
		if a.cfg.ipv6, err = hostPrefix(a.IPv6, true); err != nil {
			return err
		}
	}
	a.cfg.mtu = a.MTU
	if a.cfg.mtu == 0 {
		a.cfg.mtu = DefaultMTU
	}
	minMTU := 576
	if a.cfg.ipv6.IsValid() {
		minMTU = 1280 // RFC 8200 minimum link MTU
	}
	if a.cfg.mtu < minMTU || a.cfg.mtu > 1500 {
		return fmt.Errorf("masque: mtu must be between %d and 1500, got %d", minMTU, a.cfg.mtu)
	}
	a.cfg.manage = a.ManageNetwork == nil || *a.ManageNetwork
	a.cfg.hostAccess = a.AllowHostAccess

	if a.MaxSessions < -1 {
		return fmt.Errorf("masque: max_sessions must be 0 (default), -1 (no limit) or positive, got %d", a.MaxSessions)
	}
	a.users = map[string]string{}
	for _, u := range a.Users {
		if err := auth.ValidateUserName(u.Name); err != nil {
			return fmt.Errorf("masque: user %q: %w", u.Name, err)
		}
		if _, dup := a.users[u.Name]; dup {
			return fmt.Errorf("masque: user %q is listed twice", u.Name)
		}
		if err := auth.ValidateHash(u.PasswordHash); err != nil {
			return fmt.Errorf("masque: user %q: %w", u.Name, err)
		}
		a.users[u.Name] = u.PasswordHash
	}

	blocked := routes.DefaultBlocked
	if a.BlockedDestinations != nil {
		blocked = *a.BlockedDestinations
	}
	allowed := routes.Everything().Families(true, a.cfg.ipv6.IsValid())
	for _, b := range blocked {
		p, err := netip.ParsePrefix(b)
		if err != nil {
			return fmt.Errorf("masque: blocked destination %q: %w", b, err)
		}
		allowed.Remove(p)
	}
	// The client pool: reachable only when clients may reach each other,
	// whatever the blocked list says about the space it is in.
	pools := []netip.Prefix{a.cfg.ipv4.Masked()}
	if a.cfg.ipv6.IsValid() {
		pools = append(pools, a.cfg.ipv6.Masked())
	}
	for _, p := range pools {
		if a.AllowClientToClient {
			allowed.Insert(p)
		} else {
			allowed.Remove(p)
		}
	}
	allowed.Insert(netip.PrefixFrom(a.cfg.ipv4.Addr(), 32))
	if a.cfg.ipv6.IsValid() {
		allowed.Insert(netip.PrefixFrom(a.cfg.ipv6.Addr(), 128))
	}
	// Apply this after pool/gateway additions: no configuration may turn
	// link-local destinations into routes between separate HTTP tunnels.
	allowed.Remove(netip.MustParsePrefix("169.254.0.0/16"))
	allowed.Remove(netip.MustParsePrefix("fe80::/10"))
	a.allowed = allowed
	return nil
}

// hostPrefix parses the server's own tunnel address with its prefix.
func hostPrefix(s string, v6 bool) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("masque: %q: %w", s, err)
	}
	if p.Addr().Is6() != v6 || p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("masque: %q is not an IPv%s prefix", s, map[bool]string{false: "4", true: "6"}[v6])
	}
	if p.Addr() == p.Masked().Addr() {
		return netip.Prefix{}, fmt.Errorf("masque: %q must name the server's own address in the prefix, such as 10.89.0.1/24", s)
	}
	for _, linkLocal := range []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("fe80::/10")} {
		if p.Overlaps(linkLocal) {
			return netip.Prefix{}, fmt.Errorf("masque: tunnel pool %q overlaps link-local space", s)
		}
	}
	return p, nil
}

// takeOverHTTP3 removes h3 from the HTTP servers' protocols and notes the
// addresses where it was on, so that this app serves HTTP/3 there instead.
// It runs before any app starts.
func (a *App) takeOverHTTP3() error {
	a.h3Ports = map[int]bool{}
	httpPort := a.httpApp.HTTPPort
	if httpPort == 0 {
		httpPort = caddyhttp.DefaultHTTPPort
	}
	for name, srv := range a.httpApp.Servers {
		protocols := srv.Protocols
		if len(protocols) == 0 {
			protocols = []string{"h1", "h2", "h3"}
		}
		on := slices.Contains(protocols, "h3")
		srv.Protocols = slices.DeleteFunc(slices.Clone(protocols), func(p string) bool { return p == "h3" })
		for i, l := range srv.Listen {
			lnOn := on
			if i < len(srv.ListenProtocols) && srv.ListenProtocols[i] != nil {
				lp := srv.ListenProtocols[i]
				// "" stands for the server's protocols.
				lnOn = slices.Contains(lp, "h3") || on && (len(lp) == 0 || slices.Contains(lp, ""))
				srv.ListenProtocols[i] = slices.DeleteFunc(slices.Clone(lp), func(p string) bool { return p == "h3" })
			}
			if !lnOn || len(srv.TLSConnPolicies) == 0 {
				continue // HTTP/3 needs TLS
			}
			addr, err := caddy.ParseNetworkAddress(l)
			if err != nil {
				return err
			}
			network := map[string]string{"tcp": "udp", "tcp4": "udp4", "tcp6": "udp6"}[addr.Network]
			if network == "" {
				continue
			}
			for off := uint(0); off < addr.PortRangeSize(); off++ {
				port := int(addr.StartPort + off)
				if port == httpPort {
					continue
				}
				a.h3Addrs = append(a.h3Addrs, h3Addr{server: name, network: network, hostport: addr.JoinHostPort(off)})
				a.h3Ports[port] = true
			}
		}
	}
	return nil
}

// Start implements caddy.App. Policy changes on a shared core are staged
// until Caddy commits the configuration; a failed candidate cannot revoke
// sessions belonging to the previous configuration.
func (a *App) Start() error {
	if err := a.core.startOnce(); err != nil {
		return err
	}
	for _, h := range a.h3Addrs {
		srv := a.httpApp.Servers[h.server]
		if err := a.serveHTTP3(h.network, h.hostport, srv, srv.TLSConnPolicies.TLSConfig(a.ctx)); err != nil {
			return err
		}
		a.log.Info("serving HTTP/3 with HTTP datagrams", zap.String("server", h.server), zap.String("addr", h.hostport))
	}
	// Listener setup can fail. Do not irreversibly revoke old sessions
	// until all of this app's fallible startup work has succeeded.
	a.core.activate(a)
	a.log.Info("masque ready", zap.String("interface", a.cfg.iface), zap.Stringer("ipv4", a.cfg.ipv4),
		zap.String("ipv6", func() string {
			if a.cfg.ipv6.IsValid() {
				return a.cfg.ipv6.String()
			}
			return "off"
		}()), zap.Int("users", len(a.users)))
	return nil
}

// Stop implements caddy.App. Caddy swaps its active context only after the
// entire new configuration starts successfully, then stops the old apps.
// That is the commit point for changes that can revoke existing sessions.
func (a *App) Stop() error {
	current, err := caddy.ActiveContext().AppIfConfigured("masque")
	if err == nil {
		if next, ok := current.(*App); ok && next != a && next.core == a.core {
			a.core.commit(next)
		}
	}
	return nil
}

// Cleanup implements caddy.CleanerUpper: the configuration is unloaded, or
// failed to load or start. The tunnel and the HTTP/3 listeners stay if
// another configuration uses them; if this one was in charge of them (it
// failed after starting), the previous one is again.
func (a *App) Cleanup() error {
	for _, l := range a.h3Listeners {
		l.deactivate(a)
	}
	for _, k := range a.listeners {
		_, _ = listeners.Delete(k)
	}
	a.listeners, a.h3Listeners = nil, nil
	if a.core != nil && !a.released {
		a.core.deactivate(a)
		_, _ = cores.Delete(a.coreKey)
		a.released = true
	}
	return nil
}

// Usage pools for state that outlives one configuration.
var (
	cores     = caddy.NewUsagePool()
	listeners = caddy.NewUsagePool()
)

// h3Listener is an HTTP/3 server on one UDP address, shared by the
// configurations that use it, so connections and tunnels outlive reloads.
// The newest configuration that started serves its requests.
type h3Listener struct {
	conn   net.PacketConn
	server *http3.Server

	mu     sync.Mutex
	owners []h3Owner // in start order; the last one serves
	// What the last owner serves with, read for every connection and
	// request.
	handler atomic.Pointer[http.Handler]
	tls     atomic.Pointer[tls.Config]
	config  atomic.Pointer[http3.ConnectionConfig]
}

type h3Owner struct {
	app     *App
	handler http.Handler
	tls     *tls.Config
	config  http3.ConnectionConfig
}

func (l *h3Listener) activate(o h3Owner) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.owners = append(l.owners, o)
	l.apply()
}

func (l *h3Listener) deactivate(a *App) {
	l.mu.Lock()
	defer l.mu.Unlock()
	last := len(l.owners) > 0 && l.owners[len(l.owners)-1].app == a
	l.owners = slices.DeleteFunc(l.owners, func(o h3Owner) bool { return o.app == a })
	if last && len(l.owners) > 0 {
		l.apply()
	}
}

func (l *h3Listener) apply() {
	o := l.owners[len(l.owners)-1]
	l.handler.Store(&o.handler)
	l.tls.Store(o.tls)
	l.config.Store(&o.config)
}

func (l *h3Listener) Destruct() error {
	_ = l.server.Close()
	return l.conn.Close()
}

// quicOverhead is the worst-case QUIC overhead around a DATAGRAM frame in
// a 1-RTT packet, plus the HTTP Datagram's quarter stream ID and context
// ID. The quarter stream ID can occupy eight bytes even on a long-lived
// connection. The configured initial packet size is also capped to the
// supported path size; larger packets still depend on MTU discovery.
const quicOverhead = (1 + 20 + 4 + 16 + 1 + 2) + (8 + 1)

// listenUDP binds with SO_REUSEPORT, as Caddy does: when HTTP/3 moves to
// this app by a reload, Caddy's own socket on the port is still open.
func listenUDP(network, hostport string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		}); err != nil {
			return err
		}
		return serr
	}}
	return lc.ListenPacket(context.Background(), network, hostport)
}

func (a *App) serveHTTP3(network, hostport string, srv *caddyhttp.Server, tlsCfg *tls.Config) error {
	key := "masque-h3/" + network + "/" + hostport
	owner := h3Owner{app: a, handler: srv, tls: tlsCfg, config: http3.ConnectionConfig{
		MaxHeaderBytes: srv.MaxHeaderBytes, IdleTimeout: time.Duration(srv.IdleTimeout),
	}}
	val, loaded, err := listeners.LoadOrNew(key, func() (caddy.Destructor, error) {
		conn, err := listenUDP(network, hostport)
		if err != nil {
			return nil, fmt.Errorf("HTTP/3 on %s: %w", hostport, err)
		}
		l := &h3Listener{conn: conn}
		// Ready before the first packet arrives.
		l.activate(owner)
		base := &tls.Config{
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				c := l.tls.Load()
				if c.GetConfigForClient != nil {
					if picked, err := c.GetConfigForClient(hello); picked != nil || err != nil {
						return picked, err
					}
				}
				return c, nil
			},
			// Encrypted Client Hello is decrypted with the keys of the
			// configuration the server starts with, before it picks one.
			GetEncryptedClientHelloKeys: func(hello *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
				c := l.tls.Load()
				if c.GetEncryptedClientHelloKeys != nil {
					return c.GetEncryptedClientHelloKeys(hello)
				}
				return c.EncryptedClientHelloKeys, nil
			},
		}
		l.server = &http3.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// CONNECT-IP is the only Datagram-capable protocol in the
				// bundled builds. Other requests still follow Caddy's routes,
				// but associated Datagrams abort them (RFC 9297 section 2).
				// Recognized CONNECT-IP requests retain optimistic Datagrams
				// before authentication or the response (RFC 9484 section 7.1).
				if _, definesDatagrams := connectIPRequest(r); !definesDatagrams {
					if err := http3.RejectDatagrams(w); err != nil {
						http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
						return
					}
				}
				// This server announced SETTINGS_H3_DATAGRAM; Caddy's own
				// HTTP/3 server does not.
				r = r.WithContext(context.WithValue(r.Context(), h3DatagramsKey{}, true))
				(*l.handler.Load()).ServeHTTP(w, r)
			}),
			TLSConfig:       http3.ConfigureTLSConfig(base),
			MaxHeaderBytes:  srv.MaxHeaderBytes,
			EnableDatagrams: true,
			GetConnectionConfig: func(*quic.Conn) http3.ConnectionConfig {
				return *l.config.Load()
			},
			// Connections without requests or tunnels are closed, as web
			// servers close idle keep-alive connections.
			IdleTimeout: time.Duration(srv.IdleTimeout),
			QUICConfig: &quic.Config{
				EnableDatagrams:   true,
				InitialPacketSize: uint16(min(max(a.cfg.mtu+quicOverhead, 1200), 1452)),
				MaxIdleTimeout:    60 * time.Second,
			},
		}
		go func() {
			if err := l.server.Serve(conn); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				a.log.Error("HTTP/3 listener stopped", zap.String("addr", hostport), zap.Error(err))
			}
		}()
		return l, nil
	})
	if err != nil {
		return err
	}
	a.listeners = append(a.listeners, key)
	l := val.(*h3Listener)
	a.h3Listeners = append(a.h3Listeners, l)
	if loaded {
		l.activate(owner)
	}
	return nil
}

var (
	_ caddy.App          = (*App)(nil)
	_ caddy.Provisioner  = (*App)(nil)
	_ caddy.CleanerUpper = (*App)(nil)
	_ caddy.Destructor   = (*core)(nil)
	_ caddy.Destructor   = (*h3Listener)(nil)
)
