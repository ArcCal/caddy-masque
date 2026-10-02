package masque

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/ArcCal/caddy-masque/internal/auth"
	"github.com/ArcCal/caddy-masque/internal/hostnet"
	"github.com/ArcCal/caddy-masque/internal/ip"
	"github.com/ArcCal/caddy-masque/internal/pool"
	"github.com/ArcCal/caddy-masque/internal/routes"
)

// Packets queued per session toward its client before new ones are dropped.
const queueLen = 1024

// A packet that waited longer than this in the queue is dropped instead of
// sent: when the path is the bottleneck, the queue stays short and the
// connections inside the tunnel slow down (as on a link with a sane buffer)
// instead of seeing seconds of delay.
const maxQueueDelay = 200 * time.Millisecond

// queued is a packet toward the client, with the time it was queued.
type queued struct {
	pkt []byte
	at  time.Time
}

// A user who reconnects within this time gets the previous addresses back
// if they are still free, so connections through the tunnel survive a brief
// outage; longer gaps get fresh addresses (RFC 9484 §11).
const reconnectGrace = 120 * time.Second

// tunnelConfig are the settings the core is built from; changing them
// needs a restart.
type tunnelConfig struct {
	iface  string
	ipv4   netip.Prefix
	ipv6   netip.Prefix
	mtu    int
	manage bool
}

// logLimit lets through at most max events a minute and counts the rest,
// so a flood (made-up credentials, a failing device) cannot flood the log.
type logLimit struct {
	mu         sync.Mutex
	max        int
	window     time.Time
	n          int
	suppressed int
}

// allow reports whether to log an event, and how many were suppressed
// since the last one logged.
func (l *logLimit) allow() (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now := time.Now(); now.Sub(l.window) >= time.Minute {
		l.window, l.n = now, 0
	}
	if l.n >= l.max {
		l.suppressed++
		return false, 0
	}
	l.n++
	s := l.suppressed
	l.suppressed = 0
	return true, s
}

// device is the host's side of the tunnel: the TUN device (replaced in
// tests).
type device interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

// The host network, replaced in tests.
var (
	openDevice = func(cfg hostnet.Config) (device, error) {
		n, err := hostnet.Open(cfg)
		if err != nil {
			return nil, err
		}
		return n, nil
	}
	forgetConntrack = hostnet.Forget
)

// core is the state shared by every configuration Caddy loads: the TUN
// device, the address pool and the sessions. It lives in a usage pool, so a
// config reload keeps the tunnel and its sessions.
type core struct {
	cfg  tunnelConfig
	log  *zap.Logger
	net  device
	auth *auth.Authenticator
	// Destinations any client may reach; scoped requests narrow it.
	allowed atomic.Pointer[routes.Set]
	// The configuration turned the IPv6 MTU probe off.
	noMTUProbe atomic.Bool
	gw4        netip.Addr
	gw6        netip.Addr

	// Lock order: sessMu, then poolMu.
	sessMu   sync.RWMutex
	sessions map[netip.Addr]*sessionHandle
	poolMu   sync.Mutex
	pool     *pool.Pool
	recent   map[string]recentLease // by user name, under poolMu
	nextID   atomic.Uint64
	// Session handlers that have not returned.
	running atomic.Int64
	// Logging of failed logins and device errors.
	authLog, deviceLog logLimit
	// Deletes connection tracking entries (replaced in tests).
	forget func([]netip.Prefix) (int, error)

	startOnce func() error
	// The started configurations using the core, in start order; the
	// last one's users and allowed destinations apply.
	ownersMu sync.Mutex
	owners   []*App
	// HTTP servers whose shutdown is watched (endOnExit).
	watched sync.Map

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

type recentLease struct {
	addrs []netip.Addr
	at    time.Time
}

// sessionHandle is how packets from the network reach a session.
type sessionHandle struct {
	id       uint64
	user     auth.User
	toClient chan queued
	revoked  chan struct{}
	why      string // set before revoked closes
	// Signalled when the allowed destinations change.
	rescope chan struct{}
	once    sync.Once
}

func (h *sessionHandle) revoke(why string) {
	h.once.Do(func() {
		h.why = why
		close(h.revoked)
	})
}

func newCore(cfg tunnelConfig, log *zap.Logger) (*core, error) {
	c := &core{
		cfg:       cfg,
		log:       log,
		auth:      auth.New(),
		gw4:       cfg.ipv4.Addr(),
		sessions:  map[netip.Addr]*sessionHandle{},
		pool:      pool.New(cfg.ipv4, cfg.ipv6),
		recent:    map[string]recentLease{},
		forget:    forgetConntrack,
		authLog:   logLimit{max: 60},
		deviceLog: logLimit{max: 1},
		done:      make(chan struct{}),
	}
	if cfg.ipv6.IsValid() {
		c.gw6 = cfg.ipv6.Addr()
	}
	c.auth.OnBusy = func() {
		log.Warn("too many requests waiting for password verification; answering new ones with 503 (a flood of requests with made-up credentials?)")
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	// Every configuration sharing the core starts it; it opens once.
	c.startOnce = sync.OnceValue(c.start)
	return c, nil
}

// start opens the host network and starts reading from it.
func (c *core) start() error {
	n, err := openDevice(hostnet.Config{Interface: c.cfg.iface, IPv4: c.cfg.ipv4, IPv6: c.cfg.ipv6, MTU: c.cfg.mtu,
		Manage: c.cfg.manage, Log: func(s string) { c.log.Info(s) }})
	if err != nil {
		return err
	}
	// An earlier run's NAT state outlives it; its replies must not reach
	// whoever gets those addresses now.
	prefixes := []netip.Prefix{c.cfg.ipv4.Masked()}
	if c.cfg.ipv6.IsValid() {
		prefixes = append(prefixes, c.cfg.ipv6.Masked())
	}
	deleted, err := c.forget(prefixes)
	if err != nil {
		n.Close()
		return fmt.Errorf("deleting the connection tracking entries of the tunnel addresses: %w", err)
	}
	if deleted > 0 {
		c.log.Info("deleted connection tracking entries of the tunnel addresses (left by an earlier run)", zap.Int("count", deleted))
	}
	c.attach(n)
	return nil
}

// attach starts handing packets from the device to the sessions.
func (c *core) attach(d device) {
	c.net = d
	go c.readNetwork()
}

// Destruct implements caddy.Destructor: the last configuration using the
// core is gone.
func (c *core) Destruct() error {
	c.cancel()
	c.revokeAll("server stopped")
	if c.net != nil {
		c.net.Close()
		<-c.done
	}
	return nil
}

// readNetwork hands packets from the TUN device to the session that owns
// their destination address.
func (c *core) readNetwork() {
	defer close(c.done)
	buf := make([]byte, 65535)
	for {
		n, err := c.net.Read(buf)
		if err != nil {
			if c.ctx.Err() != nil {
				return
			}
			if ok, suppressed := c.deviceLog.allow(); ok {
				c.log.Warn("TUN read failed", zap.Error(err), zap.Int("failures_not_logged", suppressed))
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		h, ok := ip.Parse(buf[:n])
		if !ok {
			continue
		}
		c.sessMu.RLock()
		s := c.sessions[h.Dst]
		c.sessMu.RUnlock()
		if s == nil {
			continue
		}
		pkt := make([]byte, 1+h.TotalLen) // context ID 0, then the packet
		copy(pkt[1:], buf[:h.TotalLen])
		select {
		case s.toClient <- queued{pkt: pkt, at: time.Now()}:
		default: // queue full: dropped, as a network would
		}
	}
}

// toNetwork writes a packet from a client to the TUN device; the kernel
// decrements the TTL when it forwards it.
func (c *core) toNetwork(pkt []byte) {
	if _, err := c.net.Write(pkt); err != nil {
		c.log.Debug("TUN write failed", zap.Error(err))
	}
}

func (c *core) gateway(v6 bool) netip.Addr {
	if v6 {
		return c.gw6
	}
	return c.gw4
}

// setUsers installs a new user list and ends the sessions of users who were
// removed or whose password changed. Registration takes the same lock and
// checks authentication again under it, so a stale login cannot slip past.
func (c *core) setUsers(users map[string]string) {
	c.sessMu.Lock()
	defer c.sessMu.Unlock()
	c.auth.Replace(users)
	for addr, s := range c.sessions {
		if !c.auth.IsCurrent(s.user) {
			c.log.Info("ending session: user removed or password changed", zap.String("user", s.user.Name), zap.Stringer("address", addr))
			delete(c.sessions, addr)
			s.revoke("user removed or password changed")
		}
	}
}

// activate applies a configuration that started.
func (c *core) activate(a *App) {
	c.ownersMu.Lock()
	defer c.ownersMu.Unlock()
	c.owners = append(c.owners, a)
	c.apply(a)
}

// deactivate drops a configuration; if it was the one applied (it failed
// after starting), the previous one applies again.
func (c *core) deactivate(a *App) {
	c.ownersMu.Lock()
	defer c.ownersMu.Unlock()
	last := len(c.owners) > 0 && c.owners[len(c.owners)-1] == a
	c.owners = slices.DeleteFunc(c.owners, func(o *App) bool { return o == a })
	if last && len(c.owners) > 0 {
		c.apply(c.owners[len(c.owners)-1])
	}
}

func (c *core) apply(a *App) {
	c.setAllowed(a.allowed)
	c.noMTUProbe.Store(a.MTUProbe != nil && !*a.MTUProbe)
	c.setUsers(a.users)
}

// setAllowed installs the destinations clients may reach; running sessions
// narrow them to their scope and advertise the new routes.
func (c *core) setAllowed(allowed routes.Set) {
	old := c.allowed.Swap(&allowed)
	if old == nil || old.Equal(allowed) {
		return
	}
	c.sessMu.RLock()
	defer c.sessMu.RUnlock()
	for _, s := range c.sessions {
		select {
		case s.rescope <- struct{}{}:
		default: // already pending
		}
	}
}

// revokeAll ends every session.
func (c *core) revokeAll(why string) {
	c.sessMu.Lock()
	defer c.sessMu.Unlock()
	for _, s := range c.sessions {
		s.revoke(why)
	}
}

// endOnExit ends the sessions when Caddy exits and shuts the HTTP server
// down: a server waits for its requests to finish, and tunnels do not
// finish on their own. A configuration reload also shuts the old servers
// down; their tunnels carry on until the clients end them.
func (c *core) endOnExit(srv *http.Server) {
	if _, seen := c.watched.LoadOrStore(srv, true); seen {
		return
	}
	srv.RegisterOnShutdown(func() {
		c.watched.Delete(srv)
		if caddy.Exiting() {
			c.revokeAll("server shutting down")
		}
	})
}

// lease is a session's addresses, reserved and registered for packet
// routing; release undoes both.
type lease struct {
	core   *core
	handle *sessionHandle
	addrs  []netip.Addr
}

// acquire reserves addresses of the wanted families for a user: the user's
// own recent ones if they are still free, else fresh ones. An address
// another session used is handed out only after its connection tracking
// entries are deleted. nil when no address is free, deleting fails, or the
// user is no longer current.
func (c *core) acquire(ctx context.Context, user auth.User, v4, v6 bool) *lease {
	var addrs []netip.Addr
	var used []netip.Prefix
	c.poolMu.Lock()
	mine := c.recent[user.Name]
	delete(c.recent, user.Name)
	if time.Since(mine.at) >= reconnectGrace {
		mine.addrs = nil
	}
	for _, fam := range []struct{ wanted, v6 bool }{{v4, false}, {v6, true}} {
		if !fam.wanted {
			continue
		}
		claimed := false
		for _, a := range mine.addrs {
			if a.Is6() == fam.v6 && c.pool.Claim(a) {
				addrs = append(addrs, a) // the user's own address, with its connections
				claimed = true
				break
			}
		}
		if claimed {
			continue
		}
		a, usedBefore, ok := c.pool.Allocate(fam.v6)
		if !ok {
			for _, x := range addrs {
				c.pool.Release(x)
			}
			c.poolMu.Unlock()
			return nil
		}
		// Someone else's address now: no longer theirs to reclaim.
		for name, r := range c.recent {
			kept := r.addrs[:0:0]
			for _, x := range r.addrs {
				if x != a {
					kept = append(kept, x)
				}
			}
			r.addrs = kept
			c.recent[name] = r
		}
		if usedBefore {
			used = append(used, netip.PrefixFrom(a, a.BitLen()))
		}
		addrs = append(addrs, a)
	}
	c.poolMu.Unlock()

	releaseAll := func() {
		c.poolMu.Lock()
		for _, x := range addrs {
			c.pool.Release(x)
		}
		c.poolMu.Unlock()
	}
	if len(used) > 0 {
		n, err := c.forget(used)
		if err != nil {
			// Replies meant for the address's earlier user could reach
			// this one: do not hand it out.
			c.log.Error("could not delete the connection tracking entries of a reused address, not assigning it",
				zap.Any("addresses", used), zap.Error(err))
			releaseAll()
			return nil
		}
		c.log.Debug("cleared connection tracking for reused addresses", zap.Any("addresses", used), zap.Int("deleted", n))
	}
	h := &sessionHandle{id: c.nextID.Add(1), user: user, toClient: make(chan queued, queueLen), revoked: make(chan struct{}),
		rescope: make(chan struct{}, 1)}
	c.sessMu.Lock()
	if !c.auth.IsCurrent(user) {
		c.sessMu.Unlock()
		releaseAll()
		return nil
	}
	for _, a := range addrs {
		c.sessions[a] = h
	}
	c.sessMu.Unlock()
	return &lease{core: c, handle: h, addrs: addrs}
}

func (l *lease) owns(a netip.Addr) bool {
	for _, x := range l.addrs {
		if x == a {
			return true
		}
	}
	return false
}

func (l *lease) hasIPv6() bool {
	for _, x := range l.addrs {
		if x.Is6() {
			return true
		}
	}
	return false
}

func (l *lease) release() {
	c := l.core
	c.sessMu.Lock()
	for _, a := range l.addrs {
		if s := c.sessions[a]; s != nil && s.id == l.handle.id {
			delete(c.sessions, a)
		}
	}
	c.sessMu.Unlock()
	// Both under the pool's lock, so an address cannot go to someone else
	// before it is noted as this user's to reclaim (and then dropped from
	// that note).
	c.poolMu.Lock()
	for _, a := range l.addrs {
		c.pool.Release(a)
	}
	c.recent[l.handle.user.Name] = recentLease{addrs: l.addrs, at: time.Now()}
	c.poolMu.Unlock()
}
