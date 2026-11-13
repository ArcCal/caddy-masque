package masque

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
	"golang.org/x/net/http2"

	"github.com/ArcCal/caddy-masque/internal/auth"
	"github.com/ArcCal/caddy-masque/internal/proto"
)

// DefaultTemplate is the path and query of the URI Template clients use
// unless configured otherwise (RFC 9484 §3, the default well-known path).
const DefaultTemplate = "/.well-known/masque/ip/{target}/{ipproto}/"

const (
	connectIP = "connect-ip"
	// How long resolving a target host name may take (§4.1).
	dnsTimeout = 5 * time.Second
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler answers CONNECT-IP requests (RFC 9484): extended CONNECT with
// :protocol connect-ip over HTTP/2 and HTTP/3, and GET with Upgrade:
// connect-ip over HTTP/1.1. Every other request, and any CONNECT-IP request
// without TLS or without valid credentials, goes to the next handler.
// Refused extended CONNECT requests retain the site's response body but
// use a non-2xx status: a 2xx response would declare a working IP tunnel.
type Handler struct {
	// Path and query of the URI Template clients are configured with.
	Template string `json:"template,omitempty"`

	tpl *proto.Template
	app *App
	log *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.masque", New: func() caddy.Module { return new(Handler) }}
}

// Provision implements caddy.Provisioner.
func (h *Handler) Provision(ctx caddy.Context) error {
	if h.Template == "" {
		h.Template = DefaultTemplate
	}
	tpl, err := proto.ParsePathTemplate(h.Template)
	if err != nil {
		return err
	}
	h.tpl = tpl
	h.log = ctx.Logger()
	app, err := ctx.AppIfConfigured("masque")
	if errors.Is(err, caddy.ErrNotConfigured) {
		return errors.New("the masque handler needs the masque app: add a masque block to the global options")
	}
	if err != nil {
		return err
	}
	h.app = app.(*App)
	// The connection a request came on, for the TCP settings of tunnels
	// over HTTP/2 (see tunnelKeepAlive); Caddy's way to get it is a hook
	// registered while provisioning.
	if srv, ok := ctx.Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server); ok {
		srv.RegisterConnContext(func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, c)
		})
	}
	return nil
}

// connKey is the context key of the connection a request came on.
type connKey struct{}

// request describes a CONNECT-IP request whatever the HTTP version.
type request struct {
	transport string
	http1     bool
	// It meets the requirements of its HTTP version (RFC 9484 §4.2, §4.4).
	wellFormed bool
}

// connectIPRequest recognizes a request for the connect-ip upgrade token.
func connectIPRequest(r *http.Request) (request, bool) {
	switch r.ProtoMajor {
	case 3:
		// quic-go puts :protocol into Proto for extended CONNECT.
		return request{transport: "HTTP/3", wellFormed: true}, r.Method == http.MethodConnect && r.Proto == connectIP
	case 2:
		return request{transport: "HTTP/2", wellFormed: true}, r.Method == http.MethodConnect && r.Header.Get(":protocol") == connectIP
	default:
		// CONNECT-IP uses Upgrade only with HTTP/1.1 (RFC 9484 §4.2).
		// An HTTP/1.0 Upgrade field must be ignored (RFC 9110 §7.8).
		if r.ProtoMajor != 1 || r.ProtoMinor != 1 {
			return request{}, false
		}
		// RFC 9484 §4.2: GET with "Connection: Upgrade" and "Upgrade:
		// connect-ip". Any request to upgrade to connect-ip is one; the
		// others are malformed.
		upgrade := false
		for _, v := range r.Header.Values("Upgrade") {
			for _, t := range strings.Split(v, ",") {
				upgrade = upgrade || strings.EqualFold(strings.TrimSpace(t), connectIP)
			}
		}
		wants := false
		for _, v := range r.Header.Values("Connection") {
			for _, t := range strings.Split(v, ",") {
				wants = wants || strings.EqualFold(strings.TrimSpace(t), "upgrade")
			}
		}
		return request{transport: "HTTP/1.1", http1: true, wellFormed: r.Method == http.MethodGet && wants}, upgrade
	}
}

// classicConnect recognizes CONNECT without an upgrade token (RFC 9110
// Section 9.3.6), as opposed to extended CONNECT for another protocol.
func classicConnect(r *http.Request) bool {
	if r.Method != http.MethodConnect {
		return false
	}
	switch r.ProtoMajor {
	case 3:
		return r.Proto == "HTTP/3.0"
	case 2:
		return r.Header.Get(":protocol") == ""
	default:
		return true
	}
}

// expectsContinue reports a 100-continue expectation (RFC 9110 Section
// 10.1.1).
func expectsContinue(r *http.Request) bool {
	for _, v := range r.Header.Values("Expect") {
		for _, e := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(e), "100-continue") {
				return true
			}
		}
	}
	return false
}

// carriesContent reports header fields for content, which RFC 9297 §3.2
// forbids on messages that use the Capsule Protocol.
func carriesContent(r *http.Request) bool {
	for _, k := range []string{"Content-Length", "Content-Type", "Transfer-Encoding"} {
		if _, ok := r.Header[k]; ok {
			return true
		}
	}
	return r.ContentLength > 0 || len(r.TransferEncoding) > 0
}

// rejection is an answer to an authenticated request that cannot be served.
type rejection struct {
	status int
	// Proxy error type (RFC 9209 §2.3) for a Proxy-Status field, which RFC
	// 9484 §4.1 asks for when resolving the target fails.
	proxyError string
	// The request is malformed, not only refused.
	malformed bool
}

// malformed answers a malformed request: 400, then for HTTP/3 the stream
// error H3_MESSAGE_ERROR (RFC 9114 §4.1.2), sent with STOP_SENDING so that
// the response still arrives. HTTP/2 uses PROTOCOL_ERROR (RFC 9113 §8.1.1).
var malformed = rejection{status: http.StatusBadRequest, malformed: true}

func (h *Handler) reject(w http.ResponseWriter, r *http.Request, rej rejection) error {
	if rej.proxyError != "" {
		w.Header().Set("Proxy-Status", "caddy-masque; error="+rej.proxyError)
	}
	if r.ProtoMajor < 2 && r.Method == http.MethodConnect {
		// A CONNECT with "Upgrade: connect-ip" (RFC 9931 Section 8).
		w.Header().Set("Connection", "close")
	}
	w.WriteHeader(rej.status)
	if rej.malformed && r.ProtoMajor == 2 {
		// Flush the optional 400 before the mandatory stream error.
		_ = http.NewResponseController(w).Flush()
		return http2.ResetStream(w, http2.ErrCodeProtocol)
	}
	if rej.malformed && r.ProtoMajor == 3 {
		_ = http.NewResponseController(w).Flush()
		if s, ok := unwrapStreamer(w); ok {
			str := s.HTTPStream()
			str.CancelRead(h3MessageError)
			_ = str.Close()
		}
	}
	return nil
}

// serveRefusal keeps the site's response for requests that do not establish
// a tunnel. Unlike HTTP/1.1 Upgrade, any 2xx extended CONNECT response means
// success (RFC 9484 §4.5); ordinary content must therefore have an error
// status. Preserve a site's existing error or redirect status and stream its
// body without buffering it.
func serveRefusal(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.ProtoMajor < 2 {
		return next.ServeHTTP(w, r)
	}
	return serveWithoutSuccess(w, r, next)
}

// refuseConnect answers a classic CONNECT request, which this module never
// serves, as serveRefusal does for every HTTP version: any 2xx response
// would announce a tunnel (RFC 9110 Section 9.3.6). An HTTP/1.x connection
// then closes, so no further request is read from it (RFC 9112 as updated
// by RFC 9931 Section 8).
func refuseConnect(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.ProtoMajor < 2 {
		w.Header().Set("Connection", "close")
	}
	return serveWithoutSuccess(w, r, next)
}

func serveWithoutSuccess(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	rw := &refusalResponseWriter{ResponseWriter: w}
	err := next.ServeHTTP(rw, r)
	if !rw.wroteHeader {
		status := http.StatusNotFound
		if err != nil {
			// Caddy invokes handle_errors with its original writer, outside
			// this wrapper. Commit an error status before returning so its
			// error page cannot turn the refusal into a successful tunnel.
			status = http.StatusInternalServerError
			var he caddyhttp.HandlerError
			if errors.As(err, &he) && he.StatusCode >= 300 && he.StatusCode <= 599 {
				status = he.StatusCode
			}
		}
		rw.WriteHeader(status)
	}
	return err
}

type refusalResponseWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

func (w *refusalResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *refusalResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	if status >= 200 && status < 300 {
		status = http.StatusNotFound
	}
	if status >= 200 {
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *refusalResponseWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusNotFound)
	}
	return w.ResponseWriter.Write(p)
}

func (w *refusalResponseWriter) FlushError() error {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusNotFound)
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *refusalResponseWriter) Flush() { _ = w.FlushError() }

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	h.advertiseHTTP3(w, r)
	req, ok := connectIPRequest(r)
	if !ok {
		if classicConnect(r) {
			return refuseConnect(w, r, next)
		}
		return next.ServeHTTP(w, r)
	}
	// These requirements apply even when the proxy will refuse the
	// request, including an anonymous HTTP/1.1 upgrade (RFC 9484 §4.2).
	if !req.wellFormed || carriesContent(r) {
		return h.reject(w, r, malformed)
	}
	// IP proxying runs over TLS or QUIC only (RFC 9484 §4): without it, the
	// request cannot establish a tunnel.
	if r.TLS == nil {
		h.log.Debug("CONNECT-IP request without TLS", zap.String("remote", r.RemoteAddr))
		return serveRefusal(w, r, next)
	}
	vars, ok := h.tpl.Match(r.URL.RequestURI())
	if !ok {
		return serveRefusal(w, r, next)
	}
	c := h.app.core
	remote := r.RemoteAddr
	// Credentials verified recently get in at once. Otherwise a client that
	// keeps failing is not checked again for a while; its request goes to
	// the site like any without credentials.
	client, haveClient := clientAddr(r)
	authorization := r.Header.Get("Authorization")
	_, _, hasCredentials := auth.ParseBasic(authorization)
	user, ok := c.auth.Remembered(authorization)
	if !ok && hasCredentials && haveClient && c.loginLimit.Blocked(client) {
		c.counters.throttled.Add(1)
		h.log.Debug("too many failed logins, not checking credentials", zap.String("remote", remote))
		return serveRefusal(w, r, next)
	}
	if !ok {
		var err error
		user, ok, err = c.auth.Verify(r.Context(), authorization, client)
		if errors.Is(err, auth.ErrBusy) {
			// Like any web server under more load than it can take; whether
			// the credentials were valid is not known.
			return h.reject(w, r, rejection{status: http.StatusServiceUnavailable})
		}
		if err != nil {
			return nil // the request was cancelled
		}
	}
	if !ok {
		if haveClient && hasCredentials {
			c.loginLimit.Fail(client)
		}
		c.counters.authFailures.Add(1)
		if name, _, has := auth.ParseBasic(authorization); has {
			if len(name) > 64 {
				name = name[:64]
			}
			// zap quotes the client's text, so it cannot forge log lines.
			if ok, suppressed := c.authLog.allow(); ok {
				h.log.Info("authentication failed", zap.String("remote", remote), zap.String("user", name),
					zap.String("transport", req.transport), zap.Int("failures_not_logged", suppressed))
			}
		} else {
			h.log.Debug("CONNECT-IP request without credentials", zap.String("remote", remote), zap.String("transport", req.transport))
		}
		return serveRefusal(w, r, next)
	}
	log := h.log.With(zap.String("user", user.Name), zap.String("remote", remote), zap.String("transport", req.transport))
	rejectLogged := func(rej rejection) error {
		log.Info("rejected request", zap.Int("status", rej.status), zap.String("error", rej.proxyError))
		return h.reject(w, r, rej)
	}
	if req.http1 && expectsContinue(r) {
		// RFC 9110 Section 7.8 requires 100 (Continue) before 101. Like
		// masque-vpn, whose HTTP library cannot send it, refuse with 417
		// before reserving addresses; the client may repeat the request
		// without the expectation (RFC 9110 Section 10.1.1).
		return rejectLogged(rejection{status: http.StatusExpectationFailed})
	}
	// Omitted optional variables mean wildcard scope (§4.6). Empty or
	// invalidly encoded values remain present and fail parsing below.
	value := func(name string) string {
		if v, has := vars[name]; has {
			return v
		}
		return "*"
	}
	// Values that do not meet RFC 9484 §4.6 make it malformed too (§4.1).
	target, err1 := proto.ParseTarget(value("target"))
	ipproto, err2 := proto.ParseIPProtocol(value("ipproto"))
	if err1 != nil || err2 != nil {
		return rejectLogged(malformed)
	}
	sc, rej := h.resolveScope(r.Context(), target, ipproto)
	if rej != nil {
		return rejectLogged(*rej)
	}
	l := c.acquire(r.Context(), user, sc.routes.HasIPv4(), sc.routes.HasIPv6())
	if l == nil {
		if !c.auth.IsCurrent(user) {
			return serveRefusal(w, r, next)
		}
		if c.tooManySessions(user) {
			return rejectLogged(rejection{status: http.StatusTooManyRequests})
		}
		return rejectLogged(rejection{status: http.StatusServiceUnavailable})
	}
	defer l.release()

	tun, responseStarted, err := h.accept(w, r, req, l.handle)
	if err != nil {
		log.Debug("could not start the tunnel", zap.Error(err))
		if !responseStarted {
			return rejectLogged(rejection{status: http.StatusServiceUnavailable})
		}
		return nil
	}
	c.running.Add(1)
	defer c.running.Add(-1)
	s := newSession(c, l, sc, tun, log)
	c.counters.sessionsStarted.Add(1)
	log.Info("session started", zap.Any("addresses", l.addrs))
	// The request's context ends with the stream; a hijacked HTTP/1.1
	// connection is no longer watched by the server, and ends with the
	// tunnel itself. Removing the server revokes every session.
	ctx := r.Context()
	if req.http1 {
		ctx = c.ctx
	} else if srv, ok := ctx.Value(http.ServerContextKey).(*http.Server); ok {
		c.endOnExit(srv)
	}
	why := s.run(ctx)
	log.Info("session ended", zap.String("why", why), zap.Stringer("stats", s.stats))
	return nil
}

// clientAddr is the address of the client, as Caddy works it out (behind
// trusted proxies, the one they report), else the connection's.
func clientAddr(r *http.Request) (netip.Addr, bool) {
	if v, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); ok {
		if a, err := netip.ParseAddr(v); err == nil {
			return a, true
		}
	}
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr(), true
	}
	return netip.Addr{}, false
}

// advertiseHTTP3 adds the Alt-Svc header field (RFC 7838) Caddy adds when
// it serves HTTP/3 itself, so the site looks the same to visitors.
func (h *Handler) advertiseHTTP3(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor >= 3 {
		return
	}
	local, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if local == nil {
		return
	}
	ap, err := netip.ParseAddrPort(local.String())
	if err != nil || !h.app.h3Ports[int(ap.Port())] {
		return
	}
	w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%d"; ma=2592000`, ap.Port()))
}

// resolveScope finds the destinations of the requested target, resolving a
// host name (§4.1), and narrows them to those allowed (§4.6).
func (h *Handler) resolveScope(ctx context.Context, target proto.Target, ipproto proto.IPProtocol) (scope, *rejection) {
	if !ipproto.Any && proto.IsIPv6ExtensionHeader(ipproto.Number) {
		// §4.8: proxies may reject scoping to extension header numbers.
		return scope{}, &rejection{status: http.StatusBadRequest}
	}
	var requested []netip.Prefix
	switch {
	case target.Any:
		requested = anyDestination
	case target.Host == "":
		requested = []netip.Prefix{target.Prefix}
	default:
		// The proxy resolves the name before answering and advertises
		// routes for every address it can reach (§4.1, §4.6).
		ctx, cancel := context.WithTimeout(ctx, dnsTimeout)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", target.Host)
		if err != nil {
			// RFC 9209 Section 2.3: 504 for dns_timeout, 502 for dns_error.
			if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
				return scope{}, &rejection{status: http.StatusGatewayTimeout, proxyError: "dns_timeout"}
			}
			return scope{}, &rejection{status: http.StatusBadGateway, proxyError: "dns_error"}
		}
		for _, a := range addrs {
			a = a.Unmap()
			requested = append(requested, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	sc := newScope(*h.app.core.allowed.Load(), requested, ipproto.RouteProtocol())
	if sc.routes.IsEmpty() {
		// Not authorized for any destination in the scope (§4.6).
		return scope{}, &rejection{status: http.StatusForbidden}
	}
	return sc, nil
}

func isTimeout(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsTimeout
}

// h3DatagramsKey marks requests served by this module's HTTP/3 server,
// which announces SETTINGS_H3_DATAGRAM.
type h3DatagramsKey struct{}

// accept sends the successful response and returns the tunnel over the
// request stream. The tunnel bypasses Caddy's idle-timeout wrappers and
// clears the server's read and write deadlines: a tunnel lasts as long as
// its client keeps the stream open (RFC 9484 §4). The boolean tells whether
// the response has started, so an earlier failure can still get an error
// status rather than an implicit successful response.
func (h *Handler) accept(w http.ResponseWriter, r *http.Request, req request, handle *sessionHandle) (tunnel, bool, error) {
	if req.http1 {
		// RFC 9484 §4.3.
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return nil, false, err
		}
		_ = conn.SetDeadline(time.Time{})
		h.tuneConn(conn)
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-ip\r\nCapsule-Protocol: ?1\r\n\r\n")
		if err := brw.Flush(); err != nil {
			conn.Close()
			return nil, true, err
		}
		closeConn := func(ending) { conn.Close() }
		return &streamTunnel{
			reader:        newCapsuleReader(io.MultiReader(bufferedOf(brw.Reader), conn)),
			capsuleWriter: capsuleWriter{w: conn},
			stopFn:        closeConn,
			forceFn:       func() {},
		}, true, nil
	}
	raw := innermost(w)
	rc := http.NewResponseController(raw)
	if r.ProtoMajor == 3 {
		s, ok := raw.(http3.HTTPStreamer)
		if !ok {
			return nil, false, errors.New("no HTTP/3 stream behind the response writer")
		}
		// HTTP Datagrams go in QUIC DATAGRAM frames only if both sides
		// announced SETTINGS_H3_DATAGRAM (RFC 9297 §2.1.1): this module's
		// HTTP/3 server does, Caddy's own does not. Otherwise they go in
		// DATAGRAM capsules (§3.5).
		quicDatagrams := false
		ours, _ := r.Context().Value(h3DatagramsKey{}).(bool)
		if st, ok := raw.(http3.Settingser); ok && ours {
			// QUIC streams can arrive independently. A delayed control
			// stream must not permanently select capsules and leave later
			// negotiated QUIC Datagrams unread. Admission already holds a
			// lease, bounded by the per-user session limit.
			select {
			case <-st.ReceivedSettings():
				quicDatagrams = st.Settings().EnableDatagrams
			case <-r.Context().Done():
				return nil, false, r.Context().Err()
			case <-h.app.core.ctx.Done():
				return nil, false, h.app.core.ctx.Err()
			case <-handle.revoked:
				return nil, false, errors.New("session revoked before receiving HTTP/3 SETTINGS")
			case <-handle.rescope:
				return nil, false, errors.New("policy changed before receiving HTTP/3 SETTINGS")
			}
			// Prefer cancellation if it raced with receiving SETTINGS.
			select {
			case <-r.Context().Done():
				return nil, false, r.Context().Err()
			case <-h.app.core.ctx.Done():
				return nil, false, h.app.core.ctx.Err()
			case <-handle.revoked:
				return nil, false, errors.New("session revoked before accepting the tunnel")
			case <-handle.rescope:
				return nil, false, errors.New("policy changed before accepting the tunnel")
			default:
			}
		}
		// Success headers must not appear on a cancelled pending request.
		w.Header()["Content-Type"] = nil
		w.Header().Set("Capsule-Protocol", "?1")
		w.WriteHeader(http.StatusOK)
		if err := rc.Flush(); err != nil {
			return nil, true, err
		}
		str := s.HTTPStream()
		_ = str.SetReadDeadline(time.Time{})
		_ = str.SetWriteDeadline(time.Time{})
		return newH3Tunnel(str, quicDatagrams), true, nil
	}
	// No Content-Type sniffing: the response has no content (RFC 9297 §3.2).
	w.Header()["Content-Type"] = nil
	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		return nil, true, err
	}
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})
	conn, _ := r.Context().Value(connKey{}).(net.Conn)
	h.tuneConn(conn)
	body := rawBody(r.Body)
	// Forced shutdown wakes blocked writers; aborts use the stream error
	// for their reason: PROTOCOL_ERROR for malformed capsules (RFC 9297
	// §3.3, RFC 9113 §8.1.1), CANCEL otherwise.
	reset := func() { _ = rc.SetWriteDeadline(time.Now()) }
	return &streamTunnel{
		reader:        newCapsuleReader(body),
		capsuleWriter: capsuleWriter{w: raw, flush: rc.Flush},
		stopFn: func(how ending) {
			switch how {
			case endMalformed:
				_ = http2.ResetStream(raw, http2.ErrCodeProtocol)
			case endCancel:
				_ = http2.ResetStream(raw, http2.ErrCodeCancel)
			}
			_ = body.Close()
		},
		forceFn: reset,
	}, true, nil
}

// tuneConn gives the connection of a tunnel over TCP the settings of
// tunnelKeepAlive. Over HTTP/2 the connection's other streams get them
// too, also after the tunnel ends, which does them no harm.
func (h *Handler) tuneConn(c net.Conn) {
	if c == nil {
		h.log.Debug("connection of the tunnel unknown: Caddy's keepalive settings apply")
		return
	}
	if err := tuneTunnelConn(c); err != nil {
		h.log.Debug("could not shorten the TCP timeouts of the tunnel", zap.Error(err))
	}
}

// bufferedOf returns what the HTTP server read past the request headers.
func bufferedOf(br *bufio.Reader) io.Reader {
	n := br.Buffered()
	if n == 0 {
		return strings.NewReader("")
	}
	b, _ := br.Peek(n)
	return strings.NewReader(string(b))
}

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
