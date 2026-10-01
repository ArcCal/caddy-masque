package masque

// Feasibility prototype: answers CONNECT-IP over HTTP/3 (with HTTP
// datagrams), HTTP/2 and HTTP/1.1 with an address and a route, so that the
// client brings its tunnel up. Replaced by the real implementation.

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(App{})
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("masque", parseHandler)
	httpcaddyfile.RegisterGlobalOption("masque", parseApp)
}

// App serves HTTP/3 with HTTP datagrams for the HTTP servers, on their own
// ports and with their certificates; Caddy's own HTTP/3 has no datagrams.
type App struct {
	ctx     caddy.Context
	log     *zap.Logger
	servers []*http3.Server
}

func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "masque", New: func() caddy.Module { return new(App) }}
}

func (a *App) Provision(ctx caddy.Context) error {
	a.ctx = ctx
	a.log = ctx.Logger()
	return nil
}

func (a *App) Start() error {
	appIface, err := a.ctx.App("http")
	if err != nil {
		return err
	}
	httpApp := appIface.(*caddyhttp.App)
	for name, srv := range httpApp.Servers {
		if len(srv.TLSConnPolicies) == 0 {
			continue
		}
		for _, p := range srv.Protocols {
			if p == "h3" {
				return fmt.Errorf("server %s: set its protocols to h1 h2; the masque app serves HTTP/3", name)
			}
		}
		tlsCfg := http3.ConfigureTLSConfig(srv.TLSConnPolicies.TLSConfig(a.ctx))
		for _, l := range srv.Listen {
			addr, err := caddy.ParseNetworkAddress(l)
			if err != nil {
				return err
			}
			udpAddr := fmt.Sprintf("%s:%d", addr.Host, addr.StartPort)
			pc, err := net.ListenPacket("udp", udpAddr)
			if err != nil {
				return fmt.Errorf("HTTP/3 on %s: %w", udpAddr, err)
			}
			h3 := &http3.Server{Handler: srv, TLSConfig: tlsCfg, EnableDatagrams: true,
				QUICConfig: &quic.Config{EnableDatagrams: true}}
			a.servers = append(a.servers, h3)
			go func() { _ = h3.Serve(pc) }()
			a.log.Info("serving HTTP/3 with datagrams", zap.String("server", name), zap.String("addr", udpAddr))
		}
	}
	return nil
}

func (a *App) Stop() error {
	for _, s := range a.servers {
		_ = s.Close()
	}
	return nil
}

func parseApp(d *caddyfile.Dispenser, _ any) (any, error) {
	return httpcaddyfile.App{Name: "masque", Value: caddyconfig.JSON(App{}, nil)}, nil
}

// Handler answers CONNECT-IP requests; anything else goes to the next handler.
type Handler struct{}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.masque", New: func() caddy.Module { return new(Handler) }}
}

func parseHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	return new(Handler), nil
}

func (Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	fmt.Fprintf(os.Stderr, "SPIKE %s %s %s proto=%q major=%d hdr=%v\n", r.Method, r.URL, r.Host, r.Proto, r.ProtoMajor, r.Header)
	// No Content-Type sniffing: the Capsule Protocol response has no content.
	w.Header()["Content-Type"] = nil
	switch {
	case r.ProtoMajor == 3 && r.Method == http.MethodConnect && r.Proto == "connect-ip":
		return serveH3(w, r)
	case r.ProtoMajor == 2 && r.Method == http.MethodConnect && r.Header.Get(":protocol") == "connect-ip":
		return serveStream(w, r, "HTTP/2")
	case r.ProtoMajor == 1 && strings.EqualFold(r.Header.Get("Upgrade"), "connect-ip"):
		return serveH1(w, r)
	}
	return next.ServeHTTP(w, r)
}

func greeting() []byte {
	// ADDRESS_ASSIGN 10.89.0.2/32, ROUTE_ADVERTISEMENT all of IPv4.
	assign := []byte{0x00, 4, 10, 89, 0, 2, 32}
	route := []byte{4, 0, 0, 0, 0, 255, 255, 255, 255, 0}
	out := append([]byte{0x01, byte(len(assign))}, assign...)
	out = append(out, 0x03, byte(len(route)))
	return append(out, route...)
}

func unwrapStreamer(w http.ResponseWriter) (http3.HTTPStreamer, bool) {
	for {
		if s, ok := w.(http3.HTTPStreamer); ok {
			return s, true
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return nil, false
		}
		w = u.Unwrap()
	}
}

func serveH3(w http.ResponseWriter, r *http.Request) error {
	s, ok := unwrapStreamer(w)
	if !ok {
		return fmt.Errorf("no HTTP/3 stream")
	}
	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(http.StatusOK)
	_ = http.NewResponseController(w).Flush()
	str := s.HTTPStream()
	if _, err := str.Write(greeting()); err != nil {
		return nil
	}
	go func() {
		for {
			if _, err := str.ReceiveDatagram(context.Background()); err != nil {
				return
			}
		}
	}()
	_, _ = str.Read(make([]byte, 1)) // until the client closes
	<-r.Context().Done()
	return nil
}

func serveStream(w http.ResponseWriter, r *http.Request, _ string) error {
	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	_ = rc.Flush()
	if _, err := w.Write(greeting()); err != nil {
		return nil
	}
	_ = rc.Flush()
	buf := make([]byte, 4096)
	for {
		if _, err := r.Body.Read(buf); err != nil {
			return nil
		}
	}
}

func serveH1(w http.ResponseWriter, r *http.Request) error {
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return err
	}
	defer conn.Close()
	_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-ip\r\nCapsule-Protocol: ?1\r\n\r\n")
	_, _ = brw.Write(greeting())
	_ = brw.Flush()
	_, _ = bufio.NewReader(brw).ReadByte()
	buf := make([]byte, 4096)
	for {
		if _, err := conn.Read(buf); err != nil {
			return nil
		}
	}
}

var (
	_ caddy.App                   = (*App)(nil)
	_ caddy.Provisioner           = (*App)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ *tls.Config
)
