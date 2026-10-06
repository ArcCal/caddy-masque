package masque

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/ArcCal/caddy-masque/internal/hostnet"
	"github.com/ArcCal/caddy-masque/internal/proto"
)

// HTTP/3 error codes (RFC 9114 §8.1) that abort a request stream:
// H3_MESSAGE_ERROR when the client broke the Capsule Protocol (RFC 9297
// §3.3, RFC 9114 §4.1.2), H3_REQUEST_CANCELLED when the server ends the
// tunnel for another reason, such as a path that cannot carry what RFC 9484
// requires (RFC 9114 §4.1.1).
const (
	h3MessageError     = 0x10e
	h3RequestCancelled = 0x10c
)

// ending is how a session ends its request stream.
type ending int

const (
	// endClose finishes it: FIN, END_STREAM, or closing an HTTP/1.1
	// connection.
	endClose ending = iota
	// endMalformed aborts it because the client's message is malformed:
	// H3_MESSAGE_ERROR, or PROTOCOL_ERROR over HTTP/2 (RFC 9113 §8.1.1).
	endMalformed
	// endCancel aborts it for another reason: H3_REQUEST_CANCELLED, or
	// CANCEL over HTTP/2. H3_MESSAGE_ERROR would tell the client that its
	// message was malformed.
	endCancel
)

// tunnel is a CONNECT-IP request stream, whatever the HTTP version:
// capsules both ways, and HTTP Datagrams as QUIC DATAGRAM frames (HTTP/3)
// or DATAGRAM capsules (RFC 9297 §3.5).
//
// A session ends it in three steps: stop unblocks reads (and, when
// aborting, writes too), force unblocks writes that did not finish soon
// after, and finish ends the stream once nothing uses it any more; both
// stop and finish are told how it ends.
type tunnel interface {
	// readCapsule returns the next capsule from the client: io.EOF when the
	// client finished the stream, a proto.MalformedError when it broke the
	// Capsule Protocol.
	readCapsule() (proto.Capsule, error)
	writeCapsule(c proto.Capsule) error
	// sendDatagram sends an HTTP Datagram payload. For one too large for the
	// QUIC path it returns a *quic.DatagramTooLargeError whose size is the
	// largest HTTP Datagram payload the path takes.
	sendDatagram(payload []byte) error
	// receiveDatagram returns the next QUIC datagram payload of the stream
	// (HTTP/3 with datagrams only).
	receiveDatagram(ctx context.Context) ([]byte, error)
	hasQUICDatagrams() bool
	stop(how ending)
	force()
	finish(how ending)
}

// capsuleReader reads capsules from a byte stream.
type capsuleReader struct {
	r   io.Reader
	dec *proto.Decoder
	buf []byte
}

func newCapsuleReader(r io.Reader) *capsuleReader {
	return &capsuleReader{r: r, dec: proto.NewDecoder(proto.DefaultMaxValueLen), buf: make([]byte, 32<<10)}
}

func (cr *capsuleReader) next() (proto.Capsule, error) {
	for {
		raw, err := cr.dec.Next()
		if err == nil {
			return proto.Decode(raw)
		}
		if !errors.Is(err, proto.ErrIncomplete) {
			return nil, err
		}
		n, rerr := cr.r.Read(cr.buf)
		cr.dec.Push(cr.buf[:n])
		if rerr != nil {
			if n > 0 {
				continue
			}
			if errors.Is(rerr, io.EOF) {
				// A capsule cut off by the end of the stream is malformed
				// (RFC 9297 §3.3).
				if err := cr.dec.Finish(); err != nil {
					return nil, err
				}
			}
			return nil, rerr
		}
	}
}

// capsuleWriter writes capsules to a byte stream, one at a time.
type capsuleWriter struct {
	mu    sync.Mutex
	w     io.Writer
	flush func() error
}

func (cw *capsuleWriter) writeCapsule(c proto.Capsule) error {
	b := proto.Append(nil, c)
	cw.mu.Lock()
	defer cw.mu.Unlock()
	if _, err := cw.w.Write(b); err != nil {
		return err
	}
	if cw.flush != nil {
		return cw.flush()
	}
	return nil
}

// streamTunnel carries everything as capsules on a byte stream: an
// upgraded HTTP/1.1 connection, or an HTTP/2 extended CONNECT stream.
type streamTunnel struct {
	reader *capsuleReader
	capsuleWriter
	stopFn  func(how ending)
	forceFn func()
}

func (t *streamTunnel) readCapsule() (proto.Capsule, error) { return t.reader.next() }
func (t *streamTunnel) sendDatagram(p []byte) error         { return t.writeCapsule(proto.Datagram(p)) }

func (t *streamTunnel) receiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (t *streamTunnel) hasQUICDatagrams() bool { return false }
func (t *streamTunnel) stop(how ending)        { t.stopFn(how) }
func (t *streamTunnel) force()                 { t.forceFn() }

// finish: the handler returning ends an HTTP/2 stream (END_STREAM), and
// stop already closed an HTTP/1.1 connection.
func (t *streamTunnel) finish(ending) {}

// h3Tunnel is an HTTP/3 request stream. HTTP Datagrams travel in QUIC
// DATAGRAM frames when the client supports them (RFC 9297 §2.1.1), else in
// DATAGRAM capsules on the stream.
type h3Tunnel struct {
	str    *http3.Stream
	reader *capsuleReader
	capsuleWriter
	quicDatagrams bool
	// The Quarter Stream ID before every HTTP Datagram in a QUIC DATAGRAM
	// frame (RFC 9297 §2.1).
	quarterIDLen int
}

func newH3Tunnel(str *http3.Stream, quicDatagrams bool) *h3Tunnel {
	return &h3Tunnel{str: str, reader: newCapsuleReader(str), capsuleWriter: capsuleWriter{w: str},
		quicDatagrams: quicDatagrams, quarterIDLen: quicvarint.Len(uint64(str.StreamID() / 4))}
}

func (t *h3Tunnel) readCapsule() (proto.Capsule, error) { return t.reader.next() }

func (t *h3Tunnel) sendDatagram(p []byte) error {
	if !t.quicDatagrams {
		return t.writeCapsule(proto.Datagram(p))
	}
	err := t.str.SendDatagram(p)
	var tooBig *quic.DatagramTooLargeError
	if errors.As(err, &tooBig) {
		// quic-go reports the room in the QUIC DATAGRAM frame, which also
		// holds the Quarter Stream ID.
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: tooBig.MaxDatagramPayloadSize - int64(t.quarterIDLen)}
	}
	return err
}

func (t *h3Tunnel) receiveDatagram(ctx context.Context) ([]byte, error) {
	return t.str.ReceiveDatagram(ctx)
}

func (t *h3Tunnel) hasQUICDatagrams() bool { return t.quicDatagrams }

func (t *h3Tunnel) stop(how ending) {
	switch how {
	case endMalformed:
		t.str.CancelRead(h3MessageError)
		t.str.CancelWrite(h3MessageError)
	case endCancel:
		t.str.CancelRead(h3RequestCancelled)
		t.str.CancelWrite(h3RequestCancelled)
	default:
		t.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	}
}

func (t *h3Tunnel) force() { _ = t.str.SetWriteDeadline(time.Now()) }

func (t *h3Tunnel) finish(how ending) {
	if how == endClose {
		// Nothing writes any more: end the stream with a FIN.
		t.mu.Lock()
		defer t.mu.Unlock()
		_ = t.str.Close()
	}
}

// innermost unwraps Caddy's response writer wrappers down to the HTTP
// server's own.
func innermost(w http.ResponseWriter) http.ResponseWriter {
	for {
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return w
		}
		w = u.Unwrap()
	}
}

// rawBody unwraps the request body readers Caddy adds, among them
// IdleTimeoutReader, which sets a read deadline before every read: a
// tunnel is idle for as long as its user likes.
func rawBody(body io.ReadCloser) io.ReadCloser {
	for {
		if r, ok := body.(*caddyhttp.IdleTimeoutReader); ok {
			body = r.ReadCloser
			continue
		}
		// The byte counter for access logs (an unexported type) keeps the
		// body in an exported field.
		v := reflect.ValueOf(body)
		if v.Kind() == reflect.Pointer && !v.IsNil() && v.Elem().Kind() == reflect.Struct {
			if f := v.Elem().FieldByName("Source"); f.IsValid() && f.CanInterface() {
				if inner, ok := f.Interface().(io.ReadCloser); ok && inner != nil {
					body = inner
					continue
				}
			}
		}
		return body
	}
}

// TCP settings of the connections that carry tunnels over HTTP/1.1 and
// HTTP/2, the same as masque-vpn's server: a client that went away without
// closing its connection (a laptop or phone that changed networks) is
// noticed within about 30 seconds rather than the 2.5 minutes of Caddy's
// keepalive, so its address and its place among its user's sessions are
// free again soon. The user timeout (Linux) ends the connection when data
// sent stays unacknowledged that long; the keepalive probes find a client
// that went while its tunnel was idle. They apply whatever the server's
// keepalive options; tunnels over HTTP/3 end after the QUIC idle timeout.
var tunnelKeepAlive = net.KeepAliveConfig{Enable: true, Idle: 10 * time.Second, Interval: 5 * time.Second, Count: 4}

const tunnelUserTimeout = 30 * time.Second

// tuneTunnelConn applies them to the TCP connection under c. A variable
// for tests.
var tuneTunnelConn = func(c net.Conn) error {
	tc, ok := tcpConnOf(c)
	if !ok {
		return fmt.Errorf("no TCP connection found under %T", c)
	}
	if err := tc.SetKeepAliveConfig(tunnelKeepAlive); err != nil {
		return err
	}
	return hostnet.SetTCPUserTimeout(tc, tunnelUserTimeout)
}

// tcpConnOf finds the TCP connection under TLS, the PROXY protocol and
// Caddy's listener wrappers, which keep it in an embedded net.Conn.
func tcpConnOf(c net.Conn) (*net.TCPConn, bool) {
	for range 16 {
		switch x := c.(type) {
		case *net.TCPConn:
			return x, true
		case *tls.Conn:
			c = x.NetConn()
			continue
		case interface{ Raw() net.Conn }:
			c = x.Raw()
			continue
		}
		v := reflect.ValueOf(c)
		if v.Kind() == reflect.Pointer && !v.IsNil() {
			v = v.Elem()
		}
		if v.Kind() != reflect.Struct {
			return nil, false
		}
		f := v.FieldByName("Conn")
		if !f.IsValid() || !f.CanInterface() {
			return nil, false
		}
		inner, ok := f.Interface().(net.Conn)
		if !ok || inner == nil {
			return nil, false
		}
		c = inner
	}
	return nil, false
}

// unwrapStreamer finds the HTTP/3 stream behind Caddy's response writer
// wrappers.
func unwrapStreamer(w http.ResponseWriter) (http3.HTTPStreamer, bool) {
	s, ok := innermost(w).(http3.HTTPStreamer)
	return s, ok
}
