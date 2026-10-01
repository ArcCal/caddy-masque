package masque

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/ArcCal/caddy-masque/internal/proto"
)

// H3_MESSAGE_ERROR (RFC 9114 §8.1): the request stream is aborted when
// the client breaks the Capsule Protocol or the path cannot carry what
// RFC 9484 requires.
const h3MessageError = 0x10e

// tunnel is a CONNECT-IP request stream, whatever the HTTP version:
// capsules both ways, and HTTP Datagrams as QUIC DATAGRAM frames (HTTP/3)
// or DATAGRAM capsules (HTTP/1.1 and HTTP/2, RFC 9297 §3.5).
type tunnel interface {
	// readCapsule returns the next capsule from the client: io.EOF when the
	// client finished the stream, a proto.MalformedError when it broke the
	// Capsule Protocol.
	readCapsule() (proto.Capsule, error)
	writeCapsule(c proto.Capsule) error
	// sendDatagram sends an HTTP Datagram payload. For one too large for the
	// QUIC path it returns a *quic.DatagramTooLargeError.
	sendDatagram(payload []byte) error
	// receiveDatagram returns the next QUIC datagram payload of the stream
	// (HTTP/3 only).
	receiveDatagram(ctx context.Context) ([]byte, error)
	hasQUICDatagrams() bool
	// abort resets the stream after a protocol error, close ends it. Both
	// unblock reads and writes in progress, and may be called while they
	// run.
	abort()
	close()
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

// streamTunnel carries everything as capsules on a byte stream: an
// upgraded HTTP/1.1 connection, or an HTTP/2 extended CONNECT stream.
type streamTunnel struct {
	reader *capsuleReader
	mu     sync.Mutex
	w      io.Writer
	flush  func() error
	closer func()
}

func (t *streamTunnel) readCapsule() (proto.Capsule, error) { return t.reader.next() }

func (t *streamTunnel) writeCapsule(c proto.Capsule) error {
	b := proto.Append(nil, c)
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, err := t.w.Write(b); err != nil {
		return err
	}
	if t.flush != nil {
		return t.flush()
	}
	return nil
}

func (t *streamTunnel) sendDatagram(p []byte) error { return t.writeCapsule(proto.Datagram(p)) }

func (t *streamTunnel) receiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (t *streamTunnel) hasQUICDatagrams() bool { return false }
func (t *streamTunnel) abort()                 { t.closer() }
func (t *streamTunnel) close()                 { t.closer() }

// h3Tunnel is an HTTP/3 request stream with QUIC datagrams.
type h3Tunnel struct {
	str    *http3.Stream
	reader *capsuleReader
	mu     sync.Mutex
}

func newH3Tunnel(str *http3.Stream) *h3Tunnel {
	return &h3Tunnel{str: str, reader: newCapsuleReader(str)}
}

func (t *h3Tunnel) readCapsule() (proto.Capsule, error) { return t.reader.next() }

func (t *h3Tunnel) writeCapsule(c proto.Capsule) error {
	b := proto.Append(nil, c)
	t.mu.Lock()
	defer t.mu.Unlock()
	_, err := t.str.Write(b)
	return err
}

func (t *h3Tunnel) sendDatagram(p []byte) error { return t.str.SendDatagram(p) }

func (t *h3Tunnel) receiveDatagram(ctx context.Context) ([]byte, error) {
	return t.str.ReceiveDatagram(ctx)
}

func (t *h3Tunnel) hasQUICDatagrams() bool { return true }

func (t *h3Tunnel) abort() {
	t.str.CancelRead(h3MessageError)
	t.str.CancelWrite(h3MessageError)
}

func (t *h3Tunnel) close() {
	t.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	// A write blocked on flow control gives up; then the stream is finished
	// (Close must not run concurrently with Write).
	_ = t.str.SetWriteDeadline(time.Now())
	t.mu.Lock()
	defer t.mu.Unlock()
	_ = t.str.Close()
}

// unwrapStreamer finds the HTTP/3 stream behind Caddy's response writer
// wrappers.
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
