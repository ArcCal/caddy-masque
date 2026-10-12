package masque

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

// Push is not supported: a client's CANCEL_PUSH names a push ID the server
// never mentioned (RFC 9114 section 7.2.3) and MAX_PUSH_ID cannot be reduced
// (section 7.2.7), both H3_ID_ERROR. PUSH_PROMISE (section 7.2.5) and push
// frames on a request stream (sections 7.2.3 and 7.2.7) are
// H3_FRAME_UNEXPECTED, as are other control-stream frames on a request
// stream, however malformed. An equal or increasing MAX_PUSH_ID is accepted.
// A push ID payload that is empty, shorter or longer than its integer is
// H3_FRAME_ERROR (section 7.1), and is read only within its declared length.
func TestH3PushFramesAreChecked(t *testing.T) {
	e := newCaddyEnv(t)
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	frame := func(typ uint64, payload ...byte) []byte {
		b := quicvarint.Append(quicvarint.Append(nil, typ), uint64(len(payload)))
		return append(b, payload...)
	}
	for _, tc := range []struct {
		name    string
		control [][]byte
		request []byte
		code    quic.ApplicationErrorCode // 0: the connection stays open
		split   bool                      // send the control frames a byte at a time
	}{
		{"CANCEL_PUSH", [][]byte{frame(0x3, 0)}, nil, 0x108, false},
		{"MAX_PUSH_ID reduced", [][]byte{frame(0xd, 1), frame(0xd, 0)}, nil, 0x108, false},
		{"MAX_PUSH_ID increased", [][]byte{frame(0xd, 0), frame(0xd, 1), frame(0xd, 1)}, nil, 0, false},
		{"PUSH_PROMISE on the control stream", [][]byte{frame(0x5, 0)}, nil, 0x105, false},
		{"CANCEL_PUSH on a request stream", nil, frame(0x3, 0), 0x105, false},
		{"MAX_PUSH_ID on a request stream", nil, frame(0xd, 0), 0x105, false},
		{"PUSH_PROMISE on a request stream", nil, frame(0x5, 0), 0x105, false},
		// RFC 9114 section 7.1: a payload longer than its fields is
		// H3_FRAME_ERROR; on a request stream these frames are already
		// H3_FRAME_UNEXPECTED by their type. Either way the connection closes.
		{"malformed CANCEL_PUSH on the control stream", [][]byte{{0x3, 2, 0, 0}}, nil, 0x106, false},
		{"malformed MAX_PUSH_ID on the control stream", [][]byte{{0xd, 2, 0, 0}}, nil, 0x106, false},
		{"malformed CANCEL_PUSH on a request stream", nil, []byte{0x3, 2, 0, 0}, 0x105, false},
		{"malformed MAX_PUSH_ID on a request stream", nil, []byte{0xd, 2, 0, 0}, 0x105, false},
		{"malformed GOAWAY on a request stream", nil, []byte{0x7, 2, 0, 0}, 0x105, false},
		{"SETTINGS on a request stream", nil, frame(0x4), 0x105, false},
		{"PRIORITY_UPDATE on a request stream", nil, frame(0xf0700, 0), 0x105, false},
		{"PUSH_PROMISE with a truncated payload on a request stream", nil, []byte{0x5, 9, 0}, 0x105, false},
		// Payloads that end inside the push ID: the following bytes are not
		// part of the frame, so the parser must not wait for them.
		{"MAX_PUSH_ID with a two-byte ID in a one-byte payload", [][]byte{{0xd, 1, 0x40}}, nil, 0x106, false},
		{"CANCEL_PUSH with a two-byte ID in a one-byte payload", [][]byte{{0x3, 1, 0x40}}, nil, 0x106, false},
		{"GOAWAY with a two-byte ID in a one-byte payload", [][]byte{{0x7, 1, 0x40}}, nil, 0x106, false},
		{"empty MAX_PUSH_ID", [][]byte{{0xd, 0}}, nil, 0x106, false},
		{"empty CANCEL_PUSH", [][]byte{{0x3, 0}}, nil, 0x106, false},
		{"empty GOAWAY", [][]byte{{0x7, 0}}, nil, 0x106, false},
		{"MAX_PUSH_ID with a nine-byte payload", [][]byte{{0xd, 9, 0xc0, 0, 0, 0, 0, 0, 0, 1, 0}}, nil, 0x106, false},
		// Legal encodings of every width, including non-minimal ones.
		{"MAX_PUSH_ID equal, in non-minimal encodings", [][]byte{
			{0xd, 1, 5}, {0xd, 2, 0x40, 5}, {0xd, 4, 0x80, 0, 0, 5}, {0xd, 8, 0xc0, 0, 0, 0, 0, 0, 0, 5},
		}, nil, 0, false},
		{"MAX_PUSH_ID reduced after an eight-byte ID", [][]byte{{0xd, 8, 0xc0, 0, 0, 1, 0, 0, 0, 0}, {0xd, 4, 0xbf, 0xff, 0xff, 0xff}}, nil, 0x108, false},
		{"GOAWAY in a non-minimal encoding", [][]byte{{0x7, 2, 0x40, 0}}, nil, 0, false},
		// Split delivery: the reduction is only seen if the four-byte ID was
		// read whole from separate packets.
		{"MAX_PUSH_ID split delivery", [][]byte{{0xd, 4, 0x80, 0, 1, 0}, {0xd, 1, 5}}, nil, 0x108, true},
		// A payload whose remaining bytes have not arrived is not malformed yet.
		{"MAX_PUSH_ID with withheld bytes", [][]byte{{0xd, 4, 0x80, 0}}, nil, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := quic.DialAddr(ctx, fmt.Sprintf("127.0.0.1:%d", e.port), e.tlsConfig("h3"), &quic.Config{})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.CloseWithError(0, "")
			ctrl, err := conn.OpenUniStream()
			if err != nil {
				t.Fatal(err)
			}
			b := append([]byte{0x00}, frame(0x4)...) // control stream, empty SETTINGS
			for _, f := range tc.control {
				b = append(b, f...)
			}
			if tc.split {
				if _, err := ctrl.Write(b[:3]); err != nil {
					t.Fatal(err)
				}
				for _, c := range b[3:] {
					time.Sleep(20 * time.Millisecond)
					if _, err := ctrl.Write([]byte{c}); err != nil {
						t.Fatal(err)
					}
				}
			} else if _, err := ctrl.Write(b); err != nil {
				t.Fatal(err)
			}
			if tc.request != nil {
				str, err := conn.OpenStreamSync(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := str.Write(tc.request); err != nil {
					t.Fatal(err)
				}
			}
			wait := 5 * time.Second
			if tc.code == 0 {
				wait = time.Second
			}
			select {
			case <-conn.Context().Done():
			case <-time.After(wait):
				if tc.code != 0 {
					t.Fatalf("the connection stayed open, want %#x", tc.code)
				}
				return
			}
			var ae *quic.ApplicationError
			if !errors.As(context.Cause(conn.Context()), &ae) || ae.ErrorCode != tc.code {
				t.Fatalf("closed with %v, want %#x", context.Cause(conn.Context()), tc.code)
			}
		})
	}
}

// The HTTP/3 client in the fork checks the same frames in the
// server-to-client direction. Control-stream frames on a request stream, and
// MAX_PUSH_ID anywhere, are H3_FRAME_UNEXPECTED (RFC 9114 sections 4.1, 7.2.3,
// 7.2.6 and 7.2.7). The client never sends MAX_PUSH_ID, so a PUSH_PROMISE or
// CANCEL_PUSH names a push ID beyond its maximum: H3_ID_ERROR (sections 7.2.3
// and 7.2.5). A malformed payload is H3_FRAME_ERROR (section 7.1). In each case
// the client closes the connection, which the server observes.
func TestH3ClientChecksPushFrames(t *testing.T) {
	tc0 := newTestCert(t)
	cert, err := tls.X509KeyPair([]byte(tc0.certPEM), []byte(tc0.keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := quic.ListenAddr("127.0.0.1:0",
		&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{http3.NextProtoH3}}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ok := []byte{0x1, 3, 0, 0, 0xd9} // HEADERS: :status 200 (QPACK static index 25)
	for _, tc := range []struct {
		name              string
		control, response []byte
		code              quic.ApplicationErrorCode // 0: the connection stays open
	}{
		{"valid response", nil, ok, 0},
		{"unknown frame before the response", nil, append([]byte{0x21, 1, 0}, ok...), 0},
		{"MAX_PUSH_ID on a request stream", nil, []byte{0xd, 1, 0}, 0x105},
		{"malformed MAX_PUSH_ID on a request stream", nil, []byte{0xd, 2, 0, 0}, 0x105},
		{"malformed CANCEL_PUSH on a request stream", nil, []byte{0x3, 2, 0, 0}, 0x105},
		{"GOAWAY on a request stream", nil, []byte{0x7, 1, 0}, 0x105},
		{"SETTINGS on a request stream", nil, []byte{0x4, 0}, 0x105},
		{"PUSH_PROMISE", nil, []byte{0x5, 2, 0, 0}, 0x108},
		{"PUSH_PROMISE with a truncated payload", nil, []byte{0x5, 9, 0}, 0x108},
		{"PUSH_PROMISE after the response headers", nil, append(append([]byte{}, ok...), 0x5, 2, 0, 0), 0x108},
		{"malformed MAX_PUSH_ID after the response headers", nil, append(append([]byte{}, ok...), 0xd, 2, 0, 0), 0x105},
		{"CANCEL_PUSH on the control stream", []byte{0x3, 1, 0}, nil, 0x108},
		{"MAX_PUSH_ID on the control stream", []byte{0xd, 1, 0}, nil, 0x105},
		{"malformed CANCEL_PUSH on the control stream", []byte{0x3, 2, 0, 0}, nil, 0x106},
		{"CANCEL_PUSH with a two-byte ID in a one-byte payload", []byte{0x3, 1, 0x40}, nil, 0x106},
		{"empty GOAWAY on the control stream", []byte{0x7, 0}, nil, 0x106},
		{"PUSH_PROMISE on the control stream", []byte{0x5, 2, 0, 0}, nil, 0x105},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			served := make(chan *quic.Conn, 1)
			go func() {
				conn, err := ln.Accept(ctx)
				if err != nil {
					close(served)
					return
				}
				served <- conn
				ctrl, err := conn.OpenUniStream()
				if err != nil {
					return
				}
				ctrl.Write(append([]byte{0x0, 0x4, 0}, tc.control...)) // control stream, empty SETTINGS
				str, err := conn.AcceptStream(ctx)
				if err != nil || tc.response == nil {
					return
				}
				str.Write(tc.response)
			}()
			tr := &http3.Transport{TLSClientConfig: &tls.Config{ServerName: "vpn.test", RootCAs: tc0.pool}}
			defer tr.Close()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+ln.Addr().String()+"/", nil)
			rsp, err := tr.RoundTrip(req)
			if err == nil {
				if rsp.StatusCode != http.StatusOK {
					t.Fatalf("status %d", rsp.StatusCode)
				}
				if tc.code != 0 {
					io.ReadAll(rsp.Body)
				}
			}
			conn := <-served
			if conn == nil {
				t.Fatal("no connection")
			}
			if tc.code == 0 {
				if err != nil {
					t.Fatal(err)
				}
				select {
				case <-conn.Context().Done():
					t.Fatalf("connection closed: %v", context.Cause(conn.Context()))
				case <-time.After(300 * time.Millisecond):
				}
				return
			}
			select {
			case <-conn.Context().Done():
			case <-ctx.Done():
				t.Fatal("the client did not close the connection")
			}
			ae, ok := errors.AsType[*quic.ApplicationError](context.Cause(conn.Context()))
			if !ok || !ae.Remote || ae.ErrorCode != tc.code {
				t.Fatalf("closed with %v, want the client's %#x", context.Cause(conn.Context()), tc.code)
			}
		})
	}
}
