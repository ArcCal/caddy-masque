package masque

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
)

// Push is not supported: a client's CANCEL_PUSH names a push ID the server
// never mentioned (RFC 9114 section 7.2.3) and MAX_PUSH_ID cannot be reduced
// (section 7.2.7), both H3_ID_ERROR. PUSH_PROMISE (section 7.2.5) and push
// frames on a request stream (sections 7.2.3 and 7.2.7) are
// H3_FRAME_UNEXPECTED. An increasing MAX_PUSH_ID is accepted.
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
	}{
		{"CANCEL_PUSH", [][]byte{frame(0x3, 0)}, nil, 0x108},
		{"MAX_PUSH_ID reduced", [][]byte{frame(0xd, 1), frame(0xd, 0)}, nil, 0x108},
		{"MAX_PUSH_ID increased", [][]byte{frame(0xd, 0), frame(0xd, 1), frame(0xd, 1)}, nil, 0},
		{"PUSH_PROMISE on the control stream", [][]byte{frame(0x5, 0)}, nil, 0x105},
		{"CANCEL_PUSH on a request stream", nil, frame(0x3, 0), 0x105},
		{"MAX_PUSH_ID on a request stream", nil, frame(0xd, 0), 0x105},
		{"PUSH_PROMISE on a request stream", nil, frame(0x5, 0), 0x105},
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
			if _, err := ctrl.Write(b); err != nil {
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
