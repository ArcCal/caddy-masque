package http3

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

func TestQPACKZeroCapacityInstructions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		encoder bool
		data    []byte
		err     error
	}{
		{name: "empty encoder stream", encoder: true, err: io.EOF},
		{name: "zero capacity", encoder: true, data: []byte{0x20, 0x20}, err: io.EOF},
		{name: "nonzero capacity", encoder: true, data: []byte{0x21}, err: errInvalidQPACKInstruction},
		{name: "large capacity", encoder: true, data: []byte{0x3f, 0x00}, err: errInvalidQPACKInstruction},
		{name: "insert static name", encoder: true, data: []byte{0xc0, 0x00}, err: errInvalidQPACKInstruction},
		{name: "insert dynamic name", encoder: true, data: []byte{0x80, 0x00}, err: errInvalidQPACKInstruction},
		{name: "insert literal name", encoder: true, data: []byte{0x40, 0x00}, err: errInvalidQPACKInstruction},
		{name: "duplicate", encoder: true, data: []byte{0x00}, err: errInvalidQPACKInstruction},
		{name: "empty decoder stream", err: io.EOF},
		{name: "stream cancellations", data: []byte{0x40, 0x7e, 0x7f, 0x00, 0x7f, 0x80, 0x00}, err: io.EOF},
		{name: "maximum stream ID", data: []byte{0x7f, 0xc0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f}, err: io.EOF},
		{name: "stream ID overflow", data: []byte{0x7f, 0xc1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f}, err: errInvalidQPACKInstruction},
		{name: "encoded length limit", data: []byte{0x7f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00}, err: errInvalidQPACKInstruction},
		{name: "section acknowledgment", data: []byte{0x80}, err: errInvalidQPACKInstruction},
		{name: "zero insert count increment", data: []byte{0x00}, err: errInvalidQPACKInstruction},
		{name: "nonzero insert count increment", data: []byte{0x01}, err: errInvalidQPACKInstruction},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.ErrorIs(t, readQPACKStream(bytes.NewReader(tc.data), tc.encoder), tc.err)
		})
	}
}

func TestQPACKStreamCancellationInteger(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		err  error
	}{
		{name: "small stream ID", data: []byte{0x40}},
		{name: "prefixed stream ID", data: []byte{0x7f, 0x00}},
		{name: "nonminimal encoding", data: []byte{0x7f, 0x80, 0x00}},
		{name: "maximum encoded length", data: []byte{0x7f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00}},
		{name: "missing continuation", data: []byte{0x7f}, err: io.EOF},
		{name: "incomplete continuation", data: []byte{0x7f, 0x80}, err: io.EOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := readQPACKStreamCancellation(bytes.NewReader(tc.data[1:]), tc.data[0])
			if tc.err == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.err)
			}
		})
	}
}

func TestQPACKCriticalStreamErrors(t *testing.T) {
	for _, receiver := range []struct {
		name     string
		isServer bool
	}{{name: "server", isServer: true}, {name: "client"}} {
		t.Run(receiver.name, func(t *testing.T) {
			for _, tc := range []struct {
				name       string
				streamType uint64
				data       []byte
				fin        bool
				reset      bool
				code       ErrCode
			}{
				{name: "encoder FIN", streamType: streamTypeQPACKEncoderStream, fin: true, code: ErrCodeClosedCriticalStream},
				{name: "decoder FIN", streamType: streamTypeQPACKDecoderStream, fin: true, code: ErrCodeClosedCriticalStream},
				{name: "encoder reset", streamType: streamTypeQPACKEncoderStream, reset: true, code: ErrCodeClosedCriticalStream},
				{name: "decoder reset", streamType: streamTypeQPACKDecoderStream, reset: true, code: ErrCodeClosedCriticalStream},
				{name: "zero capacities then FIN", streamType: streamTypeQPACKEncoderStream, data: []byte{0x20, 0x20}, fin: true, code: ErrCodeClosedCriticalStream},
				{name: "nonzero capacity", streamType: streamTypeQPACKEncoderStream, data: []byte{0x21}, code: ErrCodeQPACKEncoderStreamError},
				{name: "insert with name reference", streamType: streamTypeQPACKEncoderStream, data: []byte{0xc0, 0x00}, code: ErrCodeQPACKEncoderStreamError},
				{name: "insert with literal name", streamType: streamTypeQPACKEncoderStream, data: []byte{0x40, 0x00}, code: ErrCodeQPACKEncoderStreamError},
				{name: "duplicate entry", streamType: streamTypeQPACKEncoderStream, data: []byte{0x00}, code: ErrCodeQPACKEncoderStreamError},
				{name: "section acknowledgment", streamType: streamTypeQPACKDecoderStream, data: []byte{0x80}, code: ErrCodeQPACKDecoderStreamError},
				{name: "zero insert count increment", streamType: streamTypeQPACKDecoderStream, data: []byte{0x00}, code: ErrCodeQPACKDecoderStreamError},
				{name: "nonzero insert count increment", streamType: streamTypeQPACKDecoderStream, data: []byte{0x01}, code: ErrCodeQPACKDecoderStreamError},
				{name: "cancellations then FIN", streamType: streamTypeQPACKDecoderStream, data: []byte{0x40, 0x7f, 0x00, 0x7f, 0xc0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f}, fin: true, code: ErrCodeClosedCriticalStream},
				{name: "incomplete cancellation then FIN", streamType: streamTypeQPACKDecoderStream, data: []byte{0x7f, 0x80}, fin: true, code: ErrCodeClosedCriticalStream},
				{name: "cancellation stream ID overflow", streamType: streamTypeQPACKDecoderStream, data: []byte{0x7f, 0xc1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f}, code: ErrCodeQPACKDecoderStreamError},
				{name: "cancellation encoded length limit", streamType: streamTypeQPACKDecoderStream, data: []byte{0x7f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}, code: ErrCodeQPACKDecoderStreamError},
			} {
				t.Run(tc.name, func(t *testing.T) {
					peer, str := openTestQPACKStream(t, tc.streamType, receiver.isServer)
					if len(tc.data) > 0 {
						_, err := str.Write(tc.data)
						require.NoError(t, err)
					}
					if tc.fin {
						require.NoError(t, str.Close())
					}
					if tc.reset {
						str.CancelWrite(42)
					}
					select {
					case <-peer.Context().Done():
						require.ErrorIs(t, context.Cause(peer.Context()), &quic.ApplicationError{
							Remote: true, ErrorCode: quic.ApplicationErrorCode(tc.code),
						})
					case <-time.After(time.Second):
						t.Fatal("timeout waiting for QPACK connection error")
					}
				})
			}
		})
	}
}

func openTestQPACKStream(t *testing.T, streamType uint64, isServer bool) (*quic.Conn, *quic.SendStream) {
	t.Helper()
	client, server := newConnPair(t)
	peer, local := client, server
	if !isServer {
		peer, local = server, client
	}
	conn := newRawConn(local, false, nil, nopControlStrHandler, nil, nil)
	str, err := peer.OpenUniStream()
	require.NoError(t, err)
	_, err = str.Write(quicvarint.Append(nil, streamType))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	localStr, err := local.AcceptUniStream(ctx)
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handleUnidirectionalStream(localStr, isServer)
	}()
	// Ensure a RESET cannot discard the stream type before it is read.
	require.Eventually(t, func() bool {
		if streamType == streamTypeQPACKEncoderStream {
			return conn.rcvdQPACKEncoderStr.Load()
		}
		return conn.rcvdQPACKDecoderStr.Load()
	}, time.Second, time.Millisecond)
	t.Cleanup(func() {
		local.CloseWithError(0, "")
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("timeout waiting for QPACK stream reader to exit")
		}
	})
	return peer, str
}
