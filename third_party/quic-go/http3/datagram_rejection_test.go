package http3

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

type rejectionClearer struct{ count atomic.Int32 }

func (c *rejectionClearer) clearStream(quic.StreamID) { c.count.Add(1) }

func rejectedStream(t *testing.T) (*stateTrackingStream, *quic.Stream, *rejectionClearer) {
	t.Helper()
	local, peer := newStreamPair(t)
	clearer := new(rejectionClearer)
	str := newStateTrackingStream(local, clearer, func([]byte) error { return nil })
	t.Cleanup(func() {
		str.CancelRead(quic.StreamErrorCode(ErrCodeNoError))
		str.CancelWrite(quic.StreamErrorCode(ErrCodeNoError))
	})
	return str, peer, clearer
}

func checkRejectedWire(t *testing.T, str *stateTrackingStream, peer *quic.Stream, clearer *rejectionClearer) {
	t.Helper()
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err := peer.Read(make([]byte, 1))
	var streamErr *quic.StreamError
	require.ErrorAs(t, err, &streamErr)
	require.Equal(t, quic.StreamErrorCode(ErrCodeDatagramError), streamErr.ErrorCode)
	require.True(t, streamErr.Remote)
	select {
	case <-peer.Context().Done():
	case <-time.After(2 * time.Second):
		t.Fatal("STOP_SENDING did not close peer send side")
	}
	require.ErrorAs(t, context.Cause(peer.Context()), &streamErr)
	require.Equal(t, quic.StreamErrorCode(ErrCodeDatagramError), streamErr.ErrorCode)
	require.True(t, streamErr.Remote)
	require.ErrorAs(t, str.SendDatagram(nil), &streamErr)
	require.Equal(t, quic.StreamErrorCode(ErrCodeDatagramError), streamErr.ErrorCode)
	require.EqualValues(t, 1, clearer.count.Load(), "stream removed exactly once")
	str.mx.Lock()
	require.Nil(t, str.queue)
	str.mx.Unlock()
}

func TestRejectDatagramsQueuedAndSubsequent(t *testing.T) {
	for _, queued := range []bool{false, true} {
		t.Run(map[bool]string{true: "already-queued", false: "arrives-after-classification"}[queued], func(t *testing.T) {
			str, peer, clearer := rejectedStream(t)
			if queued {
				// Empty payloads are Datagrams and must also be rejected.
				str.enqueueDatagram(nil)
			}
			str.rejectDatagrams()
			if !queued {
				str.enqueueDatagram(nil)
			}
			checkRejectedWire(t, str, peer, clearer)
		})
	}
}

func TestRejectDatagramsQueuedBeforeEOF(t *testing.T) {
	str, peer, clearer := rejectedStream(t)
	str.enqueueDatagram([]byte("received while open"))
	require.NoError(t, peer.Close())
	_, err := io.ReadAll(str)
	require.NoError(t, err)
	str.rejectDatagrams()
	// The earlier violation must not be hidden by a later request body EOF.
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err = peer.Read(make([]byte, 1))
	var streamErr *quic.StreamError
	require.ErrorAs(t, err, &streamErr)
	require.Equal(t, quic.StreamErrorCode(ErrCodeDatagramError), streamErr.ErrorCode)
	require.True(t, streamErr.Remote)
	require.EqualValues(t, 1, clearer.count.Load())
	str.mx.Lock()
	require.Nil(t, str.queue)
	str.mx.Unlock()
}

func TestRejectDatagramsDropsAfterEOF(t *testing.T) {
	str, peer, clearer := rejectedStream(t)
	require.NoError(t, peer.Close())
	_, err := io.ReadAll(str)
	require.NoError(t, err)
	str.rejectDatagrams()
	str.enqueueDatagram([]byte("too late"))
	str.rejectDatagrams() // repeated declaration is harmless
	require.NoError(t, str.SendDatagram(nil))
	require.EqualValues(t, 0, clearer.count.Load())
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(2*time.Second)))
	_, err = str.Write([]byte("normal response"))
	require.NoError(t, err)
	require.NoError(t, str.Close())
	b, err := io.ReadAll(peer)
	require.NoError(t, err)
	require.Equal(t, "normal response", string(b))
	require.EqualValues(t, 1, clearer.count.Load())
}

func TestRejectDatagramsConcurrentClassification(t *testing.T) {
	for range 20 {
		str, peer, clearer := rejectedStream(t)
		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Add(2)
		go func() { defer wg.Done(); <-start; str.rejectDatagrams() }()
		go func() { defer wg.Done(); <-start; str.enqueueDatagram([]byte("race")) }()
		close(start)
		wg.Wait()
		checkRejectedWire(t, str, peer, clearer)
	}
}

type rejectionWriterWrapper struct{ http.ResponseWriter }

func (w rejectionWriterWrapper) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func TestRejectDatagramsDoesNotHijackOrFlush(t *testing.T) {
	str, _, _ := rejectedStream(t)
	w := newResponseWriter(newStream(str, nil, nil, nil, nil), nil, false, nil)
	w.Header().Set("Trailer", "X-Result")
	_, err := w.Write([]byte("buffered"))
	require.NoError(t, err)
	require.False(t, w.headerWritten)
	require.NoError(t, RejectDatagrams(rejectionWriterWrapper{w}))
	require.False(t, w.wasStreamHijacked())
	require.False(t, w.headerWritten)
	require.Equal(t, "buffered", string(w.smallResponseBuf))
	require.Equal(t, "X-Result", w.Header().Get("Trailer"))
	require.Equal(t, http.StatusOK, w.status)
	// Unsupported writers return a specific error rather than silently
	// claiming that the request's Datagram policy was applied.
	require.True(t, errors.Is(RejectDatagrams(httptest.NewRecorder()), http.ErrNotSupported))
}
