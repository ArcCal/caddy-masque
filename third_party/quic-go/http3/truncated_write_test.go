package http3

import (
	"os"
	"testing"

	"github.com/quic-go/quic-go"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// A write that fails, for example at a write deadline, can stop inside a DATA
// frame. Ending the stream cleanly after that would make the peer close the
// whole connection (RFC 9114 Section 7.1), so the stream must be reset.
func TestFailedWriteResetsInsteadOfClosing(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	qstr := NewMockDatagramStream(mockCtrl)
	qstr.EXPECT().StreamID().Return(quic.StreamID(4)).AnyTimes()
	str := newStream(qstr, nil, nil, nil, nil)

	payload := make([]byte, 1000)
	gomock.InOrder(
		qstr.EXPECT().Write(gomock.Any()).DoAndReturn(func(b []byte) (int, error) { return len(b), nil }),
		// Part of the payload is queued, then the deadline expires.
		qstr.EXPECT().Write(gomock.Any()).Return(300, os.ErrDeadlineExceeded),
		qstr.EXPECT().CancelWrite(quic.StreamErrorCode(ErrCodeRequestCanceled)),
	)
	qstr.EXPECT().Close().Times(0)

	n, err := str.Write(payload)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.Equal(t, 300, n)
	// Without a successful retry, the incomplete frame must be reset.
	require.NoError(t, str.Close())
}

func TestCompleteWritesStillCloseCleanly(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	qstr := NewMockDatagramStream(mockCtrl)
	qstr.EXPECT().StreamID().Return(quic.StreamID(4)).AnyTimes()
	str := newStream(qstr, nil, nil, nil, nil)

	qstr.EXPECT().Write(gomock.Any()).DoAndReturn(func(b []byte) (int, error) { return len(b), nil }).Times(2)
	qstr.EXPECT().Close()
	qstr.EXPECT().CancelWrite(gomock.Any()).Times(0)

	_, err := str.Write([]byte("complete"))
	require.NoError(t, err)
	require.NoError(t, str.Close())
}
