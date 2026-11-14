package http3

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func TestConnectionConfigSnapshotsLimitsAndSettings(t *testing.T) {
	selected := ConnectionConfig{MaxHeaderBytes: 1024, IdleTimeout: time.Hour}
	calls := 0
	s := &Server{MaxHeaderBytes: 32768, IdleTimeout: 2 * time.Hour,
		GetConnectionConfig: func(c *quic.Conn) ConnectionConfig {
			require.NotNil(t, c)
			calls++
			return selected
		},
	}
	open := func(want ConnectionConfig) *RawServerConn {
		client, server := newConnPair(t)
		conn, _, err := s.newRawServerConn(server)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.CloseWithError(quic.ApplicationErrorCode(ErrCodeNoError), "") })
		require.Equal(t, want.MaxHeaderBytes, conn.maxHeaderBytes)
		require.Equal(t, want.IdleTimeout, conn.idleTimeout)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		control, err := client.AcceptUniStream(ctx)
		require.NoError(t, err)
		require.NoError(t, control.SetReadDeadline(time.Now().Add(time.Second)))
		kind, err := quicvarint.Read(quicvarint.NewReader(control))
		require.NoError(t, err)
		require.EqualValues(t, streamTypeControlStream, kind)
		frame, err := (&frameParser{r: io.Reader(control)}).ParseNext(nil)
		require.NoError(t, err)
		require.Equal(t, int64(want.MaxHeaderBytes), frame.(*settingsFrame).MaxFieldSectionSize)
		return conn
	}
	first := open(selected)
	selected = ConnectionConfig{MaxHeaderBytes: 2048, IdleTimeout: 3 * time.Hour}
	open(selected)
	require.Equal(t, 1024, first.maxHeaderBytes)
	require.Equal(t, time.Hour, first.idleTimeout)
	selected = ConnectionConfig{}
	open(ConnectionConfig{MaxHeaderBytes: http.DefaultMaxHeaderBytes})
	require.Equal(t, 3, calls)
}
