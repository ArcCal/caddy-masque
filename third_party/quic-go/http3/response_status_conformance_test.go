package http3

import (
	"context"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestResponseStatusSyntax(t *testing.T) {
	for _, status := range []string{"0", "20", "99", "000", "099", "+20", "-20", "+200", "0200", "2000", "20x", "2 0", "\u066200", "101"} {
		t.Run("invalid/"+status, func(t *testing.T) {
			err := updateResponseFromHeaders(&http.Response{}, decodeFromSlice([]qpack.HeaderField{{Name: ":status", Value: status}}), math.MaxInt, nil, false)
			require.Error(t, err)
		})
	}
	// Keep extension status codes and the existing policy for three-digit
	// out-of-range codes; this repair is limited to field syntax and 101.
	for _, status := range []string{"100", "103", "200", "204", "299", "304", "471", "599", "600", "999"} {
		t.Run("three digits/"+status, func(t *testing.T) {
			response := &http.Response{}
			err := updateResponseFromHeaders(response, decodeFromSlice([]qpack.HeaderField{{Name: ":status", Value: status}}), math.MaxInt, nil, false)
			require.NoError(t, err)
			want, err := strconv.Atoi(status)
			require.NoError(t, err)
			require.Equal(t, want, response.StatusCode)
		})
	}
}

func TestConformanceMalformedResponseStatus(t *testing.T) {
	for _, status := range []string{"99", "+200", "0200", "2000", "101"} {
		t.Run(status, func(t *testing.T) {
			client, server := newConnPair(t)
			cc := (&Transport{DisableCompression: true}).NewClientConn(client)
			stream, err := cc.OpenRequestStream(context.Background())
			require.NoError(t, err)
			require.NoError(t, stream.SetDeadline(time.Now().Add(time.Second)))
			require.NoError(t, stream.SendRequestHeader(httptest.NewRequest("GET", "https://localhost/", nil)))
			peer, err := server.AcceptStream(context.Background())
			require.NoError(t, err)
			_, err = peer.Write(conformanceHeaders(t, ":status", status))
			require.NoError(t, err)
			require.NoError(t, peer.Close())
			_, err = stream.ReadResponse()
			require.Error(t, err)
			require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
			_, err = io.ReadAll(peer)
			require.ErrorIs(t, err, &quic.StreamError{Remote: true, StreamID: peer.StreamID(), ErrorCode: quic.StreamErrorCode(ErrCodeMessageError)})

			// One bad response must not make a later extension status unusable.
			good, err := cc.OpenRequestStream(context.Background())
			require.NoError(t, err)
			require.NoError(t, good.SetDeadline(time.Now().Add(time.Second)))
			require.NoError(t, good.SendRequestHeader(httptest.NewRequest("GET", "https://localhost/", nil)))
			goodPeer, err := server.AcceptStream(context.Background())
			require.NoError(t, err)
			_, err = goodPeer.Write(conformanceHeaders(t, ":status", "471"))
			require.NoError(t, err)
			require.NoError(t, goodPeer.Close())
			response, err := good.ReadResponse()
			require.NoError(t, err)
			require.Equal(t, 471, response.StatusCode)
			_, err = io.ReadAll(response.Body)
			require.NoError(t, err)
		})
	}
}
