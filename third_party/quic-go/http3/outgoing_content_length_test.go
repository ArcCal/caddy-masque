package http3

import (
	"io"
	"net/http"
	"strconv"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestResponseWriterContentLengthByStatus(t *testing.T) {
	for _, tc := range []struct {
		status int
		wantCL bool
	}{
		{http.StatusContinue, false},
		{http.StatusEarlyHints, false},
		{http.StatusNoContent, false},
		{http.StatusOK, true},
		{http.StatusNotModified, true},
	} {
		t.Run(strconv.Itoa(tc.status), func(t *testing.T) {
			w := newTestResponseWriter(t)
			w.Header().Set("Content-Length", "7")
			w.WriteHeader(tc.status)
			fields := w.DecodeHeaders(t, 0)
			require.Equal(t, []string{strconv.Itoa(tc.status)}, fields[":status"])
			if tc.wantCL {
				require.Equal(t, []string{"7"}, fields["content-length"])
			} else {
				require.NotContains(t, fields, "content-length")
			}
			// Informational headers must not erase the final response's length.
			if tc.status < 200 {
				final := w.DecodeHeaders(t, 1)
				require.Equal(t, []string{"200"}, final[":status"])
				require.Equal(t, []string{"7"}, final["content-length"])
			}
		})
	}
}

func TestConformanceResponseContentLengthByStatus(t *testing.T) {
	for _, tc := range []struct {
		name       string
		method     string
		status     int
		configured string
		body       string
		wantCL     []string
	}{
		{"204 automatic", "GET", http.StatusNoContent, "", "", nil},
		{"204 configured", "GET", http.StatusNoContent, "0", "", nil},
		{"304 automatic", "GET", http.StatusNotModified, "", "", nil},
		{"304 configured", "GET", http.StatusNotModified, "7", "", []string{"7"}},
		{"200 empty", "GET", http.StatusOK, "", "", []string{"0"}},
		{"HEAD configured", "HEAD", http.StatusOK, "7", "", []string{"7"}},
		{"HEAD written", "HEAD", http.StatusOK, "", "content", []string{"7"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := conformanceServer(t, func(w http.ResponseWriter, r *http.Request) {
				if tc.configured != "" {
					w.Header().Set("Content-Length", tc.configured)
				}
				w.WriteHeader(tc.status)
				if tc.body != "" {
					if _, err := w.Write([]byte(tc.body)); err != nil {
						panic(err)
					}
				}
			})
			str := conformanceRequest(t, conn, conformanceHeaders(t, ":method", tc.method, ":scheme", "https", ":authority", "localhost", ":path", "/"), true)
			fields := decodeHeader(t, str)
			require.Equal(t, []string{strconv.Itoa(tc.status)}, fields[":status"])
			if tc.wantCL == nil {
				require.NotContains(t, fields, "content-length")
			} else {
				require.Equal(t, tc.wantCL, fields["content-length"])
			}
			body, err := io.ReadAll(str)
			require.NoError(t, err)
			require.Empty(t, body)
		})
	}
}

func TestResponseWriterRejectsSwitchingProtocols(t *testing.T) {
	w := newTestResponseWriter(t)
	require.PanicsWithValue(t, "invalid WriteHeader code 101", func() { w.WriteHeader(http.StatusSwitchingProtocols) })
	require.Empty(t, w.buf.Bytes())
	require.False(t, w.headerComplete)
	w.WriteHeader(http.StatusEarlyHints)
	w.WriteHeader(http.StatusOK)
	require.Equal(t, []string{"103"}, w.DecodeHeaders(t, 0)[":status"])
	require.Equal(t, []string{"200"}, w.DecodeHeaders(t, 1)[":status"])
}

func TestConformanceRejectsSwitchingProtocols(t *testing.T) {
	conn := conformanceServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/switch" {
			w.WriteHeader(http.StatusSwitchingProtocols)
			return
		}
		w.WriteHeader(http.StatusContinue)
		w.WriteHeader(http.StatusEarlyHints)
		w.WriteHeader(http.StatusOK)
	})
	bad := conformanceRequest(t, conn, conformanceHeaders(t, ":method", "GET", ":scheme", "https", ":authority", "localhost", ":path", "/switch"), true)
	data, err := io.ReadAll(bad)
	require.Empty(t, data, "the invalid 101 response must not reach the peer")
	require.ErrorIs(t, err, &quic.StreamError{Remote: true, StreamID: bad.StreamID(), ErrorCode: quic.StreamErrorCode(ErrCodeInternalError)})
	good := conformanceRequest(t, conn, conformanceHeaders(t, ":method", "GET", ":scheme", "https", ":authority", "localhost", ":path", "/"), true)
	for _, status := range []string{"100", "103", "200"} {
		require.Equal(t, []string{status}, decodeHeader(t, good)[":status"])
	}
	_, err = io.ReadAll(good)
	require.NoError(t, err)
}
