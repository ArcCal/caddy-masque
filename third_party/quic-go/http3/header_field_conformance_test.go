package http3

import (
	"bytes"
	"context"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestHeaderFieldEdgeWhitespace(t *testing.T) {
	for _, value := range []string{" leading", "trailing ", "\tleading", "trailing\t", " ", "\t", " \t"} {
		t.Run(value, func(t *testing.T) {
			require.Error(t, validateHeaderFieldNameAndValue(qpack.HeaderField{Name: "x-test", Value: value}))
		})
	}
	for _, value := range []string{"", "value", "a b", "a\tb", "\x80", "\xff"} {
		t.Run("valid/"+value, func(t *testing.T) {
			require.NoError(t, validateHeaderFieldNameAndValue(qpack.HeaderField{Name: "x-test", Value: value}))
		})
	}
}

func TestTERequestListSemantics(t *testing.T) {
	for _, value := range []string{"trailers", "Trailers", "TRAILERS", "trailers, trailers", "trailers,\tTRAILERS", ",trailers", "trailers,,", "", ",,"} {
		t.Run(value, func(t *testing.T) {
			fields := []qpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/"}, {Name: ":authority", Value: "localhost"}, {Name: "te", Value: value}}
			_, err := requestFromHeaders(decodeFromSlice(fields), math.MaxInt, nil)
			require.NoError(t, err)
		})
	}
	for _, value := range []string{"gzip", "trailers, gzip", "trailers;q=1", "\"trailers\"", "trailers ;q=1", "trailer\u017f"} {
		t.Run("invalid/"+value, func(t *testing.T) {
			fields := []qpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/"}, {Name: ":authority", Value: "localhost"}, {Name: "te", Value: value}}
			_, err := requestFromHeaders(decodeFromSlice(fields), math.MaxInt, nil)
			require.Error(t, err)
		})
	}
}

func TestTEOnlyInRequestHeaders(t *testing.T) {
	for _, value := range []string{"trailers", "Trailers", "trailers, trailers", ""} {
		t.Run(value, func(t *testing.T) {
			err := updateResponseFromHeaders(&http.Response{}, decodeFromSlice([]qpack.HeaderField{{Name: ":status", Value: "200"}, {Name: "te", Value: value}}), math.MaxInt, nil, false)
			require.Error(t, err)
			_, err = parseTrailers(decodeFromSlice([]qpack.HeaderField{{Name: "te", Value: value}}), math.MaxInt, nil)
			require.Error(t, err)
		})
	}
}

func TestOutgoingHeaderWhitespaceNormalization(t *testing.T) {
	const value = " \tvalue with\tinternal whitespace\t "
	const trimmed = "value with\tinternal whitespace"
	t.Run("request and request trailers", func(t *testing.T) {
		req := httptest.NewRequest("GET", "https://localhost/", nil)
		req.Header.Set("X-Trim", value)
		req.Trailer = http.Header{"X-Trailer": {value}}
		var buf bytes.Buffer
		w := newRequestWriter()
		require.NoError(t, w.WriteRequestHeader(&buf, req, false, 0, nil))
		require.Equal(t, []string{trimmed}, decodeHeader(t, &buf)["x-trim"])
		require.NoError(t, w.WriteRequestTrailer(&buf, req, 0, nil))
		require.Equal(t, []string{trimmed}, decodeHeader(t, &buf)["x-trailer"])
		require.Equal(t, value, req.Header.Get("X-Trim"))
	})
	t.Run("response and response trailers", func(t *testing.T) {
		w := newTestResponseWriter(t)
		w.Header().Set("X-Trim", value)
		w.Header().Set("Te", "trailers")
		w.Header().Set("Trailer", "X-Trailer")
		_, err := w.Write([]byte("body"))
		require.NoError(t, err)
		w.Header().Set("X-Trailer", value)
		headers := w.DecodeHeaders(t, 0)
		require.Equal(t, []string{trimmed}, headers["x-trim"])
		require.NotContains(t, headers, "te")
		require.Equal(t, []byte("body"), w.DecodeBody(t))
		require.Equal(t, []string{trimmed}, w.DecodeHeaders(t, 2)["x-trailer"])
		require.Equal(t, value, w.Header().Get("X-Trim"))
	})
}

func TestConformanceFieldRulesOnWire(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fields  []string
		trailer bool
		valid   bool
	}{
		{"leading space", []string{"x-test", " leading"}, false, false},
		{"trailing tab", []string{"x-test", "trailing\t"}, false, false},
		{"trailer edge whitespace", []string{"x-test", " leading"}, true, false},
		{"TE case insensitive", []string{"te", "Trailers"}, false, true},
		{"TE repeated list", []string{"te", "trailers,\tTRAILERS"}, false, true},
		{"TE repeated fields", []string{"te", "trailers", "te", "TRAILERS"}, false, true},
		{"TE empty list members", []string{"te", ",trailers,,"}, false, true},
		{"TE forbidden coding", []string{"te", "trailers,gzip"}, false, false},
		{"TE Unicode lookalike", []string{"te", "trailer\u017f"}, false, false},
		{"TE trailer field", []string{"te", "trailers"}, true, false},
	} {
		t.Run("request/"+tc.name, func(t *testing.T) {
			conn := conformanceServer(t, func(w http.ResponseWriter, r *http.Request) {
				io.ReadAll(r.Body)
				w.Write([]byte("ok"))
			})
			fields := []string{":method", "POST", ":scheme", "https", ":authority", "localhost", ":path", "/"}
			var data []byte
			if tc.trailer {
				data = append(conformanceHeaders(t, fields...), conformanceHeaders(t, tc.fields...)...)
			} else {
				data = conformanceHeaders(t, append(fields, tc.fields...)...)
			}
			str := conformanceRequest(t, conn, data, true)
			if tc.valid {
				require.Equal(t, []string{"200"}, decodeHeader(t, str)[":status"])
				_, err := io.ReadAll(str)
				require.NoError(t, err)
			} else {
				_, err := io.ReadAll(str)
				require.ErrorIs(t, err, &quic.StreamError{Remote: true, StreamID: str.StreamID(), ErrorCode: quic.StreamErrorCode(ErrCodeMessageError)})
			}
		})
	}
	for _, tc := range []struct {
		name, key, value string
		trailer          bool
	}{
		{"leading space", "x-test", " leading", false},
		{"trailing tab", "x-test", "trailing\t", false},
		{"trailer edge whitespace", "x-test", " leading", true},
		{"TE response", "te", "trailers", false},
		{"TE trailer", "te", "trailers", true},
	} {
		t.Run("response/"+tc.name, func(t *testing.T) {
			client, server := newConnPair(t)
			cc := (&Transport{DisableCompression: true}).NewClientConn(client)
			stream, err := cc.OpenRequestStream(context.Background())
			require.NoError(t, err)
			require.NoError(t, stream.SetDeadline(time.Now().Add(time.Second)))
			require.NoError(t, stream.SendRequestHeader(httptest.NewRequest("GET", "https://localhost/", nil)))
			peer, err := server.AcceptStream(context.Background())
			require.NoError(t, err)
			data := conformanceHeaders(t, ":status", "200", tc.key, tc.value)
			if tc.trailer {
				data = append(conformanceHeaders(t, ":status", "200"), conformanceHeaders(t, tc.key, tc.value)...)
			}
			_, err = peer.Write(data)
			require.NoError(t, err)
			require.NoError(t, peer.Close())
			rsp, err := stream.ReadResponse()
			if err == nil {
				_, err = io.ReadAll(rsp.Body)
			}
			require.Error(t, err)
			require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
			_, err = io.ReadAll(peer)
			require.ErrorIs(t, err, &quic.StreamError{Remote: true, StreamID: peer.StreamID(), ErrorCode: quic.StreamErrorCode(ErrCodeMessageError)})
		})
	}
}

func TestResponseConnectionSpecificFieldsAreOmitted(t *testing.T) {
	w := newTestResponseWriter(t)
	for _, name := range []string{"connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "te"} {
		w.Header()[name] = []string{"legacy-value"}
	}
	// Exercise noncanonical keys, multiple field lines and case-insensitive
	// connection options without editing the application's original Header map.
	w.Header()["connection"] = []string{"close, X-Hop", "x-OTHER"}
	w.Header().Set("X-Hop", "private")
	w.Header().Set("X-Other", "also-private")
	w.Header().Set("X-End-To-End", "public")
	w.Header().Set("Trailer", "X-Trailer, Upgrade, X-Hop")
	_, err := w.Write([]byte("body"))
	require.NoError(t, err)
	w.Header().Set("X-Trailer", "trailer-value")
	w.Header().Set("X-Hop", "private-trailer")
	w.Header().Set("Upgrade", "legacy-protocol")
	headers := w.DecodeHeaders(t, 0)
	require.Equal(t, []string{"public"}, headers["x-end-to-end"])
	for _, name := range []string{"connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "te", "x-hop", "x-other"} {
		require.NotContains(t, headers, name)
	}
	require.Equal(t, []byte("body"), w.DecodeBody(t))
	trailers := w.DecodeHeaders(t, 2)
	require.Equal(t, map[string][]string{"x-trailer": {"trailer-value"}}, trailers)
	require.Equal(t, []string{"close, X-Hop", "x-OTHER"}, w.Header()["connection"])
	require.Equal(t, "private-trailer", w.Header().Get("X-Hop"))
}

func TestOutgoingTrailersOmitConnectionSpecificFields(t *testing.T) {
	trailers := http.Header{
		"Connection": {"X-Hop"}, "X-Hop": {"private"},
		"Keep-Alive": {"timeout=5"}, "Proxy-Connection": {"close"},
		"Transfer-Encoding": {"chunked"}, "Upgrade": {"legacy"},
		"Te": {"trailers"}, "X-Trailer": {"public"},
	}
	var buf bytes.Buffer
	written, err := writeTrailers(&buf, trailers, 0, nil)
	require.NoError(t, err)
	require.True(t, written)
	require.Equal(t, map[string][]string{"x-trailer": {"public"}}, decodeHeader(t, &buf))
	require.Equal(t, "private", trailers.Get("X-Hop"))
}
