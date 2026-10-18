package http3

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func conformanceHeaders(t *testing.T, fields ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := qpack.NewEncoder(&buf)
	for i := 0; i < len(fields); i += 2 {
		require.NoError(t, enc.WriteField(qpack.HeaderField{Name: fields[i], Value: fields[i+1]}))
	}
	require.NoError(t, enc.Close())
	return append((&headersFrame{Length: uint64(buf.Len())}).Append(nil), buf.Bytes()...)
}

func conformanceServer(t *testing.T, handler http.HandlerFunc) *quic.Conn {
	t.Helper()
	client, server := newConnPair(t)
	s := &Server{Handler: handler}
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.ServeQUICConn(server)
	}()
	t.Cleanup(func() {
		s.Close()
		server.CloseWithError(0, "")
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("HTTP/3 server did not stop")
		}
	})
	return client
}

func conformanceRequest(t *testing.T, conn *quic.Conn, data []byte, fin bool) *quic.Stream {
	t.Helper()
	str, err := conn.OpenStream()
	require.NoError(t, err)
	require.NoError(t, str.SetDeadline(time.Now().Add(2*time.Second)))
	_, err = str.Write(data)
	require.NoError(t, err)
	if fin {
		require.NoError(t, str.Close())
	}
	return str
}

func conformanceConnectionError(t *testing.T, conn *quic.Conn, code ErrCode) {
	t.Helper()
	select {
	case <-conn.Context().Done():
		require.ErrorIs(t, context.Cause(conn.Context()), &quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(code)})
	case <-time.After(time.Second):
		t.Fatalf("connection was not closed with %s", code)
	}
}

func TestConformanceRequestErrors(t *testing.T) {
	head := conformanceHeaders(t, ":method", "POST", ":scheme", "https", ":authority", "localhost", ":path", "/")
	trailers := conformanceHeaders(t, "x-trailer", "value")
	for _, tc := range []struct {
		name       string
		data       []byte
		code       ErrCode
		connection bool
	}{
		{"missing scheme", conformanceHeaders(t, ":method", "GET", ":authority", "localhost", ":path", "/"), ErrCodeMessageError, false},
		{"empty scheme", conformanceHeaders(t, ":method", "GET", ":scheme", "", ":authority", "localhost", ":path", "/"), ErrCodeMessageError, false},
		{"empty content length", conformanceHeaders(t, ":method", "POST", ":scheme", "https", ":authority", "localhost", ":path", "/", "content-length", ""), ErrCodeMessageError, false},
		{"short content", append(conformanceHeaders(t, ":method", "POST", ":scheme", "https", ":authority", "localhost", ":path", "/", "content-length", "5"), getDataFrame([]byte("abc"))...), ErrCodeMessageError, false},
		{"short content with trailers", append(append(conformanceHeaders(t, ":method", "POST", ":scheme", "https", ":authority", "localhost", ":path", "/", "content-length", "5"), getDataFrame([]byte("abc"))...), trailers...), ErrCodeMessageError, false},
		{"pseudo header in trailers", append(bytes.Clone(head), conformanceHeaders(t, ":path", "/bad")...), ErrCodeMessageError, false},
		{"DATA after trailers", append(append(bytes.Clone(head), trailers...), getDataFrame([]byte("abc"))...), ErrCodeFrameUnexpected, true},
		{"second trailers", append(append(bytes.Clone(head), trailers...), trailers...), ErrCodeFrameUnexpected, true},
		{"invalid initial QPACK index", []byte{1, 4, 0, 0, 0xff, 0x24}, ErrCodeQPACKDecompressionFailed, true},
		{"invalid trailer QPACK index", append(bytes.Clone(head), 1, 4, 0, 0, 0xff, 0x24), ErrCodeQPACKDecompressionFailed, true},
		{"truncated initial HEADERS", []byte{1, 4, 0}, ErrCodeFrameError, true},
		{"truncated DATA", append(bytes.Clone(head), 0, 5, 'a'), ErrCodeFrameError, true},
		{"truncated trailer HEADERS", append(bytes.Clone(head), 1, 4, 0), ErrCodeFrameError, true},
		{"truncated frame type", append(bytes.Clone(head), 0x40), ErrCodeFrameError, true},
		{"missing frame length", append(bytes.Clone(head), 0), ErrCodeFrameError, true},
		{"truncated unknown frame payload", append(bytes.Clone(head), 0x21, 3, 'x'), ErrCodeFrameError, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := conformanceServer(t, func(w http.ResponseWriter, r *http.Request) {
				// Ignore application errors deliberately: the protocol layer must
				// enforce the wire error without relying on handler cooperation.
				io.ReadAll(r.Body)
				w.Write([]byte("ok"))
			})
			str := conformanceRequest(t, conn, tc.data, true)
			_, err := io.ReadAll(str)
			if tc.connection {
				conformanceConnectionError(t, conn, tc.code)
				return
			}
			require.ErrorIs(t, err, &quic.StreamError{Remote: true, StreamID: str.StreamID(), ErrorCode: quic.StreamErrorCode(tc.code)})
			// Malformed-message errors must not poison other requests.
			good := conformanceRequest(t, conn, conformanceHeaders(t, ":method", "GET", ":scheme", "https", ":authority", "localhost", ":path", "/"), true)
			require.Equal(t, []string{"200"}, decodeHeader(t, good)[":status"])
			_, err = io.ReadAll(good)
			require.NoError(t, err)
		})
	}
}

func TestConformanceSettings(t *testing.T) {
	for _, tc := range []struct {
		id    uint64
		value uint64
	}{{2, 0}, {3, 0}, {4, 0}, {5, 0}, {settingDatagram, 2}, {settingExtendedConnect, 2}} {
		t.Run(fmt.Sprintf("%x=%d", tc.id, tc.value), func(t *testing.T) {
			conn := conformanceServer(t, nil)
			str, err := conn.OpenUniStream()
			require.NoError(t, err)
			payload := quicvarint.Append(quicvarint.Append(nil, tc.id), tc.value)
			data := quicvarint.Append(nil, streamTypeControlStream)
			data = quicvarint.Append(data, 4)
			data = quicvarint.Append(data, uint64(len(payload)))
			_, err = str.Write(append(data, payload...))
			require.NoError(t, err)
			conformanceConnectionError(t, conn, ErrCodeSettingsError)
		})
	}
}

func TestConformanceOrdinaryContentAndTrailers(t *testing.T) {
	for _, contentLength := range []string{"", "0", "3"} {
		t.Run("content-length="+contentLength, func(t *testing.T) {
			conn := conformanceServer(t, func(w http.ResponseWriter, r *http.Request) {
				data, err := io.ReadAll(r.Body)
				if err != nil {
					panic(err)
				}
				if r.Trailer.Get("X-Trailer") != "value" {
					panic("missing request trailer")
				}
				w.Header().Set("Trailer", "X-Response-Trailer")
				w.Write(data)
				w.Header().Set("X-Response-Trailer", "response-value")
			})
			fields := []string{":method", "POST", ":scheme", "https", ":authority", "localhost", ":path", "/"}
			if contentLength != "" {
				fields = append(fields, "content-length", contentLength)
			}
			data := conformanceHeaders(t, fields...)
			data = append(data, getDataFrame(nil)...)
			if contentLength == "3" {
				data = append(data, getDataFrame([]byte("abc"))...)
			}
			data = append(data, getDataFrame(nil)...)
			data = append(data, conformanceHeaders(t, "x-trailer", "value")...)
			str := conformanceRequest(t, conn, data, true)
			require.Equal(t, []string{"200"}, decodeHeader(t, str)[":status"])
			fp := frameParser{r: str}
			var body []byte
			for {
				f, err := fp.ParseNext(nil)
				require.NoError(t, err)
				if _, ok := f.(*headersFrame); ok {
					// decodeHeader reads the frame header as well, so reconstruct it.
					trailer := decodeHeader(t, io.MultiReader(bytes.NewReader(f.(*headersFrame).Append(nil)), str))
					require.Equal(t, []string{"response-value"}, trailer["x-response-trailer"])
					break
				}
				payload := make([]byte, f.(*dataFrame).Length)
				_, err = io.ReadFull(str, payload)
				require.NoError(t, err)
				body = append(body, payload...)
			}
			if contentLength == "3" {
				require.Equal(t, "abc", string(body))
			} else {
				require.Empty(t, body)
			}
			_, err := fp.ParseNext(nil)
			require.ErrorIs(t, err, io.EOF)
		})
	}
}

func TestConformanceSuccessfulConnect(t *testing.T) {
	for _, tc := range []struct {
		status  int
		trailer bool
	}{
		{200, false}, {200, true}, {204, false}, {204, true},
	} {
		t.Run(fmt.Sprintf("status=%d/trailers=%t", tc.status, tc.trailer), func(t *testing.T) {
			conn := conformanceServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "0")
				w.WriteHeader(tc.status)
				w.(http.Flusher).Flush()
				data, err := io.ReadAll(r.Body)
				if err == nil {
					w.Write(data)
				}
			})
			str := conformanceRequest(t, conn, conformanceHeaders(t, ":method", "CONNECT", ":authority", "localhost:443", "content-length", "0"), false)
			hdr := decodeHeader(t, str)
			require.Equal(t, []string{fmt.Sprint(tc.status)}, hdr[":status"])
			require.NotContains(t, hdr, "content-length")
			if tc.trailer {
				// The frame type alone must be rejected after success; no length
				// or payload is needed to establish an invalid tunnel frame.
				_, err := str.Write([]byte{1})
				require.NoError(t, err)
				conformanceConnectionError(t, conn, ErrCodeFrameUnexpected)
				return
			}
			_, err := str.Write(getDataFrame([]byte("tunnel bytes")))
			require.NoError(t, err)
			require.NoError(t, str.Close())
			f, err := (&frameParser{r: str}).ParseNext(nil)
			require.NoError(t, err)
			require.Equal(t, &dataFrame{Length: 12}, f)
			data, err := io.ReadAll(str)
			require.NoError(t, err)
			require.Equal(t, "tunnel bytes", string(data))
		})
	}
}

func TestConformanceResponseContentLengthExceptions(t *testing.T) {
	for _, tc := range []struct {
		name, method string
		status       int
		body         string
		lengths      []string
	}{
		{"HEAD representation length", "HEAD", 200, "", []string{"100"}},
		{"304 representation length", "GET", 304, "", []string{"100"}},
		{"CONNECT ignores length", "CONNECT", 200, "tunnel bytes", []string{"0"}},
		{"CONNECT ignores empty length", "CONNECT", 200, "tunnel bytes", []string{""}},
		{"CONNECT ignores nonnumeric length", "CONNECT", 200, "tunnel bytes", []string{"invalid"}},
		{"CONNECT ignores negative length", "CONNECT", 200, "tunnel bytes", []string{"-1"}},
		{"CONNECT ignores contradictory lengths", "CONNECT", 200, "tunnel bytes", []string{"5", "7"}},
		{"CONNECT ignores repeated empty lengths", "CONNECT", 200, "tunnel bytes", []string{"", ""}},
		{"CONNECT ignores mixed lengths", "CONNECT", 200, "tunnel bytes", []string{"0", "invalid"}},
		{"CONNECT 204 ignores empty length", "CONNECT", 204, "tunnel bytes", []string{""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := newConnPair(t)
			cc := (&Transport{DisableCompression: true}).NewClientConn(client)
			stream, err := cc.OpenRequestStream(context.Background())
			require.NoError(t, err)
			require.NoError(t, stream.SetDeadline(time.Now().Add(2*time.Second)))
			require.NoError(t, stream.SendRequestHeader(httptest.NewRequest(tc.method, "https://localhost/", nil)))
			peer, err := server.AcceptStream(context.Background())
			require.NoError(t, err)
			fields := []string{":status", fmt.Sprint(tc.status)}
			for _, length := range tc.lengths {
				fields = append(fields, "content-length", length)
			}
			data := conformanceHeaders(t, fields...)
			if tc.body != "" {
				data = append(data, getDataFrame([]byte(tc.body))...)
			}
			_, err = peer.Write(data)
			require.NoError(t, err)
			require.NoError(t, peer.Close())
			rsp, err := stream.ReadResponse()
			require.NoError(t, err)
			body, err := io.ReadAll(rsp.Body)
			require.NoError(t, err)
			require.Equal(t, tc.body, string(body))
			if tc.method == "CONNECT" {
				require.Equal(t, tc.lengths, rsp.Header.Values("Content-Length"))
				require.Zero(t, rsp.ContentLength)
			}
		})
	}
}

func TestConformanceResponseErrors(t *testing.T) {
	initial := conformanceHeaders(t, ":status", "200")
	trailer := conformanceHeaders(t, "x-trailer", "value")
	for _, tc := range []struct {
		name       string
		method     string
		data       []byte
		code       ErrCode
		connection bool
	}{
		{"initial QPACK index", "GET", []byte{1, 4, 0, 0, 0xff, 0x24}, ErrCodeQPACKDecompressionFailed, true},
		{"trailer QPACK index", "GET", append(bytes.Clone(initial), 1, 4, 0, 0, 0xff, 0x24), ErrCodeQPACKDecompressionFailed, true},
		{"truncated initial HEADERS", "GET", []byte{1, 4, 0}, ErrCodeFrameError, true},
		{"truncated DATA", "GET", append(bytes.Clone(initial), 0, 5, 'a'), ErrCodeFrameError, true},
		{"DATA after trailers", "GET", append(append(bytes.Clone(initial), trailer...), getDataFrame([]byte("abc"))...), ErrCodeFrameUnexpected, true},
		{"second trailers", "GET", append(append(bytes.Clone(initial), trailer...), trailer...), ErrCodeFrameUnexpected, true},
		{"pseudo header in trailer", "GET", append(bytes.Clone(initial), conformanceHeaders(t, ":path", "/bad")...), ErrCodeMessageError, false},
		{"empty content length", "GET", conformanceHeaders(t, ":status", "200", "content-length", ""), ErrCodeMessageError, false},
		{"nonnumeric content length", "GET", conformanceHeaders(t, ":status", "200", "content-length", "invalid"), ErrCodeMessageError, false},
		{"negative content length", "GET", conformanceHeaders(t, ":status", "200", "content-length", "-1"), ErrCodeMessageError, false},
		{"contradictory content lengths", "GET", conformanceHeaders(t, ":status", "200", "content-length", "5", "content-length", "7"), ErrCodeMessageError, false},
		{"refused CONNECT empty content length", "CONNECT", conformanceHeaders(t, ":status", "403", "content-length", ""), ErrCodeMessageError, false},
		{"short content", "GET", append(conformanceHeaders(t, ":status", "200", "content-length", "5"), getDataFrame([]byte("abc"))...), ErrCodeMessageError, false},
		{"HEADERS after CONNECT success", "CONNECT", append(bytes.Clone(initial), 1), ErrCodeFrameUnexpected, true},
		{"PUSH_PROMISE after CONNECT success", "CONNECT", append(bytes.Clone(initial), 5), ErrCodeFrameUnexpected, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := newConnPair(t)
			cc := (&Transport{DisableCompression: true}).NewClientConn(client)
			stream, err := cc.OpenRequestStream(context.Background())
			require.NoError(t, err)
			require.NoError(t, stream.SetDeadline(time.Now().Add(2*time.Second)))
			require.NoError(t, stream.SendRequestHeader(httptest.NewRequest(tc.method, "https://localhost/", nil)))
			peer, err := server.AcceptStream(context.Background())
			require.NoError(t, err)
			_, err = peer.Write(tc.data)
			require.NoError(t, err)
			// Keep the send direction open on malformed messages so STOP_SENDING
			// remains observable; truncation and short content need clean FIN.
			if tc.connection || tc.name == "short content" {
				require.NoError(t, peer.Close())
			}
			rsp, err := stream.ReadResponse()
			if err == nil {
				_, err = io.ReadAll(rsp.Body)
			}
			require.Error(t, err)
			if tc.connection {
				conformanceConnectionError(t, server, tc.code)
			} else {
				require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
				_, peerErr := io.ReadAll(peer)
				require.ErrorIs(t, peerErr, &quic.StreamError{Remote: true, StreamID: peer.StreamID(), ErrorCode: quic.StreamErrorCode(tc.code)})
				require.NoError(t, context.Cause(client.Context()))
			}
		})
	}
}
