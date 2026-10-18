package http3

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResponseWriterOmitsInvalidFields(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
	}{
		{"", "value"},
		{"Bad Name", "value"},
		{"Bad:Name", "value"},
		{":status", "599"},
		{":path", "/injected"},
		{"X-\u212aey", "value"},
		{"X-Test", "before\rafter"},
		{"X-Test", "before\nafter"},
		{"X-Test", "before\x00after"},
		{"X-Test", "before\x7fafter"},
	} {
		t.Run(tc.name+"/"+tc.value, func(t *testing.T) {
			w := newTestResponseWriter(t)
			w.Header()[tc.name] = []string{tc.value}
			w.Header()["X-Valid"] = []string{"", " \ttrimmed\t ", "a\tb", "\x80\xff"}
			w.Header()["Content-Type"] = nil // Preserve the standard suppression sentinel.
			fields := w.DecodeHeaders(t, 0)
			require.Equal(t, []string{"200"}, fields[":status"])
			if tc.name != ":status" {
				require.NotContains(t, fields, strings.ToLower(tc.name))
			}
			require.NotContains(t, fields, "content-type")
			require.Equal(t, []string{"", "trimmed", "a\tb", "\x80\xff"}, fields["x-valid"])
			require.Equal(t, []string{tc.value}, w.Header()[tc.name], "filtering must not mutate the handler's map")
		})
	}
}

func TestOutgoingTrailersOmitInvalidValues(t *testing.T) {
	trailers := http.Header{
		"X-Mixed": {"first", "bad\rvalue", "bad\nvalue", "bad\x00value", "bad\x7fvalue", " \tlast\t "},
		"X-Empty": {""},
		"X-Obs":   {"\x80\xff"},
	}
	var b bytes.Buffer
	written, err := writeTrailers(&b, trailers, 0, nil)
	require.NoError(t, err)
	require.True(t, written)
	fields := decodeHeader(t, &b)
	require.Equal(t, []string{"first", "last"}, fields["x-mixed"])
	require.Equal(t, []string{""}, fields["x-empty"])
	require.Equal(t, []string{"\x80\xff"}, fields["x-obs"])
	require.Equal(t, "bad\rvalue", trailers["X-Mixed"][1])
}

func TestOutgoingTrailersAllInvalidValues(t *testing.T) {
	var b bytes.Buffer
	written, err := writeTrailers(&b, http.Header{"X-Trailer": {"bad\rvalue", "bad\nvalue", "bad\x00value"}}, 0, nil)
	require.NoError(t, err)
	require.False(t, written)
	require.Empty(t, b.Bytes(), "do not emit a HEADERS frame with an empty QPACK payload")
}

func TestConformanceResponseOmitsInvalidFields(t *testing.T) {
	conn := conformanceServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header()[":path"] = []string{"/injected"}
		w.Header()["X-Mixed"] = []string{"valid", "bad\r\nvalue"}
		w.Header().Set("Trailer", "X-Trailer")
		_, err := w.Write([]byte("body"))
		if err != nil {
			panic(err)
		}
		w.Header()["X-Trailer"] = []string{"valid-trailer", "bad\x00value"}
	})
	str := conformanceRequest(t, conn, conformanceHeaders(t, ":method", "GET", ":scheme", "https", ":authority", "localhost", ":path", "/"), true)
	fields := decodeHeader(t, str)
	require.Equal(t, []string{"200"}, fields[":status"])
	require.NotContains(t, fields, ":path")
	require.Equal(t, []string{"valid"}, fields["x-mixed"])
	fp := &frameParser{r: str}
	f, err := fp.ParseNext(nil)
	require.NoError(t, err)
	require.IsType(t, &dataFrame{}, f)
	body := make([]byte, f.(*dataFrame).Length)
	_, err = io.ReadFull(str, body)
	require.NoError(t, err)
	require.Equal(t, "body", string(body))
	require.Equal(t, []string{"valid-trailer"}, decodeHeader(t, str)["x-trailer"])
	_, err = io.ReadAll(str)
	require.NoError(t, err)
}

func TestConformanceResponseAllInvalidTrailerValues(t *testing.T) {
	conn := conformanceServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Trailer")
		_, err := w.Write([]byte("body"))
		if err != nil {
			panic(err)
		}
		w.Header()["X-Trailer"] = []string{"bad\rvalue", "bad\nvalue", "bad\x00value"}
	})
	str := conformanceRequest(t, conn, conformanceHeaders(t, ":method", "GET", ":scheme", "https", ":authority", "localhost", ":path", "/"), true)
	require.Equal(t, []string{"200"}, decodeHeader(t, str)[":status"])
	fp := &frameParser{r: str}
	f, err := fp.ParseNext(nil)
	require.NoError(t, err)
	require.IsType(t, &dataFrame{}, f)
	body := make([]byte, f.(*dataFrame).Length)
	_, err = io.ReadFull(str, body)
	require.NoError(t, err)
	require.Equal(t, "body", string(body))
	_, err = fp.ParseNext(nil)
	require.ErrorIs(t, err, io.EOF)
}
