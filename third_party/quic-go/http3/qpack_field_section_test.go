package http3

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

func qpackHeadersWithBase(t *testing.T, base []byte, fields ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := qpack.NewEncoder(&buf)
	for i := 0; i < len(fields); i += 2 {
		require.NoError(t, enc.WriteField(qpack.HeaderField{Name: fields[i], Value: fields[i+1]}))
	}
	require.NoError(t, enc.Close())
	require.Equal(t, []byte{0, 0}, buf.Bytes()[:2])
	block := append([]byte{0}, base...)
	block = append(block, buf.Bytes()[2:]...)
	return append((&headersFrame{Length: uint64(len(block))}).Append(nil), block...)
}

func TestQPACKFieldSectionPrefixBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		block []byte
		valid bool
		field bool
	}{
		{"empty field section", []byte{0, 0}, true, false},
		{"empty section positive Base", []byte{0, 1}, true, false},
		{"maximum nonminimal width", []byte{0, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0}, true, false},
		{"positive Base with static field", []byte{0, 1, 0xd9}, true, true},
		{"maximum Base with static field", []byte{0, 0x7f, 0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f, 0xd9}, true, true},
		{"missing Required Insert Count", nil, false, false},
		{"missing Base", []byte{0}, false, false},
		{"truncated Base", []byte{0, 0x7f}, false, false},
		{"truncated continuation", []byte{0, 0x7f, 0x80}, false, false},
		{"negative Base", []byte{0, 0x80, 0xd9}, false, false},
		{"negative Base with extended delta", []byte{0, 0xff, 0}, false, false},
		{"Base exceeds supported range", []byte{0, 0x7f, 0x81, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f, 0xd9}, false, false},
		{"Base exceeds encoded length limit", []byte{0, 0x7f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0, 0xd9}, false, false},
		{"nonzero Required Insert Count", []byte{1, 0, 0xd9}, false, false},
		{"dynamic reference remains invalid", []byte{0, 1, 0x80}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := bytes.Clone(tc.block)
			decode := decodeFieldSection(qpack.NewDecoder(), tc.block)
			field, err := decode()
			if !tc.valid {
				require.Error(t, err)
				require.NotErrorIs(t, err, io.EOF, "invalid prefixes must not become an empty field section")
			} else if tc.field {
				require.NoError(t, err)
				require.Equal(t, qpack.HeaderField{Name: ":status", Value: "200"}, field)
				_, err = decode()
				require.ErrorIs(t, err, io.EOF)
			} else {
				require.ErrorIs(t, err, io.EOF)
			}
			require.Equal(t, original, tc.block, "decoding must not mutate the received field section")
		})
	}
}

// Exercise the production request, response and trailer decode paths over
// real QUIC pairs. Base does not affect static-table field representations.
func TestQPACKFieldSectionBaseConformance(t *testing.T) {
	for _, tc := range []struct {
		name  string
		base  []byte
		valid bool
	}{
		{"zero", []byte{0}, true},
		{"positive", []byte{1}, true},
		{"prefixed", []byte{0x7f, 0}, true},
		{"nonminimal", []byte{0x7f, 0x80, 0}, true},
		{"maximum 62-bit Base", []byte{0x7f, 0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f}, true},
		{"negative Base", []byte{0x80}, false},
		{"negative Base with delta", []byte{0x81}, false},
	} {
		for _, trailers := range []bool{false, true} {
			part := "headers"
			if trailers {
				part = "trailers"
			}
			t.Run("request/"+part+"/"+tc.name, func(t *testing.T) {
				conn := conformanceServer(t, func(w http.ResponseWriter, r *http.Request) {
					io.ReadAll(r.Body) // Ignore errors: enforcement belongs to the HTTP/3 layer.
					w.WriteHeader(http.StatusOK)
				})
				fields := []string{":method", "POST", ":scheme", "https", ":authority", "localhost", ":path", "/"}
				data := qpackHeadersWithBase(t, tc.base, fields...)
				if trailers {
					data = append(conformanceHeaders(t, fields...), qpackHeadersWithBase(t, tc.base, "x-trailer", "value")...)
				}
				str := conformanceRequest(t, conn, data, true)
				if !tc.valid {
					io.ReadAll(str)
					conformanceConnectionError(t, conn, ErrCodeQPACKDecompressionFailed)
					return
				}
				require.Equal(t, []string{"200"}, decodeHeader(t, str)[":status"])
				_, err := io.ReadAll(str)
				require.NoError(t, err)
				ordinary := conformanceRequest(t, conn, conformanceHeaders(t, ":method", "GET", ":scheme", "https", ":authority", "localhost", ":path", "/"), true)
				require.Equal(t, []string{"200"}, decodeHeader(t, ordinary)[":status"])
				_, err = io.ReadAll(ordinary)
				require.NoError(t, err)
			})
			t.Run("response/"+part+"/"+tc.name, func(t *testing.T) {
				client, server := newConnPair(t)
				cc := (&Transport{DisableCompression: true}).NewClientConn(client)
				stream, err := cc.OpenRequestStream(context.Background())
				require.NoError(t, err)
				require.NoError(t, stream.SetDeadline(time.Now().Add(2*time.Second)))
				require.NoError(t, stream.SendRequestHeader(httptest.NewRequest("GET", "https://localhost/", nil)))
				peer, err := server.AcceptStream(context.Background())
				require.NoError(t, err)
				data := qpackHeadersWithBase(t, tc.base, ":status", "200")
				if trailers {
					data = append(conformanceHeaders(t, ":status", "200"), qpackHeadersWithBase(t, tc.base, "x-trailer", "value")...)
				}
				_, err = peer.Write(data)
				require.NoError(t, err)
				require.NoError(t, peer.Close())
				rsp, err := stream.ReadResponse()
				if err == nil {
					_, err = io.ReadAll(rsp.Body)
				}
				if !tc.valid {
					require.Error(t, err)
					conformanceConnectionError(t, server, ErrCodeQPACKDecompressionFailed)
					return
				}
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rsp.StatusCode)
				if trailers {
					require.Equal(t, "value", rsp.Trailer.Get("X-Trailer"))
				}
				require.NoError(t, context.Cause(client.Context()))
			})
		}
	}
}
