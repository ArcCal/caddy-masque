package http2_test

import (
	"io"
	"net/http"
	"testing"

	. "golang.org/x/net/http2"
)

// Send raw HPACK fields so the transport cannot supply missing pseudo-headers
// or normalize invalid values. Every rejection must leave another request usable.
func TestServerRequestConformance(t *testing.T) {
	connect := []string{":method", "CONNECT", ":protocol", "connect-ip", ":scheme", "https", ":authority", "example.com", ":path", "/vpn"}
	get := []string{":method", "GET", ":scheme", "https", ":authority", "example.com", ":path", "/"}
	replace := func(fields []string, name, value string, omit bool) []string {
		var result []string
		for i := 0; i < len(fields); i += 2 {
			if fields[i] == name {
				if !omit {
					result = append(result, name, value)
				}
			} else {
				result = append(result, fields[i:i+2]...)
			}
		}
		return result
	}
	type requestCase struct {
		name   string
		fields []string
		valid  bool
	}
	tests := []requestCase{
		{"connect-ip", connect, true},
		{"connect-ip-http-scheme", replace(connect, ":scheme", "http", false), true},
		{"connect-ip-other-uri-scheme", replace(connect, ":scheme", "custom", false), true},
		{"missing-scheme", replace(connect, ":scheme", "", true), false},
		{"empty-scheme", replace(connect, ":scheme", "", false), false},
		{"scheme-whitespace", replace(connect, ":scheme", "https\t", false), false},
		{"missing-path", replace(connect, ":path", "", true), false},
		{"empty-path", replace(connect, ":path", "", false), false},
		{"path-whitespace", replace(connect, ":path", "/vpn ", false), false},
		{"connect-ip-asterisk-path", replace(connect, ":path", "*", false), false},
		{"missing-authority", replace(connect, ":authority", "", true), false},
		{"missing-authority-with-host", append(replace(connect, ":authority", "", true), "host", "example.com"), false},
		{"empty-authority-with-host", append(replace(connect, ":authority", "", false), "host", "example.com"), false},
		{"authority-whitespace", replace(connect, ":authority", " example.com", false), false},
		{"wrong-method", replace(connect, ":method", "GET", false), false},
		{"empty-protocol", replace(connect, ":protocol", "", false), false},
		{"empty-protocol-wrong-method", replace(replace(connect, ":method", "GET", false), ":protocol", "", false), false},
		{"classic-connect", []string{":method", "CONNECT", ":authority", "example.com:443"}, true},
		{"classic-connect-empty-path", []string{":method", "CONNECT", ":authority", "example.com:443", ":path", ""}, false},
		{"classic-connect-empty-scheme", []string{":method", "CONNECT", ":authority", "example.com:443", ":scheme", ""}, false},
		// RFC 8441 uses ordinary request authority rules. Only CONNECT-IP
		// requires :authority explicitly, so retain Host fallback elsewhere.
		{"websocket-host-fallback", []string{":method", "CONNECT", ":protocol", "websocket", ":scheme", "https", ":path", "/ws", "host", "example.com"}, true},
		{"ordinary-host-fallback", []string{":method", "GET", ":scheme", "https", ":path", "/", "host", "example.com"}, true},
		{"ordinary-empty-authority-with-host", append(replace(get, ":authority", "", false), "host", "example.com"), false},
		{"get-asterisk-path", replace(get, ":path", "*", false), false},
		{"options-asterisk-path", replace(replace(get, ":method", "OPTIONS", false), ":path", "*", false), true},
		{"websocket-empty-authority-with-host", []string{":method", "CONNECT", ":protocol", "websocket", ":scheme", "https", ":authority", "", ":path", "/ws", "host", "example.com"}, false},
	}
	for _, name := range []string{"connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"} {
		tests = append(tests, requestCase{name, append(append([]string(nil), get...), name, "value"), false})
	}
	for _, value := range []string{"gzip", "gzip, trailers"} {
		tests = append(tests, requestCase{"te-" + value, append(append([]string(nil), get...), "te", value), false})
	}
	for _, value := range []string{" leading", "\tleading", "trailing ", "trailing\t", " ", "\t", "inner \t space", ""} {
		tests = append(tests, requestCase{"field-value-" + value, append(append([]string(nil), get...), "x-test", value), value == "" || value == "inner \t space"})
	}
	tests = append(tests, requestCase{"te-trailers", append(append([]string(nil), get...), "te", "trailers"), true})
	tests = append(tests, requestCase{"te-trailers-list", append(append([]string(nil), get...), "te", "Trailers, trailers", "te", "TRAILERS"), true})
	tests = append(tests, requestCase{"te-empty-list", append(append([]string(nil), get...), "te", ""), true})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetDisableExtendedConnectProtocol(t, false)
			synctestTest(t, func(t testing.TB) {
				st := newServerTester(t, func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/control" && !tt.valid {
						t.Error("malformed request reached handler")
					}
					w.WriteHeader(http.StatusNoContent)
				})
				defer st.Close()
				st.greet()
				st.writeHeaders(HeadersFrameParam{StreamID: 1, BlockFragment: st.encodeHeaderRaw(tt.fields...), EndHeaders: true, EndStream: true})
				if tt.valid {
					st.wantHeaders(wantHeader{streamID: 1, endStream: true, header: http.Header{":status": {"204"}}})
				} else {
					st.wantRSTStream(1, ErrCodeProtocol)
				}
				st.writeHeaders(HeadersFrameParam{StreamID: 3, BlockFragment: st.encodeHeader(":path", "/control"), EndHeaders: true, EndStream: true})
				st.wantHeaders(wantHeader{streamID: 3, endStream: true, header: http.Header{":status": {"204"}}})
			})
		})
	}
}

func TestServerTrailerConformance(t *testing.T) {
	for _, declared := range []bool{false, true} {
		for _, tt := range []struct {
			name, value string
			valid       bool
		}{
			{"x-test", " leading", false},
			{"x-test", "\tleading", false},
			{"x-test", "trailing ", false},
			{"x-test", "trailing\t", false},
			{"connection", "keep-alive", false},
			{"keep-alive", "timeout=1", false},
			{"proxy-connection", "keep-alive", false},
			{"transfer-encoding", "chunked", false},
			{"upgrade", "websocket", false},
			{"te", "gzip", false},
			{"x-test", "inner \t space", true},
			{"x-test", "", true},
		} {
			name := "undeclared/"
			if declared {
				name = "declared/"
			}
			t.Run(name+tt.name+"/"+tt.value, func(t *testing.T) {
				synctestTest(t, func(t testing.TB) {
					st := newServerTester(t, nil)
					defer st.Close()
					st.greet()
					var headers []string
					if declared {
						headers = []string{"trailer", "X-Test"}
					}
					st.writeHeaders(HeadersFrameParam{StreamID: 1, BlockFragment: st.encodeHeader(headers...), EndHeaders: true})
					call := st.nextHandlerCall()
					st.writeHeaders(HeadersFrameParam{StreamID: 1, BlockFragment: st.encodeHeaderRaw(tt.name, tt.value), EndHeaders: true, EndStream: true})
					if !tt.valid {
						st.wantRSTStream(1, ErrCodeProtocol)
					}
					call.do(func(w http.ResponseWriter, r *http.Request) {
						_, err := io.ReadAll(r.Body)
						if (err == nil) != tt.valid {
							t.Errorf("body error = %v, valid trailer = %v", err, tt.valid)
						}
						w.WriteHeader(http.StatusNoContent)
					})
					call.exit()
					if tt.valid {
						st.wantHeaders(wantHeader{streamID: 1, endStream: true, header: http.Header{":status": {"204"}}})
					}
					st.writeHeaders(HeadersFrameParam{StreamID: 3, BlockFragment: st.encodeHeader(":path", "/control"), EndHeaders: true, EndStream: true})
					control := st.nextHandlerCall()
					control.do(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
					control.exit()
					st.wantHeaders(wantHeader{streamID: 3, endStream: true, header: http.Header{":status": {"204"}}})
				})
			})
		}
	}
}

func TestServerNormalizesFieldWhitespace(t *testing.T) {
	synctestTest(t, func(t testing.TB) {
		st := newServerTester(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Test", " \tinner \t space\t ")
			w.Header().Set("Trailer", "X-End")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			w.Header().Set("X-End", " \ttrailer \t value\t ")
		})
		defer st.Close()
		st.greet()
		getSlash(st)
		st.wantHeaders(wantHeader{streamID: 1, header: http.Header{":status": {"200"}, "x-test": {"inner \t space"}}})
		st.wantHeaders(wantHeader{streamID: 1, endStream: true, header: http.Header{"x-end": {"trailer \t value"}}})
	})
}

func TestTransportNormalizesFieldWhitespace(t *testing.T) {
	synctestTest(t, func(t testing.TB) {
		tc := newTestClientConn(t)
		tc.greet()
		req, _ := http.NewRequest("GET", "https://example.com/", nil)
		req.Header.Set("X-Test", " \tinner \t space\t ")
		rt := tc.roundTrip(req)
		tc.wantHeaders(wantHeader{streamID: rt.streamID(), endStream: true, header: http.Header{":method": {"GET"}, "x-test": {"inner \t space"}}})
		tc.writeHeaders(HeadersFrameParam{StreamID: rt.streamID(), EndHeaders: true, EndStream: true, BlockFragment: tc.makeHeaderBlockFragment(":status", "204")})
		rt.wantStatus(http.StatusNoContent)
		body := tc.newRequestBody()
		req, _ = http.NewRequest("POST", "https://example.com/", body)
		req.Trailer = http.Header{"X-End": {" \ttrailer \t value\t "}}
		rt = tc.roundTrip(req)
		tc.wantHeaders(wantHeader{streamID: rt.streamID(), header: http.Header{":method": {"POST"}, "trailer": {"X-End"}}})
		body.closeWithError(io.EOF)
		tc.wantHeaders(wantHeader{streamID: rt.streamID(), endStream: true, header: http.Header{"x-end": {"trailer \t value"}}})
		tc.writeHeaders(HeadersFrameParam{StreamID: rt.streamID(), EndHeaders: true, EndStream: true, BlockFragment: tc.makeHeaderBlockFragment(":status", "204")})
		rt.wantStatus(http.StatusNoContent)
	})
}
