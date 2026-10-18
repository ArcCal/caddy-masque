package http2_test

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"testing"
	"testing/synctest"

	. "golang.org/x/net/http2"
)

// Each received SETTINGS frame needs its own ACK even while the peer blocks writes.
func TestServerSettingsAcknowledgmentsDuringWrite(t *testing.T) {
	synctestTest(t, func(t testing.TB) {
		st := newServerTester(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
		defer st.Close()
		st.greet()
		st.cc.(*synctestNetConn).SetReadBufferSize(0)
		st.bodylessReq1()
		synctest.Wait()
		for i := 0; i < 3; i++ {
			st.writeSettings()
		}
		synctest.Wait()
		st.cc.(*synctestNetConn).SetReadBufferSize(math.MaxInt)
		st.wantHeaders(wantHeader{streamID: 1, endStream: true, header: http.Header{":status": {"204"}}})
		for i := 0; i < 3; i++ {
			st.wantSettingsAck()
		}
		st.writeHeaders(HeadersFrameParam{StreamID: 3, BlockFragment: st.encodeHeader(), EndHeaders: true, EndStream: true})
		st.wantHeaders(wantHeader{streamID: 3, endStream: true, header: http.Header{":status": {"204"}}})
	})
}

func TestServerSettingsAckQueueBound(t *testing.T) {
	DisableGoroutineTracking(t)
	synctestTest(t, func(t testing.TB) {
		st := newServerTester(t, nil)
		defer st.Close()
		st.greet()
		st.cc.(*synctestNetConn).SetReadBufferSize(0)
		st.cc.(*synctestNetConn).autoWait = false
		for i := 0; i < MaxQueuedControlFrames+3; i++ {
			st.fr.WriteSettings()
		}
		synctest.Wait()
		st.cc.(*synctestNetConn).SetReadBufferSize(math.MaxInt)
		st.advance(GoAwayTimeout)
		for st.readFrame() != nil {
		}
		st.wantClosed()
	})
}

func TestServerRequestContentLengthEndingConformance(t *testing.T) {
	for _, ending := range []string{"headers-fin", "data-fin", "trailers-fin"} {
		for _, length := range []string{"0", "1"} {
			for _, body := range []string{"", "x"} {
				if ending == "headers-fin" && body != "" {
					continue
				}
				t.Run(fmt.Sprintf("%s/length-%s/body-%d", ending, length, len(body)), func(t *testing.T) {
					synctestTest(t, func(t testing.TB) {
						st := newServerTester(t, nil)
						defer st.Close()
						st.greet()
						st.writeHeaders(HeadersFrameParam{StreamID: 1, BlockFragment: st.encodeHeader(":method", "POST", "content-length", length), EndHeaders: true, EndStream: ending == "headers-fin"})
						var call *serverHandlerCall
						if ending != "headers-fin" {
							call = st.nextHandlerCall()
						}
						if ending == "data-fin" {
							st.writeData(1, true, []byte(body))
						}
						if ending == "trailers-fin" {
							if body != "" {
								st.writeData(1, false, []byte(body))
							}
							if length != "0" || body == "" {
								st.writeHeaders(HeadersFrameParam{StreamID: 1, BlockFragment: st.encodeHeaderRaw(), EndHeaders: true, EndStream: true})
							}
						}
						valid := length == fmt.Sprint(len(body))
						if !valid {
							st.wantRSTStream(1, ErrCodeProtocol)
						}
						if call == nil && valid {
							call = st.nextHandlerCall()
						}
						if call != nil {
							call.do(func(w http.ResponseWriter, r *http.Request) {
								got, err := io.ReadAll(r.Body)
								if (err == nil) != valid {
									t.Errorf("body error = %v, valid = %v", err, valid)
								}
								if valid && string(got) != body {
									t.Errorf("body = %q, want %q", got, body)
								}
								w.WriteHeader(http.StatusNoContent)
							})
							call.exit()
						}
						if valid {
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
}

func TestServerInvalidRequestContentLength(t *testing.T) {
	for _, values := range [][]string{{""}, {"+1"}, {"-1"}, {"abc"}, {"1, 2"}, {"1", "2"}, {"9223372036854775808"}} {
		for _, end := range []bool{false, true} {
			t.Run(fmt.Sprintf("%q/end-%v", values, end), func(t *testing.T) {
				synctestTest(t, func(t testing.TB) {
					st := newServerTester(t, func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path != "/control" {
							t.Error("invalid content length reached handler")
						}
						w.WriteHeader(http.StatusNoContent)
					})
					defer st.Close()
					st.greet()
					fields := []string{":method", "POST", ":scheme", "https", ":authority", "example.com", ":path", "/"}
					for _, value := range values {
						fields = append(fields, "content-length", value)
					}
					st.writeHeaders(HeadersFrameParam{StreamID: 1, BlockFragment: st.encodeHeaderRaw(fields...), EndHeaders: true, EndStream: end})
					st.wantRSTStream(1, ErrCodeProtocol)
					st.writeHeaders(HeadersFrameParam{StreamID: 3, BlockFragment: st.encodeHeader(":path", "/control"), EndHeaders: true, EndStream: true})
					st.wantHeaders(wantHeader{streamID: 3, endStream: true, header: http.Header{":status": {"204"}}})
				})
			})
		}
	}
}

func TestServerConnectContentLengthEnding(t *testing.T) {
	t.Run("initial-headers-fin", func(t *testing.T) {
		synctestTest(t, func(t testing.TB) {
			st := newServerTester(t, nil)
			defer st.Close()
			st.greet()
			st.writeHeaders(HeadersFrameParam{StreamID: 1, BlockFragment: st.encodeHeaderRaw(":method", "CONNECT", ":authority", "example.com:443", "content-length", "1"), EndHeaders: true, EndStream: true})
			call := st.nextHandlerCall()
			call.do(func(w http.ResponseWriter, r *http.Request) {
				if r.ContentLength != 0 {
					t.Errorf("ended CONNECT content length = %d, want original 0", r.ContentLength)
				}
				if body, err := io.ReadAll(r.Body); err != nil || len(body) != 0 {
					t.Errorf("ended CONNECT body = %q, %v", body, err)
				}
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
			})
			st.wantHeaders(wantHeader{streamID: 1, header: http.Header{":status": {"200"}}})
			call.exit()
			st.wantData(wantData{streamID: 1, endStream: true})
			st.writeHeaders(HeadersFrameParam{StreamID: 3, BlockFragment: st.encodeHeader(), EndHeaders: true, EndStream: true})
			control := st.nextHandlerCall()
			control.do(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
			control.exit()
			st.wantHeaders(wantHeader{streamID: 3, endStream: true, header: http.Header{":status": {"204"}}})
		})
	})
	for _, status := range []int{200, 403} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			synctestTest(t, func(t testing.TB) {
				st := newServerTester(t, nil)
				defer st.Close()
				st.greet()
				st.writeHeaders(HeadersFrameParam{StreamID: 1, BlockFragment: st.encodeHeaderRaw(":method", "CONNECT", ":authority", "example.com:443", "content-length", "1"), EndHeaders: true})
				call := st.nextHandlerCall()
				call.do(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(status)
					w.(http.Flusher).Flush()
				})
				st.wantHeaders(wantHeader{streamID: 1, header: http.Header{":status": {fmt.Sprint(status)}}})
				st.writeData(1, true, nil)
				// CONNECT has no HTTP message content. Preserve the existing
				// Body.Read error without adding an HTTP content-length reset
				// for tunnel DATA (RFC 9110 section 9.3.6, RFC 9113 section 8.1.1).
				call.do(func(w http.ResponseWriter, r *http.Request) {
					if _, err := io.ReadAll(r.Body); err == nil {
						t.Error("expected existing body length error")
					}
				})
				call.exit()
				st.wantData(wantData{streamID: 1, endStream: true})
				st.writeHeaders(HeadersFrameParam{StreamID: 3, BlockFragment: st.encodeHeader(), EndHeaders: true, EndStream: true})
				control := st.nextHandlerCall()
				control.do(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
				control.exit()
				st.wantHeaders(wantHeader{streamID: 3, endStream: true, header: http.Header{":status": {"204"}}})
			})
		})
	}
}

func TestServerPriorityUpdateConformance(t *testing.T) {
	for _, tt := range []struct {
		name, state, priority string
		id                    uint32
		valid                 bool
	}{
		{"idle-push", "idle", "u=1", 2, false},
		{"idle-at-stream-limit", "active", "u=1", 3, false},
		{"unparsable-idle", "idle", "Invalid dictionary: (((", 1, false},
		{"legal-idle-request", "idle", "u=1", 1, true},
		{"active-request", "active", "u=1", 1, true},
		{"closed-request", "closed", "u=1", 1, true},
		{"unknown-and-out-of-range", "idle", "u=8, i=42, unknown=?1", 1, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctestTest(t, func(t testing.TB) {
				st := newServerTester(t, nil, func(s *Server) {
					s.MaxConcurrentStreams = 1
					s.NewWriteScheduler = NewPriorityWriteSchedulerRFC9218
				})
				defer st.Close()
				st.greet()
				var call *serverHandlerCall
				var lastStream uint32
				if tt.state != "idle" {
					st.bodylessReq1()
					call = st.nextHandlerCall()
					lastStream = 1
					if tt.state == "closed" {
						call.do(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
						call.exit()
						st.wantHeaders(wantHeader{streamID: 1, endStream: true, header: http.Header{":status": {"204"}}})
					}
				}
				st.writePriorityUpdate(tt.id, tt.priority)
				if !tt.valid {
					st.wantGoAway(lastStream, ErrCodeProtocol)
					return
				}
				st.writePing(false, [8]byte{1})
				if ping := readFrame[*PingFrame](t, st); !ping.IsAck() || ping.Data != [8]byte{1} {
					t.Errorf("unexpected PING response: %v", ping)
				}
				if tt.state == "active" {
					call.do(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
					call.exit()
					st.wantHeaders(wantHeader{streamID: 1, endStream: true, header: http.Header{":status": {"204"}}})
				}
				id := lastStream + 2
				if lastStream == 0 {
					id = 1
				}
				st.writeHeaders(HeadersFrameParam{StreamID: id, BlockFragment: st.encodeHeader(), EndHeaders: true, EndStream: true})
				control := st.nextHandlerCall()
				control.do(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
				control.exit()
				st.wantHeaders(wantHeader{streamID: id, endStream: true, header: http.Header{":status": {"204"}}})
			})
		})
	}
}

func TestServerSwitchingProtocolsResponse(t *testing.T) {
	for _, status := range []int{100, 101, 103} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			synctestTest(t, func(t testing.TB) {
				st := newServerTester(t, func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/control" {
						w.WriteHeader(status)
					}
					w.WriteHeader(http.StatusNoContent)
				})
				defer st.Close()
				st.greet()
				st.bodylessReq1()
				if status == 101 {
					st.wantRSTStream(1, ErrCodeInternal)
				} else {
					st.wantHeaders(wantHeader{streamID: 1, header: http.Header{":status": {fmt.Sprint(status)}}})
					st.wantHeaders(wantHeader{streamID: 1, endStream: true, header: http.Header{":status": {"204"}}})
				}
				st.writeHeaders(HeadersFrameParam{StreamID: 3, BlockFragment: st.encodeHeader(":path", "/control"), EndHeaders: true, EndStream: true})
				st.wantHeaders(wantHeader{streamID: 3, endStream: true, header: http.Header{":status": {"204"}}})
			})
		})
	}
}

func TestServerReceiveFlowControlErrorConformance(t *testing.T) {
	for _, state := range []string{"open", "ended", "reset", "content-length-overrun"} {
		t.Run("connection-window/"+state, func(t *testing.T) {
			synctestTest(t, func(t testing.TB) {
				const window = 65535 * 2
				st := newServerTester(t, nil, func(s *Server) {
					s.MaxUploadBufferPerConnection = window
					s.MaxUploadBufferPerStream = window
				})
				defer st.Close()
				st.greet()
				fields := []string{":method", "POST"}
				if state == "content-length-overrun" {
					fields = append(fields, "content-length", "0")
				}
				st.writeHeaders(HeadersFrameParam{StreamID: 1, BlockFragment: st.encodeHeader(fields...), EndHeaders: true, EndStream: state == "ended"})
				_ = st.nextHandlerCall()
				if state == "reset" {
					if err := st.fr.WriteRSTStream(1, ErrCodeCancel); err != nil {
						t.Fatal(err)
					}
				}
				st.writeData(1, false, make([]byte, window+1))
				st.wantGoAway(1, ErrCodeFlowControl)
			})
		})
	}
	t.Run("stream-window-refunds-full-padded-frame", func(t *testing.T) {
		synctestTest(t, func(t testing.TB) {
			st := newServerTester(t, nil, func(s *Server) {
				s.MaxUploadBufferPerConnection = 65535 * 2
				s.MaxUploadBufferPerStream = 4096
			})
			defer st.Close()
			st.greet()
			st.writeHeaders(HeadersFrameParam{StreamID: 1, BlockFragment: st.encodeHeader(":method", "POST"), EndHeaders: true})
			call := st.nextHandlerCall()
			st.writeDataPadded(1, false, make([]byte, 8190), make([]byte, 1))
			st.wantUnorderedFrames(
				func(f *RSTStreamFrame) bool { return f.StreamID == 1 && f.ErrCode == ErrCodeFlowControl },
				func(f *WindowUpdateFrame) bool { return f.StreamID == 0 && f.Increment == 8192 },
			)
			call.do(func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.ReadAll(r.Body); err == nil {
					t.Error("expected stream error")
				}
			})
			call.exit()
			st.writeHeaders(HeadersFrameParam{StreamID: 3, BlockFragment: st.encodeHeader(":method", "POST", "content-length", "4096"), EndHeaders: true})
			control := st.nextHandlerCall()
			st.writeData(3, true, make([]byte, 4096))
			control.do(func(w http.ResponseWriter, r *http.Request) {
				if body, err := io.ReadAll(r.Body); err != nil || len(body) != 4096 {
					t.Errorf("control body = %d bytes, %v", len(body), err)
				}
				w.WriteHeader(http.StatusNoContent)
			})
			st.wantWindowUpdate(0, 4096)
			control.exit()
			st.wantHeaders(wantHeader{streamID: 3, endStream: true, header: http.Header{":status": {"204"}}})
		})
	})
}

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
	for _, value := range []string{"HTTP", "HTTPS", "custom", "custom+1.2-foo"} {
		tests = append(tests,
			requestCase{"ordinary-valid-scheme-" + value, replace(get, ":scheme", value, false), true},
			requestCase{"connect-valid-scheme-" + value, replace(connect, ":scheme", value, false), true})
	}
	for _, value := range []string{"1https", "+https", "https:", "http s", "http/s", "h\tttp", "h\xc3\xa9", "\xe2\x84\xaa"} {
		tests = append(tests,
			requestCase{"ordinary-invalid-scheme-" + value, replace(get, ":scheme", value, false), false},
			requestCase{"connect-invalid-scheme-" + value, replace(connect, ":scheme", value, false), false})
	}
	for _, value := range []string{"get", "CUSTOM", "!#$%&'*+-.^_`|~9"} {
		tests = append(tests, requestCase{"valid-method-" + value, replace(get, ":method", value, false), true})
	}
	for _, value := range []string{"", "BAD METHOD", "BAD\tMETHOD", "BAD/METHOD", "BAD:METHOD", "M\xc3\x89THOD"} {
		tests = append(tests, requestCase{"invalid-method-" + value, replace(get, ":method", value, false), false})
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

func TestServerConnectFrameConformance(t *testing.T) {
	requests := []struct {
		name   string
		fields []string
	}{
		{"ordinary", []string{":method", "GET", ":scheme", "https", ":authority", "example.com", ":path", "/"}},
		{"classic-connect", []string{":method", "CONNECT", ":authority", "example.com:443"}},
		{"connect-ip", []string{":method", "CONNECT", ":protocol", "connect-ip", ":scheme", "https", ":authority", "example.com", ":path", "/vpn"}},
	}
	for _, request := range requests {
		for _, response := range []struct {
			name   string
			status int
		}{
			{"accepted", 200},
			{"accepted-other-2xx", 299},
			{"refused", 403},
			{"before-final-response", 0},
			{"after-informational", 103},
		} {
			for _, ending := range []string{"trailers", "empty-trailers", "data-fin"} {
				t.Run(request.name+"/"+response.name+"/"+ending, func(t *testing.T) {
					SetDisableExtendedConnectProtocol(t, false)
					synctestTest(t, func(t testing.TB) {
						st := newServerTester(t, nil)
						defer st.Close()
						st.greet()
						fields := append(append([]string(nil), request.fields...), "trailer", "X-End")
						st.writeHeaders(HeadersFrameParam{StreamID: 1, BlockFragment: st.encodeHeaderRaw(fields...), EndHeaders: true})
						call := st.nextHandlerCall()
						if response.status != 0 {
							call.do(func(w http.ResponseWriter, r *http.Request) {
								w.WriteHeader(response.status)
								if response.status >= 200 {
									w.(http.Flusher).Flush()
								}
							})
							st.wantHeaders(wantHeader{streamID: 1, header: http.Header{":status": {fmt.Sprint(response.status)}}})
						}
						if ending == "data-fin" {
							st.writeData(1, true, nil)
						} else {
							var trailers []string
							if ending == "trailers" {
								trailers = []string{"x-end", "ok"}
							}
							st.writeHeaders(HeadersFrameParam{StreamID: 1, BlockFragment: st.encodeHeaderRaw(trailers...), EndHeaders: true, EndStream: true})
						}
						rejected := request.name != "ordinary" && response.status >= 200 && response.status < 300 && ending != "data-fin"
						if rejected {
							st.wantRSTStream(1, ErrCodeProtocol)
						}
						call.do(func(w http.ResponseWriter, r *http.Request) {
							_, err := io.ReadAll(r.Body)
							if (err != nil) != rejected {
								t.Errorf("body error = %v, rejected = %v", err, rejected)
							}
						})
						call.exit()
						if !rejected {
							if response.status < 200 {
								st.wantHeaders(wantHeader{streamID: 1, endStream: true, header: http.Header{":status": {"200"}}})
							} else {
								st.wantData(wantData{streamID: 1, endStream: true})
							}
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
