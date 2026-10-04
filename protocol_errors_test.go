package masque

import (
	"bytes"
	"context"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Observe frames, rather than merely checking that malformed input closes
// a tunnel. RFC 9113 §8.1.1 requires a particular stream error code.
func TestHTTP2ProtocolErrorsPreserveOtherStreams(t *testing.T) {
	for _, kind := range []string{"content-header", "empty-address-request", "truncated-capsule"} {
		t.Run(kind, func(t *testing.T) {
			e := newCaddyEnv(t)
			if err := e.load(masqueConfig("alice")); err != nil {
				t.Fatal(err)
			}
			conn, err := e.dialTCP(context.Background(), e.tlsConfig("h2"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
				t.Fatal(err)
			}
			f := http2.NewFramer(conn, conn)
			f.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
			if err := f.WriteSettings(); err != nil {
				t.Fatal(err)
			}
			for enabled := false; !enabled; {
				frame, err := f.ReadFrame()
				if err != nil {
					t.Fatal(err)
				}
				if s, ok := frame.(*http2.SettingsFrame); ok && !s.IsAck() {
					_ = s.ForeachSetting(func(s http2.Setting) error {
						enabled = enabled || s.ID == http2.SettingEnableConnectProtocol && s.Val == 1
						return nil
					})
					if err := f.WriteSettingsAck(); err != nil {
						t.Fatal(err)
					}
				}
			}
			var block bytes.Buffer
			enc := hpack.NewEncoder(&block)
			fields := []hpack.HeaderField{{Name: ":method", Value: "CONNECT"}, {Name: ":protocol", Value: "connect-ip"},
				{Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "vpn.test"}, {Name: ":path", Value: anyTarget},
				{Name: "authorization", Value: authorization(testPassword)}}
			if kind == "content-header" {
				fields = append(fields, hpack.HeaderField{Name: "content-type", Value: "text/plain"})
			}
			for _, field := range fields {
				if err := enc.WriteField(field); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true}); err != nil {
				t.Fatal(err)
			}
			if kind != "content-header" {
				body := []byte{2, 0}
				end := false
				if kind == "truncated-capsule" {
					body = []byte{2}
					end = true
				}
				if err := f.WriteData(1, end, body); err != nil {
					t.Fatal(err)
				}
			}
			for {
				frame, err := f.ReadFrame()
				if err != nil {
					t.Fatal(err)
				}
				if reset, ok := frame.(*http2.RSTStreamFrame); ok && reset.StreamID == 1 {
					if reset.ErrCode != http2.ErrCodeProtocol {
						t.Fatalf("reset = %v, want PROTOCOL_ERROR", reset.ErrCode)
					}
					break
				}
			}
			// The malformed tunnel must not take down this connection's website.
			block.Reset()
			for _, field := range []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"},
				{Name: ":authority", Value: "vpn.test"}, {Name: ":path", Value: "/"}} {
				if err := enc.WriteField(field); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			status := ""
			var body bytes.Buffer
			for {
				frame, err := f.ReadFrame()
				if err != nil {
					t.Fatal(err)
				}
				switch frame := frame.(type) {
				case *http2.MetaHeadersFrame:
					if frame.StreamID == 3 {
						for _, field := range frame.Fields {
							if field.Name == ":status" {
								status = field.Value
							}
						}
					}
				case *http2.DataFrame:
					if frame.StreamID == 3 {
						body.Write(frame.Data())
						if frame.StreamEnded() {
							if status != "200" || body.String() != "cover page" {
								t.Fatalf("website after reset: %s %q", status, body.String())
							}
							return
						}
					}
				}
			}
		})
	}
}
