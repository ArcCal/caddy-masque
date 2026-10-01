package masque

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/http2"
)

// The server announces extended CONNECT (RFC 8441 §3) in its SETTINGS:
// internal/xconnect ran before net/http read GODEBUG.
func TestHTTP2ExtendedConnectIsOn(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(conn, conn)
	if err := fr.WriteSettings(); err != nil {
		t.Fatal(err)
	}
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	settings, ok := f.(*http2.SettingsFrame)
	if !ok {
		t.Fatalf("first frame %T", f)
	}
	if v, ok := settings.Value(http2.SettingEnableConnectProtocol); !ok || v != 1 {
		t.Errorf("SETTINGS_ENABLE_CONNECT_PROTOCOL = %d, %v", v, ok)
	}
}
