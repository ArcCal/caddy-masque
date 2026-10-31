package masque

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// initialDatagram is an Initial-shaped long-header datagram for version,
// padded to the 1200 bytes a server must see before it answers an
// unsupported version (RFC 9000 sections 5.2.2 and 14.1).
func initialDatagram(version uint32) []byte {
	packet := []byte{0xc0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(packet[1:], version)
	packet = append(packet, 8)
	packet = append(packet, bytes.Repeat([]byte{0x11}, 8)...)
	packet = append(packet, 8)
	packet = append(packet, bytes.Repeat([]byte{0x22}, 8)...)
	return append(packet, make([]byte, 1200-len(packet))...)
}

// negotiatedVersions returns the versions a Version Negotiation packet lists
// for initialDatagram, without RFC 9000 section 15 reserved (greasing)
// versions.
func negotiatedVersions(t *testing.T, packet []byte) []uint32 {
	t.Helper()
	if len(packet) < 23 || packet[0]&0x80 == 0 || binary.BigEndian.Uint32(packet[1:5]) != 0 {
		t.Fatalf("not a Version Negotiation packet: %x", packet)
	}
	if !bytes.Equal(packet[5:14], append([]byte{8}, bytes.Repeat([]byte{0x22}, 8)...)) ||
		!bytes.Equal(packet[14:23], append([]byte{8}, bytes.Repeat([]byte{0x11}, 8)...)) {
		t.Fatalf("connection IDs are not echoed: %x", packet[:23])
	}
	var versions []uint32
	for rest := packet[23:]; len(rest) >= 4; rest = rest[4:] {
		if v := binary.BigEndian.Uint32(rest); v&0x0f0f0f0f != 0x0a0a0a0a {
			versions = append(versions, v)
		}
	}
	return versions
}

func TestHTTP3NegotiatesOnlyQUICv1(t *testing.T) {
	e := newCaddyEnv(t)
	if err := e.load(masqueConfig("alice")); err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	server := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: e.port}
	// Drafts 29 to 34 and QUIC v2 (RFC 9369) are all refused.
	versions := []uint32{0xff00001d, 0xff00001e, 0xff00001f, 0xff000020, 0xff000021, 0xff000022, 0x6b3343cf}
	for _, version := range versions {
		if _, err := conn.WriteTo(initialDatagram(version), server); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 1500)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := conn.ReadFrom(reply)
		if err != nil {
			t.Fatalf("no Version Negotiation for 0x%08x: %v", version, err)
		}
		if got := negotiatedVersions(t, reply[:n]); fmt.Sprint(got) != fmt.Sprint([]uint32{1}) {
			t.Fatalf("version 0x%08x: server offers %x, want only QUIC v1", version, got)
		}
	}

	// A client limited to QUIC v2 cannot connect; QUIC v1 still carries
	// HTTP/3 with the MASQUE settings.
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	addr := fmt.Sprintf("127.0.0.1:%d", e.port)
	c, err := quic.DialAddr(ctx, addr, http3.ConfigureTLSConfig(e.tlsConfig("h3")),
		&quic.Config{Versions: []quic.Version{quic.Version2}})
	if err == nil {
		_ = c.CloseWithError(0, "")
		t.Fatal("a QUIC v2-only client connected")
	}
	// The refusal must be version negotiation, not an unrelated dial failure.
	var negotiation *quic.VersionNegotiationError
	var offered []quic.Version
	if errors.As(err, &negotiation) {
		for _, v := range negotiation.Theirs {
			if uint32(v)&0x0f0f0f0f != 0x0a0a0a0a { // skip reserved greasing versions
				offered = append(offered, v)
			}
		}
	}
	if fmt.Sprint(offered) != fmt.Sprint([]quic.Version{quic.Version1}) {
		t.Fatalf("v2-only dial: %v, want Version Negotiation offering only QUIC v1", err)
	}
	_, cc := datagramTestClient(t, e)
	if !cc.Settings().EnableExtendedConnect {
		t.Fatal("QUIC v1 HTTP/3 lost Extended CONNECT")
	}
}
