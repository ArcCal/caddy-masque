package ip

import (
	"encoding/binary"
	"testing"
)

func TestInvalidIPv4ChecksumIsDiscarded(t *testing.T) {
	for _, options := range []bool{false, true} {
		p := ipv4Packet([4]byte{10, 89, 0, 2}, [4]byte{192, 168, 1, 1}, ProtoUDP, make([]byte, 8))
		if options {
			p = append(p[:20], append([]byte{1, 1, 1, 1}, p[20:]...)...)
			p[0] = 0x46
			binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
			binary.BigEndian.PutUint16(p[10:12], 0)
			binary.BigEndian.PutUint16(p[10:12], Checksum(p[:24]))
		}
		if _, ok := Parse(p); !ok {
			t.Fatalf("valid header rejected; options=%v", options)
		}
		p[10] ^= 1
		if _, ok := Parse(p); ok {
			t.Errorf("bad checksum parsed; options=%v", options)
		}
		if e := DestUnreachable(p, addr("10.89.0.1"), AdminProhibited); e != nil {
			t.Errorf("bad checksum caused unreachable: %x", e)
		}
		if e := PacketTooBig(p, addr("10.89.0.1"), 1280); e != nil {
			t.Errorf("bad checksum caused packet-too-big: %x", e)
		}
	}
}
