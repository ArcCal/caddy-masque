package ip

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func v4Packet(headerOpts []byte, payload int, flags uint16) []byte {
	hl := 20 + len(headerOpts)
	p := make([]byte, hl+payload)
	p[0] = 0x40 | byte(hl/4)
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:], 0x1234)
	binary.BigEndian.PutUint16(p[6:], flags)
	p[8], p[9] = 64, ProtoUDP
	copy(p[12:], []byte{1, 2, 3, 4})
	copy(p[16:], []byte{5, 6, 7, 8})
	copy(p[20:], headerOpts)
	binary.BigEndian.PutUint16(p[10:], Checksum(p[:hl]))
	for i := hl; i < len(p); i++ {
		p[i] = byte(i)
	}
	return p
}

// reassemble puts fragments back together, checking their headers.
func reassemble(t *testing.T, frags [][]byte, mtu int) (data []byte, firstOffset int, lastMF bool) {
	t.Helper()
	for i, f := range frags {
		if len(f) > mtu {
			t.Fatalf("fragment %d has %d bytes, mtu %d", i, len(f), mtu)
		}
		h, ok := Parse(f)
		if !ok || h.TotalLen != len(f) {
			t.Fatalf("fragment %d does not parse", i)
		}
		hl := int(f[0]&0x0f) * 4
		if Checksum(f[:hl]) != 0 {
			t.Errorf("fragment %d: bad header checksum", i)
		}
		ff := binary.BigEndian.Uint16(f[6:8])
		off := int(ff&0x1fff) * 8
		if i == 0 {
			firstOffset = off
		} else if off != firstOffset+len(data) {
			t.Fatalf("fragment %d at %d, expected %d", i, off, firstOffset+len(data))
		}
		if i < len(frags)-1 && ff&0x2000 == 0 {
			t.Errorf("fragment %d lacks MF", i)
		}
		if binary.BigEndian.Uint16(f[4:6]) != 0x1234 {
			t.Error("identification changed")
		}
		data = append(data, f[hl:]...)
		lastMF = ff&0x2000 != 0
	}
	return data, firstOffset, lastMF
}

func TestFragment(t *testing.T) {
	p := v4Packet(nil, 3000, 0)
	frags := Fragment(p, 1000)
	if len(frags) != 4 {
		t.Fatalf("%d fragments", len(frags))
	}
	data, off, mf := reassemble(t, frags, 1000)
	if !bytes.Equal(data, p[20:]) || off != 0 || mf {
		t.Error("reassembled data differs")
	}
	if Fragment(v4Packet(nil, 3000, 0x4000), 1000) != nil {
		t.Error("fragmented a packet with DF")
	}
	if got := Fragment(p, 5000); len(got) != 1 || !bytes.Equal(got[0], p) {
		t.Error("a packet that fits is changed")
	}
	if Fragment(v4Packet(nil, 100, 0), 20) != nil {
		t.Error("no room for data")
	}
}

func TestFragmentAFragment(t *testing.T) {
	// The middle fragment of a larger packet: offset 800, MF set.
	p := v4Packet(nil, 2000, 0x2000|100)
	data, off, mf := reassemble(t, Fragment(p, 576), 576)
	if !bytes.Equal(data, p[20:]) || off != 800 || !mf {
		t.Errorf("offset %d, MF %v", off, mf)
	}
}

func TestFragmentOptions(t *testing.T) {
	// A copied option (type 0x83, loose source route, length 7), a NOP, and
	// one not copied (0x07, record route, length 7), then end of options.
	opts := []byte{0x83, 7, 4, 1, 1, 1, 1, 1, 0x07, 7, 4, 0, 0, 0, 0, 0}
	p := v4Packet(opts, 1500, 0)
	frags := Fragment(p, 600)
	data, _, _ := reassemble(t, frags, 600)
	if !bytes.Equal(data, p[36:]) {
		t.Error("data differs")
	}
	if !bytes.Equal(frags[0][20:36], opts) {
		t.Error("the first fragment lost options")
	}
	later := frags[1][20 : int(frags[1][0]&0x0f)*4]
	if len(later) != 8 || !bytes.Equal(later[:7], opts[:7]) {
		t.Errorf("later fragments carry % x", later)
	}
}
