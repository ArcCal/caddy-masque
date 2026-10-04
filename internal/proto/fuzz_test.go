package proto

import (
	"errors"
	"reflect"
	"testing"
)

// Arbitrary stream segmentation must not change capsule values or errors.
// Decode the resulting values too, so control-message validation is exercised.
func FuzzCapsuleStream(f *testing.F) {
	for _, c := range []RawCapsule{
		{Type: TypeDatagram, Value: []byte{0, 0x45}},
		{Type: TypeAddressAssign, Value: []byte{0, 4, 10, 0, 0, 2, 32}},
		{Type: TypeAddressRequest, Value: []byte{0, 4, 0, 0, 0, 0, 32}},
		{Type: TypeRouteAdvertisement, Value: []byte{4, 0, 0, 0, 0, 255, 255, 255, 255, 0}},
		{Type: 0x1234, Value: []byte("unknown")},
	} {
		f.Add(AppendCapsule(nil, c.Type, c.Value), uint8(1))
	}
	f.Add([]byte{0, 0x80, 0, 0xff, 0xff}, uint8(7))
	f.Fuzz(func(t *testing.T, wire []byte, chunkSize uint8) {
		if len(wire) > 128*1024 {
			t.Skip()
		}
		decode := func(chunk int) ([]RawCapsule, string) {
			d := NewDecoder(4096)
			var got []RawCapsule
			for offset := 0; offset < len(wire); {
				end := min(offset+chunk, len(wire))
				d.Push(wire[offset:end])
				offset = end
				for {
					c, err := d.Next()
					if errors.Is(err, ErrIncomplete) {
						break
					}
					if err != nil {
						return got, err.Error()
					}
					_, _ = Decode(c)
					got = append(got, c)
				}
			}
			if err := d.Finish(); err != nil {
				return got, err.Error()
			}
			return got, ""
		}
		whole, wholeErr := decode(max(1, len(wire)))
		split, splitErr := decode(int(chunkSize) + 1)
		if wholeErr != splitErr || !reflect.DeepEqual(whole, split) {
			t.Fatalf("segmentation changed decoding: whole=%v %q, split=%v %q", whole, wholeErr, split, splitErr)
		}
	})
}
