package proto

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func FuzzCapsuleStreamChunks(f *testing.F) {
	f.Add(AppendCapsule(nil, TypeDatagram, []byte{0, 0x45}), uint8(1))
	f.Add(AppendCapsule(nil, 0xff, bytes.Repeat([]byte{1}, 300)), uint8(7))
	f.Add([]byte{0x03, 0x40}, uint8(2))
	f.Fuzz(func(t *testing.T, data []byte, chunk uint8) {
		if len(data) > DefaultMaxValueLen {
			return
		}
		decode := func(size int) ([]RawCapsule, string) {
			d := NewDecoder(256)
			var capsules []RawCapsule
			for offset := 0; offset < len(data); {
				end := min(offset+size, len(data))
				d.Push(data[offset:end])
				offset = end
				for {
					c, err := d.Next()
					if errors.Is(err, ErrIncomplete) {
						break
					}
					if err != nil {
						return capsules, err.Error()
					}
					capsules = append(capsules, c)
				}
			}
			if err := d.Finish(); err != nil {
				return capsules, err.Error()
			}
			return capsules, ""
		}
		whole, wholeErr := decode(max(1, len(data)))
		split, splitErr := decode(int(chunk) + 1)
		if wholeErr != splitErr || !reflect.DeepEqual(whole, split) {
			t.Fatalf("stream interpretation depends on chunk size: %v/%s versus %v/%s", whole, wholeErr, split, splitErr)
		}
	})
}

func FuzzDecodeCapsule(f *testing.F) {
	f.Add(uint8(TypeAddressRequest), []byte{1, 4, 0, 0, 0, 0, 32})
	f.Add(uint8(TypeRouteAdvertisement), []byte{4, 0, 0, 0, 0, 255, 255, 255, 255, 0})
	f.Add(uint8(TypeDatagram), []byte{0, 0x45})
	f.Fuzz(func(t *testing.T, kind uint8, data []byte) {
		if len(data) > DefaultMaxValueLen {
			return
		}
		c, err := Decode(RawCapsule{Type: uint64(kind), Value: data})
		if err != nil {
			return
		}
		wire := Append(nil, c)
		d := NewDecoder(DefaultMaxValueLen)
		d.Push(wire)
		raw, err := d.Next()
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Decode(raw)
		if err != nil || !bytes.Equal(wire, Append(nil, decoded)) {
			t.Fatalf("valid capsule did not round trip: %v", err)
		}
		if err := d.Finish(); err != nil {
			t.Fatal(err)
		}
	})
}
