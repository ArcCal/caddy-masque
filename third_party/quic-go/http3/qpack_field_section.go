package http3

import (
	"errors"
	"io"

	"github.com/quic-go/qpack"
)

var errInvalidQPACKBase = errors.New("invalid QPACK Base")

// decodeFieldSection validates the Base omitted by the static-only decoder.
// RFC 9204 section 4.5.1.2 permits any nonnegative Base without dynamic
// references, but a sign bit of 1 with Required Insert Count zero is invalid.
func decodeFieldSection(decoder *qpack.Decoder, block []byte) qpack.DecodeFunc {
	if len(block) < 2 || block[0] != 0 || block[1] == 0 {
		return decoder.Decode(block)
	}
	if block[1]&0x80 != 0 {
		return func() (qpack.HeaderField, error) { return qpack.HeaderField{}, errInvalidQPACKBase }
	}
	n, err := qpackBasePrefixLength(block[1:])
	if err != nil {
		return func() (qpack.HeaderField, error) { return qpack.HeaderField{}, err }
	}
	// Static field representations do not depend on Base. Normalize this
	// uncommon prefix for the existing decoder, without mutating the input.
	fields := block[1+n:]
	normalized := make([]byte, 2+len(fields))
	copy(normalized[2:], fields)
	return decoder.Decode(normalized)
}

// qpackBasePrefixLength consumes a 7-bit prefixed integer. Support the full
// 62-bit range required by RFC 9204 section 4.1.1, with bounded encoded length.
func qpackBasePrefixLength(b []byte) (int, error) {
	const maxBase = uint64(1<<62 - 1)
	value := uint64(b[0] & 0x7f)
	if value < 0x7f {
		return 1, nil
	}
	for i, shift := 1, uint(0); shift <= 56; i, shift = i+1, shift+7 {
		if i >= len(b) {
			return 0, io.ErrUnexpectedEOF
		}
		digit := uint64(b[i] & 0x7f)
		if digit > (maxBase-value)>>shift {
			return 0, errInvalidQPACKBase
		}
		value += digit << shift
		if b[i]&0x80 == 0 {
			return i + 1, nil
		}
	}
	return 0, errInvalidQPACKBase
}
