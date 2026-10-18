package http3

import (
	"errors"
	"io"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/quicvarint"
)

var errInvalidQPACKInstruction = errors.New("invalid QPACK instruction for a zero-capacity dynamic table")

// Our QPACK encoder never inserts entries, and our decoder advertises the
// default maximum table capacity of zero. Peer-created QPACK streams still
// need instruction validation and critical-stream lifecycle monitoring.
func (c *rawConn) handleQPACKStream(str *quic.ReceiveStream, encoder bool) {
	err := readQPACKStream(quicvarint.NewReader(str), encoder)
	if c.conn.Context().Err() != nil {
		return
	}
	code := ErrCodeQPACKDecoderStreamError
	if encoder {
		code = ErrCodeQPACKEncoderStreamError
	}
	_, isStreamError := errors.AsType[*quic.StreamError](err)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || isStreamError {
		code = ErrCodeClosedCriticalStream
	}
	c.CloseWithError(quic.ApplicationErrorCode(code), err.Error())
}

func readQPACKStream(r io.ByteReader, encoder bool) error {
	for {
		b, err := r.ReadByte()
		if err != nil {
			return err
		}
		if encoder {
			// Set Dynamic Table Capacity to zero is harmless. Any nonzero
			// capacity, insertion, or duplication is invalid with our empty,
			// zero-capacity table (RFC 9204, Sections 3.2.2 and 4.3).
			if b != 0x20 {
				return errInvalidQPACKInstruction
			}
			continue
		}
		// No field section we encode has a nonzero Required Insert Count,
		// and no entries are ever inserted. Every Section Acknowledgment or
		// Insert Count Increment is therefore invalid (Sections 4.4.1, 4.4.3).
		// Stream Cancellation remains permitted even at zero capacity
		// (Section 2.2.2.2), but its complete integer must be consumed.
		if b&0xc0 != 0x40 {
			return errInvalidQPACKInstruction
		}
		if err := readQPACKStreamCancellation(r, b); err != nil {
			return err
		}
	}
}

func readQPACKStreamCancellation(r io.ByteReader, first byte) error {
	const maxStreamID = uint64(1<<62 - 1)
	value := uint64(first & 0x3f)
	if value < 0x3f {
		return nil
	}
	// Accept the full 62-bit range required by RFC 9204, Section 4.1.1,
	// while bounding both the integer value and its encoded length.
	for shift := uint(0); shift <= 56; shift += 7 {
		b, err := r.ReadByte()
		if err != nil {
			return err
		}
		digit := uint64(b & 0x7f)
		if digit > (maxStreamID-value)>>shift {
			return errInvalidQPACKInstruction
		}
		value += digit << shift
		if b&0x80 == 0 {
			return nil
		}
	}
	return errInvalidQPACKInstruction
}
