package http3

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"sync/atomic"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/quicvarint"
)

// FrameType is the frame type of a HTTP/3 frame
type FrameType uint64

type frame any

var errPriorityUpdateForPush = errors.New("http3: PRIORITY_UPDATE frame for push")

// The maximum length of an encoded HTTP/3 frame header is 16:
// The frame has a type and length field, both QUIC varints (maximum 8 bytes in length)
const frameHeaderLen = 16

type countingByteReader struct {
	quicvarint.Reader
	NumRead int
}

func (r *countingByteReader) ReadByte() (byte, error) {
	b, err := r.Reader.ReadByte()
	if err == nil {
		r.NumRead++
	}
	return b, err
}

func (r *countingByteReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	r.NumRead += n
	return n, err
}

func (r *countingByteReader) Reset() {
	r.NumRead = 0
}

type frameParser struct {
	// client is set on a client's request streams: the client never sends
	// MAX_PUSH_ID, so any PUSH_PROMISE has a push ID larger than it advertised.
	client bool
	// request is set on request streams, where frames that belong only on
	// the control stream are rejected as soon as their type is read.
	tunnel    *atomic.Bool
	request   bool
	r         io.Reader
	streamID  quic.StreamID
	closeConn func(quic.ApplicationErrorCode, string) error
}

// truncatedFrame distinguishes a clean frame-boundary EOF from a FIN inside a
// frame. Peer resets and transport errors retain their original semantics.
func truncatedFrame(closeConn func(quic.ApplicationErrorCode, string) error, err error) error {
	if err != io.EOF && err != io.ErrUnexpectedEOF {
		return err
	}
	if closeConn != nil {
		closeConn(quic.ApplicationErrorCode(ErrCodeFrameError), "truncated HTTP/3 frame")
	}
	return io.ErrUnexpectedEOF
}

func (p *frameParser) ParseNext(qlogger qlogwriter.Recorder) (_ frame, err error) {
	r := &countingByteReader{Reader: quicvarint.NewReader(p.r)}
	defer func() {
		if err == io.ErrUnexpectedEOF || err == io.EOF && r.NumRead > 0 {
			err = truncatedFrame(p.closeConn, err)
		} else if errors.Is(err, errMalformedFrame) && p.closeConn != nil {
			p.closeConn(quic.ApplicationErrorCode(ErrCodeFrameError), err.Error())
		}
	}()
	for {
		t, err := quicvarint.Read(r)
		if err != nil {
			return nil, err
		}
		if p.tunnel != nil && p.tunnel.Load() {
			switch t {
			case 0x1, 0x3, 0x4, 0x5, 0x7, 0xd, 0xf0700, 0xf0701:
				// RFC 9114 section 4.4 permits only DATA and applicable extensions
				// after successful CONNECT, in both stream directions.
				p.closeConn(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "unexpected frame on a CONNECT tunnel")
				return nil, fmt.Errorf("peer sent an unexpected frame: type %#x on a CONNECT tunnel", t)
			}
		}
		// Frames that are not permitted on this stream are connection errors
		// whatever their payload, so they are rejected before it is read.
		switch t {
		case 0x3, 0x4, 0x7, 0xd, 0xf0700, 0xf0701:
			if p.request {
				// CANCEL_PUSH, SETTINGS, GOAWAY, MAX_PUSH_ID and PRIORITY_UPDATE
				// on a request stream are H3_FRAME_UNEXPECTED (RFC 9114 sections
				// 4.1, 7.2.3, 7.2.4, 7.2.6 and 7.2.7; RFC 9218 section 7.1).
				p.closeConn(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "")
				return nil, fmt.Errorf("peer sent an unexpected frame: type %#x on a request stream", t)
			}
		case 0x5:
			if !p.client {
				// PUSH_PROMISE is only permitted on a client's request streams:
				// a server receiving it, or either endpoint receiving it on the
				// control stream, is H3_FRAME_UNEXPECTED (RFC 9114 sections
				// 6.2.1 and 7.2.5).
				p.closeConn(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "")
				return nil, errors.New("peer sent an unexpected frame: PUSH_PROMISE")
			}
		}
		l, err := quicvarint.Read(r)
		if err != nil {
			return nil, err
		}

		switch t {
		case 0x0: // DATA
			if qlogger != nil {
				qlogger.RecordEvent(qlog.FrameParsed{
					StreamID: p.streamID,
					Raw: qlog.RawInfo{
						Length:        int(l) + r.NumRead,
						PayloadLength: int(l),
					},
					Frame: qlog.Frame{Frame: qlog.DataFrame{}},
				})
			}
			return &dataFrame{Length: l}, nil
		case 0x1: // HEADERS
			return &headersFrame{
				Length:    l,
				headerLen: r.NumRead,
			}, nil
		case 0x4: // SETTINGS
			return parseSettingsFrame(r, l, p.streamID, qlogger)
		case 0x3: // CANCEL_PUSH; push is unsupported, but callers must reject it
			if qlogger != nil {
				qlogger.RecordEvent(qlog.FrameParsed{
					StreamID: p.streamID,
					Raw:      qlog.RawInfo{Length: r.NumRead, PayloadLength: int(l)},
					Frame:    qlog.Frame{Frame: qlog.CancelPushFrame{}},
				})
			}
			id, err := parseVarIntPayload(r, l)
			if err != nil {
				return nil, err
			}
			return &cancelPushFrame{PushID: id}, nil
		case 0x5: // PUSH_PROMISE; push is unsupported, but callers must reject it
			if qlogger != nil {
				qlogger.RecordEvent(qlog.FrameParsed{
					StreamID: p.streamID,
					Raw:      qlog.RawInfo{Length: r.NumRead, PayloadLength: int(l)},
					Frame:    qlog.Frame{Frame: qlog.PushPromiseFrame{}},
				})
			}
			// Only a client's request streams get here. The client never sends
			// MAX_PUSH_ID, so any push ID is larger than it advertised (RFC 9114
			// section 7.2.5).
			p.closeConn(quic.ApplicationErrorCode(ErrCodeIDError), "")
			return nil, errors.New("http3: PUSH_PROMISE without MAX_PUSH_ID")
		case 0x7: // GOAWAY
			return parseGoAwayFrame(r, l, p.streamID, qlogger)
		case 0xf0700: // PRIORITY_UPDATE for a request stream
			return parsePriorityUpdateFrame(r, l, p.streamID, qlogger)
		case 0xf0701: // PRIORITY_UPDATE for a push stream
			return nil, errPriorityUpdateForPush
		case 0xd: // MAX_PUSH_ID; push is unsupported, but callers must check it
			if qlogger != nil {
				qlogger.RecordEvent(qlog.FrameParsed{
					StreamID: p.streamID,
					Raw:      qlog.RawInfo{Length: r.NumRead, PayloadLength: int(l)},
					Frame:    qlog.Frame{Frame: qlog.MaxPushIDFrame{}},
				})
			}
			id, err := parseVarIntPayload(r, l)
			if err != nil {
				return nil, err
			}
			return &maxPushIDFrame{PushID: id}, nil
		case 0x2, 0x6, 0x8, 0x9: // reserved frame types
			if qlogger != nil {
				qlogger.RecordEvent(qlog.FrameParsed{
					StreamID: p.streamID,
					Raw:      qlog.RawInfo{Length: r.NumRead + int(l), PayloadLength: int(l)},
					Frame:    qlog.Frame{Frame: qlog.ReservedFrame{Type: t}},
				})
			}
			p.closeConn(quic.ApplicationErrorCode(ErrCodeFrameUnexpected), "")
			return nil, fmt.Errorf("http3: reserved frame type: %d", t)
		default:
			// unknown frame types
			if qlogger != nil {
				qlogger.RecordEvent(qlog.FrameParsed{
					StreamID: p.streamID,
					Raw:      qlog.RawInfo{Length: r.NumRead, PayloadLength: int(l)},
					Frame:    qlog.Frame{Frame: qlog.UnknownFrame{Type: t}},
				})
			}
		}

		// skip over the payload
		if _, err := io.CopyN(io.Discard, r, int64(l)); err != nil {
			return nil, err
		}
		r.Reset()
	}
}

type dataFrame struct {
	Length uint64
}

func (f *dataFrame) Append(b []byte) []byte {
	b = quicvarint.Append(b, 0x0)
	return quicvarint.Append(b, f.Length)
}

type headersFrame struct {
	Length    uint64
	headerLen int // number of bytes read for type and length field
}

func (f *headersFrame) Append(b []byte) []byte {
	b = quicvarint.Append(b, 0x1)
	return quicvarint.Append(b, f.Length)
}

const (
	// SETTINGS_MAX_FIELD_SECTION_SIZE
	settingMaxFieldSectionSize = 0x6
	// Extended CONNECT, RFC 9220
	settingExtendedConnect = 0x8
	// HTTP Datagrams, RFC 9297
	settingDatagram = 0x33
)

type settingsFrame struct {
	MaxFieldSectionSize int64 // SETTINGS_MAX_FIELD_SECTION_SIZE, -1 if not set

	Datagram        bool              // HTTP Datagrams, RFC 9297
	ExtendedConnect bool              // Extended CONNECT, RFC 9220
	Other           map[uint64]uint64 // all settings that we don't explicitly recognize
}

// settingsError reports invalid setting semantics, rather than a malformed frame.
type settingsError struct{ message string }

func (e *settingsError) Error() string { return e.message }

const maxSettingsFrameSize = 8 << 10

func parseSettingsFrame(r *countingByteReader, l uint64, streamID quic.StreamID, qlogger qlogwriter.Recorder) (*settingsFrame, error) {
	if l > maxSettingsFrameSize {
		return nil, fmt.Errorf("unexpected size for SETTINGS frame: %d", l)
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, io.EOF
		}
		return nil, err
	}
	frame := &settingsFrame{MaxFieldSectionSize: -1}
	b := bytes.NewReader(buf)
	settingsFrame := qlog.SettingsFrame{MaxFieldSectionSize: -1}
	var readMaxFieldSectionSize, readDatagram, readExtendedConnect bool
	for b.Len() > 0 {
		id, err := quicvarint.Read(b)
		if err != nil { // should not happen. We allocated the whole frame already.
			return nil, err
		}
		val, err := quicvarint.Read(b)
		if err != nil { // should not happen. We allocated the whole frame already.
			return nil, err
		}

		switch id {
		case 0x2, 0x3, 0x4, 0x5:
			return nil, &settingsError{fmt.Sprintf("reserved HTTP/2 setting: %d", id)}
		case settingMaxFieldSectionSize:
			if readMaxFieldSectionSize {
				return nil, &settingsError{fmt.Sprintf("duplicate setting: %d", id)}
			}
			readMaxFieldSectionSize = true
			frame.MaxFieldSectionSize = int64(val)
			settingsFrame.MaxFieldSectionSize = int64(val)
		case settingExtendedConnect:
			if readExtendedConnect {
				return nil, &settingsError{fmt.Sprintf("duplicate setting: %d", id)}
			}
			readExtendedConnect = true
			if val != 0 && val != 1 {
				return nil, &settingsError{fmt.Sprintf("invalid value for SETTINGS_ENABLE_CONNECT_PROTOCOL: %d", val)}
			}
			frame.ExtendedConnect = val == 1
			if qlogger != nil {
				settingsFrame.ExtendedConnect = new(frame.ExtendedConnect)
			}
		case settingDatagram:
			if readDatagram {
				return nil, &settingsError{fmt.Sprintf("duplicate setting: %d", id)}
			}
			readDatagram = true
			if val != 0 && val != 1 {
				return nil, &settingsError{fmt.Sprintf("invalid value for SETTINGS_H3_DATAGRAM: %d", val)}
			}
			frame.Datagram = val == 1
			if qlogger != nil {
				settingsFrame.Datagram = new(frame.Datagram)
			}
		default:
			if _, ok := frame.Other[id]; ok {
				return nil, &settingsError{fmt.Sprintf("duplicate setting: %d", id)}
			}
			if frame.Other == nil {
				frame.Other = make(map[uint64]uint64)
			}
			frame.Other[id] = val
		}
	}
	if qlogger != nil {
		settingsFrame.Other = maps.Clone(frame.Other)

		qlogger.RecordEvent(qlog.FrameParsed{
			StreamID: streamID,
			Raw: qlog.RawInfo{
				Length:        r.NumRead,
				PayloadLength: int(l),
			},
			Frame: qlog.Frame{Frame: settingsFrame},
		})
	}
	return frame, nil
}

func (f *settingsFrame) Append(b []byte) []byte {
	b = quicvarint.Append(b, 0x4)
	var l int
	if f.MaxFieldSectionSize >= 0 {
		l += quicvarint.Len(settingMaxFieldSectionSize) + quicvarint.Len(uint64(f.MaxFieldSectionSize))
	}
	for id, val := range f.Other {
		l += quicvarint.Len(id) + quicvarint.Len(val)
	}
	if f.Datagram {
		l += quicvarint.Len(settingDatagram) + quicvarint.Len(1)
	}
	if f.ExtendedConnect {
		l += quicvarint.Len(settingExtendedConnect) + quicvarint.Len(1)
	}
	b = quicvarint.Append(b, uint64(l))
	if f.MaxFieldSectionSize >= 0 {
		b = quicvarint.Append(b, settingMaxFieldSectionSize)
		b = quicvarint.Append(b, uint64(f.MaxFieldSectionSize))
	}
	if f.Datagram {
		b = quicvarint.Append(b, settingDatagram)
		b = quicvarint.Append(b, 1)
	}
	if f.ExtendedConnect {
		b = quicvarint.Append(b, settingExtendedConnect)
		b = quicvarint.Append(b, 1)
	}
	for id, val := range f.Other {
		b = quicvarint.Append(b, id)
		b = quicvarint.Append(b, val)
	}
	return b
}

// Server push frames. Push is not supported, so a server never sends
// PUSH_PROMISE and a client never sends MAX_PUSH_ID. CANCEL_PUSH and
// MAX_PUSH_ID on the control stream are returned so that callers can reject
// them as RFC 9114 sections 7.2.3 and 7.2.7 require, rather than being
// skipped; the parser itself rejects PUSH_PROMISE (section 7.2.5) and push
// frames on request streams.
type cancelPushFrame struct {
	PushID uint64
}

type maxPushIDFrame struct {
	PushID uint64
}

var errMalformedFrame = errors.New("http3: frame payload does not match its declared length")

// parseVarIntPayload reads a frame payload of length l that consists of exactly
// one variable-length integer (CANCEL_PUSH, GOAWAY and MAX_PUSH_ID). It never
// reads past the declared payload: a payload that is empty, longer than the
// integer or shorter than it is malformed (RFC 9114 section 7.1), and callers
// treat that as a connection error of type H3_FRAME_ERROR.
func parseVarIntPayload(r io.Reader, l uint64) (uint64, error) {
	if l == 0 || l > 8 {
		return 0, errMalformedFrame
	}
	var b [8]byte
	if _, err := io.ReadFull(r, b[:l]); err != nil {
		if err == io.ErrUnexpectedEOF {
			return 0, io.EOF
		}
		return 0, err
	}
	v, n, err := quicvarint.Parse(b[:l])
	if err != nil || n != int(l) {
		return 0, errMalformedFrame
	}
	return v, nil
}

type goAwayFrame struct {
	StreamID quic.StreamID
}

func parseGoAwayFrame(r *countingByteReader, l uint64, streamID quic.StreamID, qlogger qlogwriter.Recorder) (*goAwayFrame, error) {
	frame := &goAwayFrame{}
	id, err := parseVarIntPayload(r, l)
	if err != nil {
		return nil, err
	}
	frame.StreamID = quic.StreamID(id)
	if qlogger != nil {
		qlogger.RecordEvent(qlog.FrameParsed{
			StreamID: streamID,
			Raw:      qlog.RawInfo{Length: r.NumRead, PayloadLength: int(l)},
			Frame:    qlog.Frame{Frame: qlog.GoAwayFrame{StreamID: frame.StreamID}},
		})
	}
	return frame, nil
}

func (f *goAwayFrame) Append(b []byte) []byte {
	b = quicvarint.Append(b, 0x7)
	b = quicvarint.Append(b, uint64(quicvarint.Len(uint64(f.StreamID))))
	return quicvarint.Append(b, uint64(f.StreamID))
}

// PRIORITY_UPDATE, RFC 9218
type priorityUpdateFrame struct {
	ElementID          uint64
	PriorityFieldValue string
}

const maxPriorityUpdateFrameSize = 4 << 10

func parsePriorityUpdateFrame(r *countingByteReader, l uint64, streamID quic.StreamID, qlogger qlogwriter.Recorder) (*priorityUpdateFrame, error) {
	if l > maxPriorityUpdateFrameSize {
		return nil, fmt.Errorf("unexpected size for PRIORITY_UPDATE frame: %d", l)
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, io.EOF
		}
		return nil, err
	}
	id, n, err := quicvarint.Parse(buf)
	if err != nil {
		return nil, err
	}
	frame := &priorityUpdateFrame{
		ElementID:          id,
		PriorityFieldValue: string(buf[n:]),
	}
	if qlogger != nil {
		qlogger.RecordEvent(qlog.FrameParsed{
			StreamID: streamID,
			Raw:      qlog.RawInfo{Length: r.NumRead, PayloadLength: int(l)},
			Frame: qlog.Frame{Frame: qlog.PriorityUpdateFrame{
				StreamID:           quic.StreamID(frame.ElementID),
				PriorityFieldValue: frame.PriorityFieldValue,
			}},
		})
	}
	return frame, nil
}
