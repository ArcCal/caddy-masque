package http3

import "net/http"

// RejectDatagrams declares that the request has no semantics for HTTP Datagrams.
// Any Datagram already received or subsequently received while the request's
// receive side is open aborts the stream with H3_DATAGRAM_ERROR (RFC 9297, section 2).
// Datagrams received after the receive side is closed are silently discarded.
//
// This does not hijack the request, flush its response, or change ownership of
// the request body. Normal HTTP response buffering and trailers are preserved.
// It must only be called for requests whose extension defines no Datagram
// semantics; in particular, callers must preserve optimistic CONNECT-IP
// Datagrams before the response (RFC 9484, section 7.1).
//
// ResponseWriter wrappers can expose their underlying writer with Unwrap.
// It returns http.ErrNotSupported for a writer not provided by this package.
func RejectDatagrams(w http.ResponseWriter) error {
	for {
		if rw, ok := w.(*responseWriter); ok {
			str, ok := rw.str.datagramStream.(*stateTrackingStream)
			if !ok {
				return http.ErrNotSupported
			}
			str.rejectDatagrams()
			return nil
		}
		if u, ok := w.(interface{ Unwrap() http.ResponseWriter }); ok {
			w = u.Unwrap()
			continue
		}
		return http.ErrNotSupported
	}
}
