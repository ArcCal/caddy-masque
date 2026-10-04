// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license in LICENSE.

package http2

import "net/http"

// ResetStream terminates an HTTP/2 response stream using code. It unwraps
// middleware response writers and returns http.ErrNotSupported on other
// transports. Callers must stop using the writer after this call.
func ResetStream(w http.ResponseWriter, code ErrCode) error {
	for {
		if r, ok := w.(interface{ ResetStream(uint32) error }); ok {
			return r.ResetStream(uint32(code))
		}
		if u, ok := w.(interface{ Unwrap() http.ResponseWriter }); ok {
			w = u.Unwrap()
			continue
		}
		return http.ErrNotSupported
	}
}
