//go:build !go1.26

package http2

import (
	"net/http"
)

func http2ConfigStrictMaxConcurrentRequests(h2 *http.HTTP2Config) bool {
	return false
}
