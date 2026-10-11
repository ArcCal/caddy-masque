//go:build go1.27

package http2

import "net/http"

func clientPriorityDisabled(s *http.Server) bool {
	return s.DisableClientPriority
}
