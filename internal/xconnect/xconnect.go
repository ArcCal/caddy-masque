// Package xconnect turns on extended CONNECT (RFC 8441) in Go's HTTP/2
// server, which CONNECT-IP over HTTP/2 needs. Go enables it only with
// GODEBUG=http2xconnect=1, which net/http reads from the environment in its
// init function.
//
// This package sets the variable in its own init function. It imports
// nothing that imports net/http, and its import path sorts before
// "net/http", so the Go specification's initialization order runs it
// first, whichever program it is built into.
package xconnect

import (
	"os"
	"strings"
)

func init() {
	godebug := os.Getenv("GODEBUG")
	if strings.Contains(godebug, "http2xconnect=") {
		return // the administrator's choice
	}
	if godebug != "" {
		godebug += ","
	}
	_ = os.Setenv("GODEBUG", godebug+"http2xconnect=1")
}

// Enabled reports whether extended CONNECT is on for HTTP/2.
func Enabled() bool {
	return strings.Contains(os.Getenv("GODEBUG"), "http2xconnect=1")
}
