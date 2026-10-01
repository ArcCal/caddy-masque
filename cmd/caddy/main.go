// Command caddy is Caddy with the MASQUE CONNECT-IP module built in.
package main

import (
	"os"
	"strings"
	"syscall"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/standard"

	_ "github.com/ArcCal/caddy-masque"
)

func main() {
	enableExtendedConnect()
	caddycmd.Main()
}

// enableExtendedConnect restarts the program with GODEBUG=http2xconnect=1
// unless it is set. Go's HTTP/2 server accepts extended CONNECT (RFC 8441),
// which CONNECT-IP over HTTP/2 needs, only with that setting, and reads it
// from the environment once, when net/http is initialized: before main, so
// setting it here would be too late.
func enableExtendedConnect() {
	godebug := os.Getenv("GODEBUG")
	if strings.Contains(godebug, "http2xconnect=1") {
		return
	}
	if godebug != "" {
		godebug += ","
	}
	godebug += "http2xconnect=1"
	exe, err := os.Executable()
	if err != nil {
		return // keep running; HTTP/2 tunnels will be refused
	}
	// Go uses the first of duplicate variables, so replace the old one.
	env := []string{"GODEBUG=" + godebug}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GODEBUG=") {
			env = append(env, kv)
		}
	}
	_ = syscall.Exec(exe, os.Args, env)
}
