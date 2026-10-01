// Command caddy is Caddy with the MASQUE CONNECT-IP module built in.
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/standard"

	_ "github.com/ArcCal/caddy-masque"
)

func main() {
	caddycmd.Main()
}
