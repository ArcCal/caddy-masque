// Command caddy bundles standard Caddy modules, MASQUE CONNECT-IP and Cloudflare DNS.
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/standard"

	_ "github.com/ArcCal/caddy-masque"
)

func main() {
	caddycmd.Main()
}
