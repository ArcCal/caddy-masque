# caddy-masque

The [masque-vpn](https://github.com/ArcCal/masque-vpn) server rewritten in Go as a Caddy module. Every build also bundles
[Cloudflare DNS](https://github.com/caddy-dns/cloudflare) for DNS challenges and wildcard certificates:

- **Standards**: IETF MASQUE IP proxying, CONNECT-IP (RFC 9484); HTTP Datagrams and Capsules (RFC 9297);
  extended CONNECT over HTTP/2 and HTTP/3 (RFC 8441, RFC 9220). HTTP/3, HTTP/2 and HTTP/1.1 are all supported.
- **Clients unchanged**: masque-vpn's `masque-client` and IETF Masque on macOS 27 arm64 connect directly, without changing a single
  line of their configuration (a client with the server's IP address in its `uri_template` needs the `:443` in the site
  addresses shown below; over HTTP/3 with IPv6 on, older clients need the note on the MTU probe below). Password hashes made by `caddy masque-passwd` and by masque-vpn's `masque-passwd` are interchangeable.
- **Caddy handles certificates and traffic**: certificates are obtained and renewed automatically; the VPN and the website
  share port 443 (TCP and UDP); the same Caddy can go on hosting other sites and reverse proxies as usual.
- **Website sharing within protocol rules**: only valid CONNECT-IP requests with correct credentials become tunnels.
  Other traffic follows the website. Refused HTTP/2 and HTTP/3 CONNECT-IP requests keep the site's body and existing
  error/redirect status, but a successful site status is changed to 404: a 2xx CONNECT response would falsely declare
  an IP tunnel. Malformed requests receive the errors required by the RFCs. HTTP/1.1 Upgrade refusals can retain 200.
- **Standards take priority** when camouflage or another design goal conflicts with mandatory IETF behavior.
  Tests cover protocol errors and the unchanged masque-vpn clients; they are not formal conformance certification.

Linux x86_64 and arm64 only (needs root: it creates a TUN device and sets up forwarding and NAT).

The latest release tag is `v1.2.0`; main contains newer fixes. Rebuild from updated
main for the [HTTP/2 security repair](docs/http2-security-2026-10-11.md).
The differences between versions are in [CHANGELOG.md](CHANGELOG.md).
Earlier review results and native-validation requirements are in [the October 4 production review](docs/review-2026-10-04-production.md).
Design goals and the checks required for Caddy updates are in [the design document](docs/design.md).
The [October 18 standards repair report](docs/conformance-repair-2026-10-18.md) records the audit findings,
repairs, current-client results and remaining native/kernel validation limits.

## One-step install

On Debian 12/13 or Ubuntu 22.04/24.04, with the domain already pointing at the server:

```sh
git clone https://github.com/ArcCal/caddy-masque && cd caddy-masque
sudo bash deploy/install-server.sh vpn.example.com
```

The script installs Go (the newest patch release of the current line, which carries the standard library's security fixes), builds,
writes `/etc/caddy/Caddyfile` (with a cover home page and one user with a random password), and starts the
`caddy-masque` service. At the end it prints the domain, user name and password to enter in the client.
The cloud provider's firewall must allow TCP 80, TCP 443 and UDP 443.
The script also checks that `/dev/net/tun` exists (on OpenVZ- and LXC-type VPSes, turn on TUN/TAP in the provider's panel);
when it finds ufw running, it opens the ports and allows forwarding from `masque0`; when Docker has set the FORWARD default
policy to DROP, it prints a warning and the command to allow the traffic.

The service runs as root (it writes to `/proc/sys`), but `deploy/caddy-masque.service` cuts its privileges down to
CAP_NET_ADMIN, CAP_NET_BIND_SERVICE and CAP_DAC_READ_SEARCH, makes the file system read-only except `/var/lib/caddy*` and
`/var/log/caddy`, and restricts system calls and address families. When a site needs to write to another directory
(for example its own log file): `systemctl edit caddy-masque`, and add `[Service]` and `ReadWritePaths=/that/directory`.

Already running the masque-vpn server? First `systemctl disable --now masque-server`; both need port 443.
Existing users carry over as they are: each `[[user]]` in `server.toml` becomes one `user NAME HASH` line in the Caddyfile.

## Building by hand

Needs Go 1.26.9 or 1.27.2, or a later reviewed patch of those lines:

```sh
go build -o caddy ./cmd/caddy
```

The resulting `caddy` includes all standard Caddy modules, MASQUE and **Cloudflare DNS v0.2.4**.
Cloudflare is registered by the MASQUE package itself, so custom main modules importing MASQUE include it too.
Verify the required provider with `./caddy list-modules | grep -Fx dns.providers.cloudflare`.
The installer and CI use this same default; rebuilding never removes Cloudflare. Builds use
the pinned protocol patches in `third_party/xnet` and `third_party/quic-go`.
The HTTP/2 fork retains its patched server and transport on both Go 1.26
and Go 1.27; no extra build tag is needed. From this checkout, xcaddy uses
both dependencies:

```sh
xcaddy build v2.11.7 --with github.com/ArcCal/caddy-masque=. \
  --with github.com/caddy-dns/cloudflare@v0.2.4 \
  --replace golang.org/x/net=./third_party/xnet \
  --replace github.com/quic-go/quic-go=./third_party/quic-go
```

Go does not inherit dependency replacements. Custom main modules must also
replace `golang.org/x/net` and `github.com/quic-go/quic-go` with these trees;
omitting either fails the build. See [the patches and their verification](third_party/README.md).

## Configuration

```caddyfile
{
	masque {
		ipv4 10.89.0.1/24
		ipv6 fd89:6d61:7371::1/64
		user macbook $argon2id$v=19$m=19456,t=2,p=1$...
		user iphone  $argon2id$v=19$m=19456,t=2,p=1$...
	}
}

vpn.example.com, :443 {
	masque
	root * /var/www/site
	file_server
}
```

The `masque` directive in the site takes the VPN requests; other requests continue to the site (here, `file_server`).
Refused extended CONNECT uses a non-2xx status even when the site would normally return 200. It is ordered automatically before `file_server`, `reverse_proxy` and the like.

### Global option `masque { ... }`

| Option | Meaning | Default |
|---|---|---|
| `ipv4 ADDRESS/PREFIX` | The server's own tunnel address; the rest of the prefix is given to clients. Required | — |
| `ipv6 ADDRESS/PREFIX` | Offer IPv6 in the tunnel; turn it on only when the server has IPv6 Internet access | Not offered |
| `user NAME HASH` | A user; the hash comes from `caddy masque-passwd`. One per device | — |
| `interface NAME` | TUN device name | `masque0` |
| `mtu BYTES` | Tunnel MTU (576–1500; at least 1280 with IPv6) | `1350` |
| `block PREFIX...` | Destination addresses clients may not reach; may be given on several lines. Replaces the default list; `block none` blocks nothing | Private addresses, loopback, multicast, benchmarking and transition-mechanism (NAT64, 6to4, Teredo) addresses and so on (including cloud providers' internal networks and 169.254.169.254) |
| `allow_client_to_client` | Let clients reach each other | Not allowed |
| `allow_host_access` | Let clients reach services on the server itself (ports listening on the tunnel address and the server's public addresses) | Ping only |
| `max_sessions COUNT` | The most tunnels one user may have at once; `unlimited` for no limit | 8 |
| `manage_network off` | Leave forwarding and NAT (sysctl, nftables) alone; manage them yourself | Managed automatically |
| `http3 off` | Do not take over HTTP/3 (see below); VPN packets then travel inside the stream (DATAGRAM capsules) on every HTTP version | Taken over |
| `mtu_probe off` | Skip the IPv6 MTU probe (see below). Turn it off only when you know every client connects directly, with no HTTP proxy in between | Probe |

Once an HTTP/3 tunnel (QUIC datagrams) with IPv6 is up, the server sends a 1280-byte ICMPv6 Echo Request to the
client's IPv6 address, to confirm that the tunnel can carry IPv6's minimum MTU; with no reply within 10 seconds it closes
the tunnel (RFC 9484 §7.2 requires this, unless an out-of-band means ensures the QUIC Initial packets were padded enough,
that is, there is no HTTP proxy in between). The client's IPv6 stack replies by itself; **when a client firewall drops
ICMPv6 Echo (such as macOS stealth mode), HTTP/3 tunnels are closed**. Then allow ICMPv6 Echo, or, when you know there
is no intermediate proxy, use `mtu_probe off`.

The probe comes from the server's IPv6 tunnel address. A client sends only where the server's routes lead (RFC 9484 §7.2),
so when a scoped request (`target`) leaves that address out, the route advertisement also lists it, for ICMPv6 only.
The server assigns an IPv6 address even to clients that asked only for IPv4, and probes it. masque-vpn's `masque-client`
answers the probe in every mode from [ArcCal/masque-vpn#14](https://github.com/ArcCal/masque-vpn/pull/14) on; with older
clients, HTTP/3 tunnels are closed every 10 seconds when the client has `ipv6 = false`, or runs in SOCKS mode (the Mac
app). Give such clients `transport = "h2"`, or use `mtu_probe off` as above.

Link-local addresses (169.254.0.0/16, fe80::/10) are never forwarded, whatever the configuration (RFC 9484 §7.2).

### Protecting the server itself

Packets that clients send to the server itself (to the `ipv4` tunnel address or the server's public addresses) are not
forwarded, so `block` does not apply to them. That is why the nftables rules have an `input` chain: packets coming in
from the tunnel device are allowed only for ICMP and replies on established connections; the rest are dropped. Otherwise,
services listening on all addresses (SSH, databases, admin interfaces…) would be open to every client with an account,
and host firewall rules written only for the public network interface would not cover them. When clients really should
reach a service on the server, add `allow_host_access` (and restrict it yourself in the host firewall by the `masque0`
interface). With `manage_network off` no rules are installed, and this is up to you.

Caddy's admin API (it shows and replaces the configuration, password hashes included, and can stop the server) has no
authentication. Caddy's default for it is `localhost:2019`, where every local user and process could use it, and the
service runs as root. So `deploy/caddy-masque.service` moves it to a unix socket only root can use,
`/run/caddy-masque/admin.sock` (`CADDY_ADMIN` in the unit). `systemctl reload caddy-masque` uses it; to call it by hand,
as root: `caddy reload --config /etc/caddy/Caddyfile --address 'unix//run/caddy-masque/admin.sock'`, or
`curl --unix-socket /run/caddy-masque/admin.sock http://localhost/config/`. An `admin` option in the Caddyfile replaces
the socket; if you set one, keep it a unix socket only root can reach, or `admin off`, and never put it on a network
address.

### Against password guessing and pool exhaustion

- After 10 requests with wrong credentials within a minute from one client address (for IPv6, per /64), its
  requests that carry credentials are not checked for the next minute but are treated as ordinary web requests (like
  requests without credentials). Users sharing an outgoing address affect one another during that minute, except
  those whose credentials are remembered (below).
  Generated passwords have 144 bits and cannot be guessed; passwords of your own given to `masque-passwd --stdin` need
  at least 12 characters; make them long and random.
- Checking a password (Argon2id) takes tens of milliseconds and megabytes of memory, so only a few checks run at once
  and a limited number wait. One client address (for IPv6, per /64) may have at most 4 checks waiting or running;
  beyond that, or when the queue is full, requests get 503. Credentials that were correct in the last 12 hours skip
  the check, the queue and the limit above: the server remembers them in memory only, as an HMAC under a key made at
  start-up, and only as long as that user's hash stays the same. So a flood of made-up credentials, even from many
  addresses, does not keep out users who connected before; a user's first connection (after a restart, a new
  password) can get 503 during such a flood, and masque-client tries again with backoff. masque-vpn's server does the
  same.
- Each user may have at most `max_sessions` tunnels at once (default 8); requests beyond that get 429. Otherwise one
  account could take the whole address pool and crowd out the other users. When a device reconnects after losing its
  connection, the old tunnel still counts until the server notices it is gone (see Timeouts below: about 30 seconds
  over HTTP/1.1 and HTTP/2, the QUIC idle timeout over HTTP/3), so do not set this to 1.

### Monitoring

Caddy's `metrics` directive and admin endpoint (as root:
`curl -s --unix-socket /run/caddy-masque/admin.sock http://localhost/metrics`) include these metrics:
`caddy_masque_sessions_active{user}`, `caddy_masque_sessions_started_total`, `caddy_masque_auth_failures_total`,
`caddy_masque_auth_throttled_total`, `caddy_masque_packets_total{direction}`, `caddy_masque_bytes_total{direction}`,
`caddy_masque_packets_dropped_total`. The counters are not reset when the configuration is reloaded.

### Automatic repair of the host network configuration

Every 30 seconds the service checks forwarding and NAT: when a host firewall reload (such as `nft flush ruleset` or a
firewalld reload) has removed the nftables table, or another program has turned off `ip_forward`, the service puts them
back and logs a warning. When the service exits normally, it sets the forwarding switches it changed back to their
original values (leaving them alone if they were already on) and removes the nftables table.

### Directive `masque [PATH_TEMPLATE]`

The path template defaults to `/.well-known/masque/ip/{target}/{ipproto}/`, which matches the client's default.
If you change it, change the client's `uri_template` to match.

Caddy picks the site by the host name a request names (`:authority` or `Host`), which comes from the authority of the
client's `uri_template`. A request for a name no site lists gets Caddy's empty response, which clients take for a
failure ("the server's response (200 OK) is malformed"). Clients that connect by IP address put the IP there:
masque-vpn's `masque-client` with an IP in `uri_template` and the domain in `server_name`, and MasqueVPN on the Mac
when its "IP" field is filled in. Hence the `:443` next to the domain in the examples and in the Caddyfile
`install-server.sh` writes: it makes the site answer HTTPS requests on port 443 for any host name as well. Caddy
requests no certificate for it (the clients check the domain's certificate, which they ask for by name), and HTTP
requests are still redirected to HTTPS. A Caddyfile written by an earlier `install-server.sh` lacks it: add `, :443`
after the domain on the site's first line and `systemctl reload caddy-masque`. Listing the IP address as a site address
works too, but Caddy then also tries to get a certificate for the IP address from the public CAs.
The template may use the forms RFC 9484 §3 allows: simple expressions in the path and query (`{target}`,
`{target,ipproto}`, with fixed text before or after), `{?target,ipproto}`, `{&...}`, and fixed parameters (such as `?v=1`).
The template may contain other variables: clients define only `target` and `ipproto`, other variables are left out when
expanded (RFC 6570), and the server matches accordingly.
Forms the server cannot match unambiguously (two expressions next to each other, a variable as a parameter name, text
after `{?...}` that does not start with `&`) are an error when the configuration is loaded, rather than failing to match
at request time.

### Example: wildcard certificate through Cloudflare DNS, TLS 1.3 only, security headers

A fuller Caddyfile for a domain whose DNS is at Cloudflare: one wildcard certificate covers the domain and all its
subdomains, TLS is limited to version 1.3, and the website sends the usual security headers.

```caddyfile
{
	# Let's Encrypt account email: expiry warnings and notices go here.
	email admin@example.com

	masque {
		ipv4 10.89.0.1/24
		# Only if the server has working IPv6; otherwise delete this line.
		ipv6 fd89:6d61:7371::1/64
		# One line per device; hashes from: caddy masque-passwd --name NAME
		user macbook $argon2id$v=19$m=19456,t=2,p=1$...
	}
}

example.com, *.example.com, :443 {
	tls {
		protocols tls1.3
		curves x25519mlkem768 x25519
		dns cloudflare {file./etc/caddy/cloudflare-token}
	}

	# VPN requests (CONNECT-IP with a valid user); everything else falls through to the site.
	masque

	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
		X-Content-Type-Options nosniff
		X-Frame-Options DENY
		Referrer-Policy strict-origin-when-cross-origin
		-Server
	}

	root * /var/www/html
	file_server
}
```

- **Cloudflare is already built in.** `./cmd/caddy`, the one-step installer, xcaddy commands above and every
  CI artifact include `dns.providers.cloudflare`. No separate plugin build is needed. The manual Cloudflare workflow
  packages the same executable that passed the required interoperability gates.
- **The API token** is a Cloudflare token with the "Edit zone DNS" permission for the domain. Put it alone in
  `/etc/caddy/cloudflare-token` (`chmod 600`); `{file.PATH}` reads it when the configuration loads. The service does not dump its environment; a protected file also avoids exposing the token through environment inspection.
- **Cloudflare's proxy must be off** for the VPN host name (DNS only, the grey cloud): Cloudflare does not pass CONNECT-IP
  or UDP 443 through. The DNS challenge needs neither port 80 nor 443 to be reachable.
- **Site addresses**: the certificate covers `example.com` and every `*.example.com`; the client's `uri_template` names
  one of them (for example `vpn.example.com`), or the server's IP address, which the `:443` lets through (see "Directive
  `masque`" above).
- **TLS**: QUIC and masque-vpn's client use TLS 1.3 only anyway. X25519MLKEM768 is the post-quantum key exchange recent
  browsers use; X25519 stays for everything else, masque-vpn's client included. There is no `alpn` line: the HTTP/3
  listener always offers `h3` whatever it says, but limiting TCP to `h2` would lock out clients that fall back to
  HTTP/1.1 (`transport = "http/1.1"`).
- **Headers**: `-Server` removes the `Server: Caddy` header, so the cover site gives less away. `X-XSS-Protection` is
  left out because browsers no longer use it. `preload` in `Strict-Transport-Security` does nothing until the domain is
  submitted to [hstspreload.org](https://hstspreload.org/); after that, every subdomain must serve HTTPS, which is hard to
  undo. These headers are on the website's responses only: `masque` runs before `header`, so a tunnel's own response
  (which only clients with a valid password ever get, never a browser) does not pass through it.

The default Caddy build includes this module and caddy-dns/cloudflare: `caddy validate` accepts the file, and with
Caddy's internal CA in place of Cloudflare, the website can send the headers above, TLS 1.2 is refused, and masque-vpn's
`masque-client` brings tunnels up over HTTP/3, HTTP/2 and HTTP/1.1.

## Managing users

```sh
caddy masque-passwd --name iphone
```

Add the `user ...` line it prints to `masque { }` in the Caddyfile, then `systemctl reload caddy-masque`.
The output also has the user name and the random password for the client configuration. To choose the password
yourself: `echo PASSWORD | caddy masque-passwd --name iphone --stdin`.

## Reloading the configuration

`systemctl reload caddy-masque` (that is, `caddy reload` through the service's admin socket; see "Protecting the server
itself" for running it by hand):

- Connected tunnels **stay up**, over HTTP/3, HTTP/2 and HTTP/1.1 alike;
- Users that were removed, or whose password changed, are **disconnected at once**;
- Changes to `block` or `allow_client_to_client`: destinations that were added are sent to live sessions **at once** in a
  new route advertisement; for destinations that were withdrawn, the tunnels concerned are closed (RFC 9484 requires the
  routes given to stay for the life of the tunnel), and clients get the new routes when they reconnect automatically;
- `max_sessions` applies to new tunnels as soon as the configuration is reloaded;
- Changes to `interface`, `ipv4`, `ipv6`, `mtu`, `manage_network` or `allow_host_access` need a restart:
  `systemctl restart caddy-masque`.

When the certificate comes from files of your own (`tls CERT KEY`) and the files change while the Caddyfile does not,
`caddy reload --force` is needed to read them again (the reload in the service file already has `--force`). Certificates
Caddy obtains by itself need nothing.

## How it fits with Caddy (technical details)

- **HTTP/3**: Caddy's own HTTP/3 has HTTP Datagrams turned off, so CONNECT-IP over it can only carry packets in
  DATAGRAM capsules on the request stream (RFC 9297 §2.1.1, §3.5), which suffer TCP-like head-of-line blocking.
  This module therefore takes over the UDP port of HTTPS sites and serves HTTP/3 (with Datagrams) with the same
  certificates and the same site routes, and sends `Alt-Svc` headers the way Caddy does. Ordinary web requests over
  HTTP/3 are still handled by Caddy's routes. `http3 off` gives HTTP/3 back to Caddy.
- **HTTP/2**: Go's HTTP/2 does not accept extended CONNECT by default; it needs `GODEBUG=http2xconnect=1`.
  This module sets it automatically at program start (whether built with this project's `cmd/caddy` or with xcaddy);
  if the environment explicitly says `http2xconnect=0`, that is respected, HTTP/2 tunnels are then unavailable, and the
  log has a warning.
- **Encrypted connections only**: RFC 9484 §4 requires CONNECT-IP to run over TLS or QUIC. CONNECT-IP requests on
  connections without TLS (`http://` sites, h2c) always go to the website; no tunnel is set up.
- **Malformed requests**: an authenticated request whose `target` or `ipproto` is missing or invalid, or that has content
  headers, is malformed (RFC 9484 §4.1, RFC 9297 §3.2): the answer is 400; over HTTP/3 the request stream is also ended
  with H3_MESSAGE_ERROR as RFC 9114 §4.1.2 says (STOP_SENDING; the 400 still gets through). A destination that is not
  allowed (403), a DNS failure (502) and the like are refusals, not malformed requests. A tunnel the server aborts for
  another reason (an unanswered IPv6 MTU probe, a path too narrow for 1280-byte packets) is cancelled with
  H3_REQUEST_CANCELLED (HTTP/2: CANCEL), not reported as malformed.
- **Timeouts**: Caddy 2.11's default read and write idle timeouts (1 minute) and `read_timeout` and `write_timeout` do not
  apply to tunnels, which stay up however long they are idle; they apply to ordinary web requests as usual. The TCP
  connections of tunnels over HTTP/1.1 and HTTP/2 get the settings masque-vpn's server uses, whatever the server's
  `keepalive_*` options: keepalive probes after 10 seconds without traffic, every 5 seconds, and on Linux a
  `TCP_USER_TIMEOUT` of 30 seconds. So a client that is gone without closing its connection (a laptop that changed
  networks) is noticed in about 30 seconds rather than the 2.5 minutes of Caddy's keepalive, and its address and its
  place under `max_sessions` are free again. With a listener wrapper that hides the TCP connection, Caddy's keepalive
  applies.
- **Clients without HTTP/3 Datagram support**: packets are carried on the stream in DATAGRAM capsules (RFC 9297 §3.5).
- **Exit**: when Caddy exits it ends every tunnel itself, so open tunnels do not keep it from exiting.
- **Failed reloads**: users, reachable destinations and HTTP/3 return to the previous configuration. User and route
  changes on the shared tunnel are committed only after the entire new Caddy configuration starts successfully;
  a failed candidate does not revoke existing sessions.
- **HTTP/3 limits**: new connections snapshot the current Caddy header limit and HTTP idle timeout, including after
  reload. Existing connections keep their negotiated limits; active tunnels remain independent of website idle timeouts.

Known limitations:

- The `Alt-Svc` header is added only on sites with the `masque` directive; other sites on the same port can still use
  HTTP/3, they just are not advertised.
- The HTTP/3 the VPN takes over does not accept 0-RTT (replay risk), and does not apply Caddy's `packet_conn_wrappers`
  (such as the PROXY protocol over UDP).

CONNECT-IP is the only HTTP Datagram protocol supported by the bundled builds. An HTTP Datagram on any other
HTTP/3 request aborts that request with H3_DATAGRAM_ERROR (0x33), as RFC 9297 §2 requires, including unsupported
extended-CONNECT tokens and sites without the `masque` directive. Requests without Datagrams follow the site's
normal routes. The pinned
quic-go patch rejects those datagrams without taking over the request stream; ordinary request bodies, response
status codes and trailers retain their normal behavior. Recognized CONNECT-IP requests retain optimistic Datagrams,
including authentication refusals (RFC 9484 §7.1). Malformed datagrams (too short, or a Quarter Stream ID above 2⁶⁰−1)
close the connection with H3_DATAGRAM_ERROR, as RFC 9297 §2.1 requires.

HTTP/2 malformed requests and capsules use PROTOCOL_ERROR as required by
RFC 9113 §8.1.1 and RFC 9297 §3.3. The pinned dependency patch supplies the
reset API; frame-level tests also verify that other streams remain usable.
All three transports remain supported. IPv6 all-nodes MTU probes are answered
inside their authenticated tunnel and are never forwarded into the host network.
See [the earlier interoperability validation](docs/interop-2026-10-04.md).

## Tests

```sh
go test -race ./...                 # unit tests and in-process integration tests (no root needed)
sudo tests/e2e-netns.sh             # end-to-end tests: Caddy and the original masque-client in network namespaces
```

The in-process tests start a real Caddy inside the test process (with a fake TUN device) and use a small client written
in Go to do CONNECT-IP over HTTP/3, HTTP/2 and HTTP/1.1: sending and receiving packets, refusals that look like the
website, reloads (including failed ones), removed users, new blocks, idle timeouts and more.

With the current sibling masque-vpn checkout available, also run the real Rust
client and the current Mac/Killswitch public settings, packet and SOCKS APIs:

```sh
MASQUE_CLIENT=../masque-vpn/target/release/masque-client go test -race -count=1 -run '^TestInteropMasqueClient$' -v .
python3 tests/run-client-wrapper-interop.py --masque-vpn-root ../masque-vpn --release
```

The wrapper check requires all 16 combinations: Mac and Killswitch, four
transports, and IPv4-only or dual-stack servers. It validates protocol/core
interoperability; native macOS utun, routes, DNS restoration and PF protection
still require tests on a Mac. See [the harness and its scope](tests/clients/README.md).

See the [Caddy 2.11.7 and Go 1.27 verification report](docs/compatibility-2026-10-11.md)
for the tested artifacts, client coverage and remaining native-platform checks.

The end-to-end tests need the masque-vpn client (by default `../masque-vpn/target/debug/masque-client`, or set with
`CLIENT_BIN=`) and cover: the three transports, falling back to TCP when UDP is blocked, scoped requests (including
domain names the server resolves), reloading certificates and users, server crashes and restarts, client-to-client
traffic, SOCKS mode, LAN gateway mode, clearing connection tracking when addresses are reused, large file transfers with
checksums (300 MB download and 100 MB upload over HTTP/3, 100 MB / 50 MB each over HTTP/2 and HTTP/1.1), bad networks
(see below), a narrow path with an MTU of 1300, and more.

For release validation, set `CLIENT_BIN` to `masque-vpn/target/release/masque-client` built with
`cargo build --locked --release`. Build `tests/netsim` with Go and pass its path as `NETSIM` explicitly, including
when using sudo. Set `REQUIRE_ALL_TESTS=1` to make missing IPv6 or simulator support and any skipped checks fail.
CI uses this strict configuration so optimized-client regressions and adverse-network checks are exercised.

### Behaviour on bad networks

When the kernel has no netem, the tests use `tests/netsim` to make a slow link in the router (a user-space netem on a TUN
device: per-packet delay and jitter, random loss, packet order kept). Its software limiter verifies 4 Mbit/s aggregate
bandwidth without requiring kernel qdiscs. The tests also exercise 120 ms RTT, 1% and 5% loss, and 20-second and
70-second outages. UDP capacity measurements use 1200-byte application payloads to fit the guaranteed 1280-byte
CONNECT-IP path while QUIC discovers its MTU, and require actual receiver data. Results vary with the build and host;
the following throughput figures are previous measurements, with current validation in
[the interoperability report](docs/interop-2026-10-04.md):

- The tunnel sends and receives normally under all these conditions, and the checksums match; after a 20-second outage
  the QUIC connection recovers by itself without reconnecting; a 70-second outage is longer than the idle timeout, the
  client reconnects automatically, and the server cleans up the dead session.
- **Under random loss, HTTP/3 tunnels have much lower throughput than HTTP/2 tunnels.** At 120 ms RTT and 1% loss, an
  HTTP/3 tunnel downloads at 1.7 Mbit/s, with about 7 Mbit/s of UDP inside the tunnel; an HTTP/2 tunnel downloads at
  13 Mbit/s, with about 19 Mbit/s of UDP inside the tunnel. For comparison (same link, no tunnel): Linux TCP gets about
  70 Mbit/s, while quic-go streams and datagrams both get only about 2 Mbit/s; without loss both get hundreds of Mbit/s.
  This comes from how quic-go's congestion control reacts to random loss and is not something this module can change;
  the Rust server (quinn) is similar.
  **On networks with noticeable loss, `transport = "h2"` in the client configuration is much faster.**
- When bandwidth is limited, packets that have waited in the server's queue for more than 200 ms are dropped, so seconds
  of delay do not build up.
- When the path MTU is only 1300, HTTP/3 cannot be set up (both ends pad QUIC Initial packets to about 1400 bytes,
  which is how RFC 9484 §7.2 ensures that 1280-byte IPv6 packets get through), the client falls back to HTTP/2, and
  large file transfers work normally.

GitHub Actions runs the unit tests on every push to main and on every PR, plus `govulncheck` (weekly, and also on every
push and PR) to check dependencies and the standard library for known vulnerabilities. Dependabot sends weekly PRs with
dependency and Actions updates. Publishing a GitHub Release builds Caddy for Linux x86_64 and arm64, checks each
program's architecture and the archives' checksums, and attaches the archives with their SHA-256 files once every test
has passed (Actions → ci → Run workflow with a release's tag does the same for an existing release); while the
repository is public they also carry build provenance attestations
(`gh attestation verify FILE --repo ArcCal/caddy-masque`), which GitHub does not offer to private repositories. The
end-to-end tests with masque-client must pass on both native architectures before downloadable builds or release
uploads are produced. `MASQUE_VPN_TOKEN` must read masque-vpn; missing access fails the required job. Fork pull requests
cannot use repository secrets, so a maintainer must validate their changes from a trusted repository branch.
The standard and manual Cloudflare workflows package the exact checksum-bound Caddy executable that passed the
kernel and wire gates; they do not rebuild a different executable after testing. Every artifact includes Cloudflare DNS.
