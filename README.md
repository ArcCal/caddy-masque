# caddy-masque

The [masque-vpn](https://github.com/ArcCal/masque-vpn) server rewritten in Go as a Caddy module:

- **Standards**: IETF MASQUE IP proxying, CONNECT-IP (RFC 9484); HTTP Datagrams and Capsules (RFC 9297);
  extended CONNECT over HTTP/2 and HTTP/3 (RFC 8441, RFC 9220). HTTP/3, HTTP/2 and HTTP/1.1 are all supported.
- **Clients unchanged**: masque-vpn's `masque-client` and MasqueVPN on the Mac connect directly, without changing a single
  line of their configuration (over HTTP/3 with IPv6 on, older clients need the note on the MTU probe below). Password hashes made by `caddy masque-passwd` and by masque-vpn's `masque-passwd` are interchangeable.
- **Caddy handles certificates and traffic**: certificates are obtained and renewed automatically; the VPN and the website
  share port 443 (TCP and UDP); the same Caddy can go on hosting other sites and reverse proxies as usual.
- **Looks like just a website**: only CONNECT-IP requests with a correct user name and password become tunnels;
  every other request (including ones with a wrong password, and probes) goes to the website, and the response is
  exactly what an ordinary Caddy website gives.

Linux only (needs root: it creates a TUN device and sets up forwarding and NAT).

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

Needs Go 1.26:

```sh
go build -o caddy ./cmd/caddy
```

The resulting `caddy` is a complete Caddy (with all the standard modules) plus this module. xcaddy works too:
`xcaddy build --with github.com/ArcCal/caddy-masque`.

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

vpn.example.com {
	masque
	root * /var/www/site
	file_server
}
```

The `masque` directive in the site takes the VPN requests; all other requests carry on as usual (here, to `file_server`
for the web pages). It is ordered automatically before `file_server`, `reverse_proxy` and the like.

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
| `http3 off` | Do not take over HTTP/3 (see below); the VPN uses only HTTP/2 and HTTP/1.1 | Taken over |
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
Caddy's admin endpoint listens only on `localhost:2019` by default, out of the clients' reach; do not make it listen on
all addresses.

### Against password guessing and pool exhaustion

- After more than 10 requests with wrong credentials within a minute from one client address (for IPv6, per /64), its
  requests that carry credentials are not checked for the next minute but are treated as ordinary web requests (like
  requests without credentials). Users sharing an outgoing address affect one another during that minute.
  Generated passwords have 144 bits and cannot be guessed; passwords of your own given to `masque-passwd --stdin` need
  at least 12 characters; make them long and random.
- Each user may have at most `max_sessions` tunnels at once (default 8); requests beyond that get 429. Otherwise one
  account could take the whole address pool and crowd out the other users. When a device reconnects after losing its
  connection, the old tunnel still counts until the server notices it is gone, so do not set this to 1.

### Monitoring

Caddy's `metrics` directive and admin endpoint (`curl localhost:2019/metrics`) include these metrics:
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
If you change it, change the client's `uri_template` to match. The host name in the client's `uri_template` must match
the site address.
The template may use the forms RFC 9484 §3 allows: simple expressions in the path and query (`{target}`,
`{target,ipproto}`, with fixed text before or after), `{?target,ipproto}`, `{&...}`, and fixed parameters (such as `?v=1`).
The template may contain other variables: clients define only `target` and `ipproto`, other variables are left out when
expanded (RFC 6570), and the server matches accordingly.
Forms the server cannot match unambiguously (two expressions next to each other, a variable as a parameter name, text
after `{?...}` that does not start with `&`) are an error when the configuration is loaded, rather than failing to match
at request time.

## Managing users

```sh
caddy masque-passwd --name iphone
```

Add the `user ...` line it prints to `masque { }` in the Caddyfile, then `systemctl reload caddy-masque`.
The output also has the user name and the random password for the client configuration. To choose the password
yourself: `echo PASSWORD | caddy masque-passwd --name iphone --stdin`.

## Reloading the configuration

`systemctl reload caddy-masque` (that is, `caddy reload`):

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

- **HTTP/3**: Caddy's own HTTP/3 has HTTP Datagrams turned off, so CONNECT-IP cannot work over it.
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
  allowed (403), a DNS failure (502) and the like are refusals, not malformed requests.
- **Timeouts**: Caddy 2.11's default read and write idle timeouts (1 minute) and `read_timeout` and `write_timeout` do not
  apply to tunnels, which stay up however long they are idle; they apply to ordinary web requests as usual.
- **Clients without HTTP/3 Datagram support**: packets are carried on the stream in DATAGRAM capsules (RFC 9297 §3.5).
- **Exit**: when Caddy exits it ends every tunnel itself, so open tunnels do not keep it from exiting.
- **Failed reloads**: when the new configuration fails to start, users, reachable destinations and HTTP/3 all go back to
  the old configuration.

Known limitations:

- The `Alt-Svc` header is added only on sites with the `masque` directive; other sites on the same port can still use
  HTTP/3, they just are not advertised.
- The HTTP/3 the VPN takes over does not accept 0-RTT (replay risk), and does not apply Caddy's `packet_conn_wrappers`
  (such as the PROXY protocol over UDP).
- Over HTTP/2, RFC 9113 §8.1.1 requires malformed requests (and malformed capsules, RFC 9297 §3.3) to be treated as
  stream errors of type PROTOCOL_ERROR. The Go HTTP/2 server Caddy uses (`x/net/http2`) does not let handlers choose the
  error code; the only stream reset a handler can cause is INTERNAL_ERROR. So malformed requests get only a 400, and
  malformed capsules end the tunnel with INTERNAL_ERROR. Clients that follow RFC 9484 still treat this as a failure
  (§4.5: any non-successful response is a failure), but the meaning of the error code still does not conform to RFC 9113.
  This cannot be fixed in this module: patching `x/net/http2` would affect only this repository's `cmd/caddy`, while
  builds made with xcaddy would stay as they are, and the same version would behave differently depending on how it was
  built. It has to wait for Go to provide a way for handlers to reset a stream with a given error code.

## Tests

```sh
go test -race ./...                 # unit tests and in-process integration tests (no root needed)
sudo tests/e2e-netns.sh             # end-to-end tests: Caddy and the original masque-client in network namespaces
```

The in-process tests start a real Caddy inside the test process (with a fake TUN device) and use a small client written
in Go to do CONNECT-IP over HTTP/3, HTTP/2 and HTTP/1.1: sending and receiving packets, refusals that look like the
website, reloads (including failed ones), removed users, new blocks, idle timeouts and more.

The end-to-end tests need the masque-vpn client (by default `../masque-vpn/target/debug/masque-client`, or set with
`CLIENT_BIN=`) and cover: the three transports, falling back to TCP when UDP is blocked, scoped requests (including
domain names the server resolves), reloading certificates and users, server crashes and restarts, client-to-client
traffic, SOCKS mode, LAN gateway mode, clearing connection tracking when addresses are reused, large file transfers with
checksums (300 MB download and 100 MB upload over HTTP/3, 100 MB / 50 MB each over HTTP/2 and HTTP/1.1), bad networks
(see below), a narrow path with an MTU of 1300, and more.

### Behaviour on bad networks

When the kernel has no netem, the tests use `tests/netsim` to make a slow link in the router (a user-space netem on a TUN
device: per-packet delay and jitter, random loss, packet order kept), rate-limited with tbf: 120 ms RTT, 1% and 5% loss,
4 Mbit/s bandwidth, and 20-second and 70-second outages. Results:

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
dependency and Actions updates, and release archives carry build provenance attestations
(`gh attestation verify FILE --repo ArcCal/caddy-masque`). When the repository has `MASQUE_VPN_TOKEN` set (a token that
can read masque-vpn), the end-to-end tests run too.

## License

MIT or Apache-2.0, the same as masque-vpn.
