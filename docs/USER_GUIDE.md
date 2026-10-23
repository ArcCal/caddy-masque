# caddy-masque practical user guide

This is an operator's guide to the CONNECT-IP server implemented by this
repository. Commands assume a Linux server and an authenticated checkout
where repository access requires it. Replace example domains, interfaces,
addresses and credentials with your own values. Procedures and retained test
results are distinguished throughout; this guide does not claim that a new
production deployment was executed while the documentation was written.

## Contents

- [What the server does](#what-the-server-does)
- [Choose a build and deployment](#choose-a-build-and-deployment)
- [Prepare the server](#prepare-the-server)
- [Install using the supplied script](#install-using-the-supplied-script)
- [Build manually](#build-manually)
- [Create credentials and configure Caddy](#create-credentials-and-configure-caddy)
- [Connect a client](#connect-a-client)
- [Configuration reference](#configuration-reference)
- [Certificates and Cloudflare DNS](#certificates-and-cloudflare-dns)
- [Operate, reload and monitor](#operate-reload-and-monitor)
- [Troubleshooting](#troubleshooting)
- [Validation and acceptance](#validation-and-acceptance)
- [Upgrade, rollback and remove](#upgrade-rollback-and-remove)

## What the server does

`caddy-masque` adds an authenticated MASQUE CONNECT-IP server to Caddy. It
accepts IP tunnels over HTTP/3, HTTP/2 and HTTP/1.1 while ordinary website
traffic shares the HTTPS listener. The server creates a Linux TUN interface
and, by default, configures forwarding and NAT for authenticated clients.

It is not a client, a WARP account-registration tool, an HTTP CONNECT proxy,
or a generic CONNECT-UDP server. A browser's successful visit to the website
does not establish that a client can authenticate, obtain a tunnel address,
forward TCP/UDP traffic or resolve DNS through the server.

| Deployment component | Role |
| --- | --- |
| This repository's `caddy` executable | Public-facing server, website, TLS and CONNECT-IP endpoint |
| Rust `masque-client`, Go `masque-client`, or supported app | Remote client; its selected mode controls that device's routing or proxy behavior |
| Server TUN, default `masque0` | Carries authenticated client packets inside Linux |
| Server `inet caddy-masque` table | Managed forwarding/NAT and protection of host services from tunnel clients |
| Cloudflare DNS provider module | Optional DNS-challenge certificate issuance, not the tunnel's remote backend |

Linux amd64 and arm64 are the product targets. Runtime needs TUN and
network-management privileges, normally supplied by the root systemd unit.
Do not confuse a successful arm64 cross-build with native arm64 acceptance.

Ordinary non-tunnel requests follow Caddy's normal site handlers. Refused
HTTP/2 or HTTP/3 CONNECT-IP requests retain the site's body, but a successful
site status is converted to 404: 2xx would incorrectly signal a successful
tunnel. Existing error/redirect statuses can remain. Malformed requests
receive protocol-required errors. The project does not promise that every
refusal is indistinguishable from a successful website response.

## Choose a build and deployment

Use current reviewed source for current fixes. Release labels and draft
release records do not prove a downloadable release or a corresponding Git
tag exists. In particular, the repository's `v1.2.0` release record is a draft
and is not a published downloadable release. Do not use `git checkout
v1.2.0` as an installation instruction unless that tag is actually published
later. Check the authenticated Releases page for the artifacts currently
available and their checksums.

Main contains fixes newer than the historical release material, including
HTTP/2 security, standards validation, reload/lifecycle and interoperability
repairs. Read [the changelog](../CHANGELOG.md) and
[the comprehensive recheck](comprehensive-recheck-2026-10-18.md) when deciding
which source to deploy. Record `git rev-parse HEAD` for reproducibility.

For a new supported Debian/Ubuntu server, the supplied installer is the
shortest route. For an existing Caddy installation, inspect modules and
configuration first and use a controlled manual migration. Two Caddy or
MASQUE server processes cannot bind the same TCP/UDP ports or own the same
TUN/firewall state.

## Prepare the server

You need:

1. A Linux amd64/arm64 machine with a usable `/dev/net/tun`, appropriate
   privileges and nftables/conntrack/NAT kernel support.
2. A public DNS name pointing to the server. Publish an AAAA record only if
   that address actually reaches the server. Public TLS validation and
   reliable certificate renewal must work.
3. TCP 80 and TCP 443 allowed for the supplied default deployment, plus UDP
   443 for HTTP/3, in both host and provider firewalls. Other certificate
   challenge strategies can have different port requirements.
4. Actual upstream IPv4 Internet access; enable tunnel IPv6 only when the
   server has working upstream IPv6 too.
5. A nonoverlapping tunnel pool. The examples use `10.89.0.1/24`; avoid
   overlap with server networks, client LANs and other VPNs.
6. A secure way to administer and recover the machine while changing a
   root network service.

Useful initial checks:

```sh
uname -m
test -c /dev/net/tun
ip -4 address show
ip -4 route show
sudo nft list ruleset
sudo ss -ltnup
```

Save a private baseline of the existing Caddy binary/configuration, service
units, routes, nftables ruleset and forwarding sysctls. Check for `caddy`,
`nginx`, `apache2` or `masque-server` already occupying ports. Container
providers can expose a TUN node while still denying the necessary operations.

The server's own Internet traffic and resolver are not converted into a
client full tunnel. Its managed input protection targets traffic arriving
from the server TUN. Public-interface SSH/firewall policy remains yours to
configure separately. Existing firewall drops can still override traffic
accepted by the module's rules.

## Install using the supplied script

The installer targets Debian 12/13 and Ubuntu 22.04/24.04:

```sh
git clone https://github.com/ArcCal/caddy-masque.git
cd caddy-masque
sudo bash deploy/install-server.sh vpn.example.com
```

Read [the script](../deploy/install-server.sh) before running it on an existing
server. It installs required distribution packages and a checksum-verified
official Go toolchain, builds the repository's Caddy, installs it at
`/usr/local/bin/caddy`, writes the initial `/etc/caddy/Caddyfile` and cover
page if needed, generates a device account, and starts `caddy-masque.service`.
It prints client credentials at the end and saves the generated credentials
in `/root/masque-credentials.txt`, mode 0600. That file contains the plaintext
client password: keep it private, outside website roots and support bundles,
and retain or remove it deliberately after storing the credentials securely.

The installer checks for TUN availability and conflicting web services. It
handles an active ufw configuration for its documented ports/forwarding and
warns about a Docker FORWARD policy that needs operator attention. It cannot
open your provider's external firewall or repair incorrect public DNS.

Rerunning the script rebuilds and restarts the service while retaining an
existing Caddyfile, users and certificates. This is not a zero-interruption
upgrade. Back up existing state first; custom Caddy settings still require
review against the current binary and service restrictions.

If migrating from the Rust server, stop and disable `masque-server` before
starting this server, after preparing rollback. Its `[[user]]` username/hash
pairs map to `user NAME HASH` lines. The plaintext password kept by each
client remains unchanged; its hash is not the client's password value.

## Build manually

The documented reviewed toolchains are Go 1.26.9 and 1.27.2, or a later
reviewed patch in those lines. The module's minimum language declaration is
not a substitute for applying standard-library security patches.

```sh
go version
go mod verify
go build -mod=readonly -o caddy ./cmd/caddy
./caddy version
./caddy list-modules
```

Confirm the output includes all three modules:

```text
masque
http.handlers.masque
dns.providers.cloudflare
```

The default binary includes standard Caddy modules and Cloudflare DNS
v0.2.4. It uses the pinned local HTTP/2 and HTTP/3/QUIC trees. A plain upstream
Caddy binary does not contain this module. Custom `xcaddy` or separate-main
builds must preserve both dependency replacements; Go does not inherit them
from a dependency's `go.mod`:

```sh
xcaddy build v2.11.7 --with github.com/ArcCal/caddy-masque=. \
  --with github.com/caddy-dns/cloudflare@v0.2.4 \
  --replace golang.org/x/net=./third_party/xnet \
  --replace github.com/quic-go/quic-go=./third_party/quic-go
```

Run that command from this checkout. Review
[the dependency patch instructions](../third_party/README.md); do not
silently replace the shipped forks with an unpatched library merely to make
a custom build succeed. Verify the final executable's modules and checksum.

For a manual systemd installation, install the executable, create the Caddy
configuration/site files and copy the supplied unit:

```sh
sudo install -m 0755 caddy /usr/local/bin/caddy
sudo install -d -m 0700 /etc/caddy
sudo install -d -m 0755 /var/www/site
sudo install -m 0644 deploy/caddy-masque.service /etc/systemd/system/caddy-masque.service
```

Complete the next section before enabling the service. Do not overwrite an
unrelated installation's binary or Caddyfile without a migration plan.

## Create credentials and configure Caddy

Generate one account per device:

```sh
./caddy masque-passwd --name laptop
```

The command prints a complete `user laptop $argon2id$...` line for the
server, plus `username` and plaintext `password` lines for the client. Copy
each to the correct side. Generated passwords have 144 bits of entropy.
Usernames allow 1-64 letters, digits, hyphen, underscore or dot.

`--stdin` reads a chosen password instead of generating one. It must contain
at least 12 characters and no control characters. Avoid putting a plaintext
password in shell history or process arguments. The command intentionally
does not echo a supplied password back as a ready-to-copy client value.

Create `/etc/caddy/Caddyfile` with the following structure, replacing the
entire placeholder user line with the complete generated line:

```caddyfile
{
    masque {
        ipv4 10.89.0.1/24
        user laptop REPLACE_WITH_COMPLETE_ARGON2ID_HASH
    }
}

vpn.example.com, :443 {
    masque
    root * /var/www/site
    file_server
}
```

Create actual site content in `/var/www/site`, keep configuration ownership
restricted, and adapt/validate before starting:

```sh
sudo chmod 0600 /etc/caddy/Caddyfile
sudo /usr/local/bin/caddy adapt --config /etc/caddy/Caddyfile --adapter caddyfile --pretty
sudo /usr/local/bin/caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo systemctl daemon-reload
sudo systemctl enable --now caddy-masque
sudo systemctl status caddy-masque
sudo journalctl -u caddy-masque -b -n 100 --no-pager
```

Treat `adapt` output as sensitive: it includes password hashes and can include
other configuration secrets. Successful adaptation checks Caddyfile
translation. Validation adds module/configuration checks; neither proves
live ACME issuance, kernel forwarding or successful client traffic.

The global `masque` block defines the one tunnel/pool/user service. The site
`masque` directive routes matching requests to it. Both are required. Other
site handlers continue to serve ordinary requests.

The `:443` site address additionally accepts HTTPS requests whose authority
is a numeric IP, as some clients use. TLS verification still needs a trusted
certificate for the configured server name. `server_name` on a client does
not change its HTTP authority; merely setting it cannot fix a site that
never matches the request. Review the catch-all site's effect if Caddy hosts
several unrelated domains.

## Connect a client

The default endpoint template is:

```text
https://vpn.example.com/.well-known/masque/ip/{target}/{ipproto}/
```

For the current Go gateway client, use this minimal configuration as a
starting point, with the generated plaintext password:

```toml
uri_template = "https://vpn.example.com/.well-known/masque/ip/{target}/{ipproto}/"
username = "laptop"
password = "REPLACE_WITH_THE_DEVICE_PASSWORD"
mode = "gateway"
transport = "auto"
target = "*"
ipproto = "*"
ipv6 = false
dns = ["1.1.1.1", "9.9.9.9"]
```

The Rust client and GUI variants have their own mode/configuration contracts;
use their manuals rather than copying Go-only assumptions. Client full-tunnel
mode needs a full scope. A scoped request supported by the server does not
mean a particular client accepts it in gateway mode.

Test explicit `h3`, `h2` and `http/1.1` client transports separately, then
Auto fallback. With the module's `http3 off`, HTTP/3 remains available through
Caddy where configured, but IP packets travel in stream DATAGRAM capsules
rather than QUIC DATAGRAM frames. This is a fourth useful interoperability
case, not a fourth client transport-string value.

Verify a granted address, TCP and UDP exchange, DNS, the expected egress
address, large transfers and reconnect behavior. A successful HTTP handshake
alone is insufficient. Use another account to verify isolation; test wrong
credentials without assuming they will produce a Basic-auth 401 prompt.

Client-side network takeover, local SSH safety, DNS restoration and macOS
PF/utun behavior belong to the client. A passing server fixture does not
prove those native effects. In particular, the Go client's LAN firewall is
not an unconditional LAN-SSH allowlist.

## Configuration reference

These are Caddyfile options inside the global `masque` block. See
[the parser](../caddyfile.go) and [application defaults](../app.go) for the
JSON schema and precise validation.

| Option | Default | Practical use and caution |
| --- | --- | --- |
| `ipv4 ADDRESS/PREFIX` | Required | Server TUN address and client pool; choose nonoverlapping space |
| `ipv6 ADDRESS/PREFIX` | Absent | Enable only with working upstream IPv6; not needed for IPv4-only service |
| `interface NAME` | `masque0` | Keep exclusive ownership; name length at most 15 characters |
| `mtu BYTES` | 1350 | 576-1500 for IPv4; at least 1280 when IPv6 is configured |
| `user NAME HASH` | No users | One device account per line; Argon2id PHC hash |
| `max_sessions N` | 8 per user | Positive count or `unlimited`; avoid 1 because an old lost session can coexist with its reconnect |
| `block PREFIX...` | Built-in blocked destinations | Explicit entries replace the defaults, rather than extending them implicitly |
| `block none` | Not set | Removes configurable destination blocks; do not use casually |
| `allow_client_to_client` | Off | Permit client-pool reachability; assess device isolation first |
| `allow_host_access` | Off | Permit tunnel clients to reach server services; requires a separate host-access policy |
| `manage_network off` | Management on | Operator owns forwarding/NAT/firewall; TUN is still created |
| `http3 off` | Takeover on | Use Caddy's stream-carried H3 instead of the module's H3 DATAGRAM service |
| `mtu_probe off` | Probe on | Only when out-of-band/direct-path assurance satisfies the documented MTU requirement |

The default destination list excludes private, loopback, multicast,
benchmarking and several transition/cloud-internal ranges. Link-local
unicast (`169.254.0.0/16`, `fe80::/10`) is never forwarded, regardless of
`block`. Traffic addressed to the server itself is local input, not forwarded
traffic; changing `block` does not substitute for host-service protection.

By default the managed nftables input chain permits tunnel ping and
established replies but blocks other unsolicited host-service access from
the TUN. Enabling `allow_host_access` broadens that exposure, including
services bound to all addresses or the server's public addresses. With
`manage_network off`, implement the corresponding protection yourself.

The site form is `masque [PATH_TEMPLATE]`. Omit the template for the default;
if changed, update clients too. Supported URI-template forms are described
in the README. Ambiguous templates are rejected during configuration load.

For dual-stack HTTP/3 DATAGRAM sessions, the server checks a 1280-byte IPv6
path using ICMPv6 Echo and closes the tunnel after about ten seconds without
a valid reply. A client can receive an IPv6 probe even when it requested
IPv4-only behavior. Current supported client cores contain responders, but
older clients and native firewall behavior need separate attention. Use H2
to diagnose a probe/firewall problem. Do not disable the probe simply to
hide an unknown MTU failure; `mtu_probe off` requires the documented
out-of-band/direct-path assumption.

## Certificates and Cloudflare DNS

Normal Caddy automatic HTTPS can obtain/renew certificates for a reachable
domain using its standard challenges. Cloudflare DNS support is included in
every default build; using it is optional and requires your own scoped
Cloudflare API credential.

For DNS challenges, a site can use a root-readable token file:

```caddyfile
example.com, *.example.com, :443 {
    tls {
        dns cloudflare {file./etc/caddy/cloudflare-token}
    }
    masque
    root * /var/www/site
    file_server
}
```

Keep the global `masque` block from the previous example. Store only the
token in `/etc/caddy/cloudflare-token`, restrict its permissions, and grant
only the DNS permissions/zones required by your deployment. Do not embed
tokens in public configs or diagnostic dumps. Check file access under the
actual service restrictions.

Provider module registration or validation with a dummy token does not
prove live DNS updates, certificate issuance or renewal. Verify issuance
and later renewal using your own account and journal. Keep Caddy's state
directories across upgrades so ACME account/certificate state is retained.

## Operate, reload and monitor

The supplied unit runs as root but restricts capabilities, devices,
filesystem writes, system calls and address families. State lives under
`/var/lib/caddy` and `/var/lib/caddy-config`; logs may use `/var/log/caddy`.
A site that needs another writable directory requires a service drop-in
with the corresponding `ReadWritePaths`. Do not remove sandboxing simply
because a custom log path fails.

The admin API can read/replace the full configuration and stop this root
service. The unit sets it to a root-only Unix socket:
`/run/caddy-masque/admin.sock`, mode 0600 inside a mode-0700 runtime directory.
An explicit Caddyfile `admin` option overrides that choice. Do not expose an
unauthenticated network admin address. Caddy's ordinary localhost default
is still reachable by other local users/processes.

Common operations with the supplied unit:

```sh
sudo systemctl status caddy-masque
sudo journalctl -u caddy-masque -f
sudo systemctl reload caddy-masque
sudo systemctl restart caddy-masque
sudo systemctl stop caddy-masque
```

`reload` applies compatible user/site/policy changes without blanket tunnel
teardown and forces certificate rereading through the unit's command. Removed
users or withdrawn routes can terminate affected sessions. A failed
candidate preserves the prior committed configuration. Changes to interface,
IPv4/IPv6 pool, MTU, `manage_network` or `allow_host_access` require restart;
the module rejects changing its shared host-network settings through reload.
Restart disconnects clients and interrupts websites in that process.

To reload manually against the protected socket:

```sh
sudo caddy reload --config /etc/caddy/Caddyfile --address 'unix//run/caddy-masque/admin.sock'
```

To add or rotate a device, generate a new line, update the Caddyfile, reload,
and update that device's plaintext password. Replacing a hash invalidates
the remembered credentials for that account. Removing a user is a revocation
operation; verify that its old credential and sessions no longer work.

Enable Caddy metrics by adding `metrics` to the existing global options block
where appropriate, reload, and read the admin endpoint locally:

```sh
sudo curl --noproxy '*' --fail --silent --show-error --unix-socket /run/caddy-masque/admin.sock http://localhost/metrics
ip address show dev masque0
sudo nft list table inet caddy-masque
sysctl net.ipv4.ip_forward
```

Useful counters include `caddy_masque_sessions_active{user}`,
`caddy_masque_sessions_started_total`, `caddy_masque_auth_failures_total`,
`caddy_masque_auth_throttled_total`, `caddy_masque_packets_total{direction}`,
`caddy_masque_bytes_total{direction}` and `caddy_masque_packets_dropped_total`.
Reload does not reset the shared counters. Protect access because usernames
and operational metadata can be sensitive.

Authentication is deliberately bounded. Wrong credentials can trigger
per-address throttling, IPv6 source grouping is by /64, password-check queues
are limited, remembered valid credentials use an in-memory cache, and session
limits bound pool consumption. HTTP 503 can indicate authentication capacity
or pool exhaustion; HTTP 429 indicates a user session limit. Account for
devices sharing one public NAT address when diagnosing repeated failures.

While alive with managed networking, the service checks forwarding/NAT
about every 30 seconds and tries to repair a removed table or disabled
forwarding. Coordinate host-firewall managers; repeated repair warnings are
a conflict to investigate, not evidence of stable integration.

On normal shutdown, the module closes its TUN, removes its own nftables table
and restores forwarding sysctls it changed. These cleanup calls can fail;
compare actual state with your baseline. SIGKILL cannot run cleanup, and saved
pre-start sysctls are not a durable on-disk recovery record. After a crash,
inspect leftover `inet caddy-masque` state and forwarding before restarting
or decommissioning. Never clear the entire host ruleset as a cleanup shortcut.

## Troubleshooting

| Symptom | Checks and next action |
| --- | --- |
| `unrecognized directive: masque` | You are running a different Caddy binary, or a build lacks the module; inspect executable path and `list-modules` |
| Missing `dns.providers.cloudflare` | Rebuild from the documented main/custom-main setup; do not assume a generic Caddy package includes it |
| `creating TUN device` failure | Check privileges, provider TUN support, an existing TUN owner and conflicting instances |
| Website works, tunnel refused | Verify both global/site directives, exact endpoint template, credentials, HTTP authority and client/server logs |
| Client connects by IP and sees malformed 200 | Ensure the correct site accepts that authority, for example the documented `:443` address; TLS name override alone is insufficient |
| HTTP/3 fails, H2 works | Check UDP 443 in both firewalls, path MTU and intermediate proxies; force H2 for diagnosis |
| HTTP/3 closes at about ten seconds | Check the IPv6 MTU probe, client version and native ICMPv6 filtering; do not assume the server rejected the password |
| Tunnel assigned but no Internet | Check forwarding, NAT, upstream reachability, blocked destinations, overlap and Docker/ufw/firewalld rules |
| Client cannot reach server SSH/admin service through tunnel | Default host-access protection is intentional; do not broadly enable access without a host firewall policy |
| New credentials receive 503 during load | Check bounded authentication capacity, shared-NAT throttling and pool availability; existing cached credentials have a different path |
| Device reconnect gets 429 | Check `max_sessions` and old sessions awaiting liveness timeout; avoid a limit of one |
| Reload fails after changing pool/interface/MTU | Those host-network settings require restart; restore the old file or schedule the controlled restart |
| Manual reload cannot find admin endpoint | Use the unit's Unix socket explicitly, with root privileges; check for an overriding `admin` option |
| Certificate issuance fails | Check A/AAAA, challenge ports or DNS token permissions, clock and ACME logs; module presence is not live issuance evidence |
| Custom logs/site writes fail under systemd | Check filesystem ownership and `ReadWritePaths`; foreground root success does not exercise the service sandbox |
| Throughput degrades on lossy H3 paths | Compare forced H2 with H3 under the same path and packet size; retained benchmark numbers are historical, not a deployment guarantee |

For a useful issue report, collect source revision, executable checksum,
`caddy version`/required modules, architecture, client revision/mode/transport,
sanitized Caddyfile, exact symptom, relevant logs and packet/kernel evidence.
Remove hashes/tokens/passwords and unrelated private configuration. Preserve
the timing and workload needed to reproduce the failure.

## Validation and acceptance

Start with the ordinary source checks:

```sh
go mod verify
python3 tests/verify-http2-fork.py
python3 tests/verify-http3-fork.py
go vet ./...
go test -mod=readonly -race -count=1 ./...
```

The main tests use real in-process Caddy/TLS transports with fake TUNs where
appropriate. Some cases need an actual sibling Rust client or privileged
Linux state; missing prerequisites can produce skips. Read the complete
result, including skip reasons. A passing parent test name or cached output
does not establish that a required external case executed.

With the unchanged Rust client and source checkout available:

```sh
MASQUE_CLIENT=/path/to/masque-client go test -race -count=1 -run '^TestInteropMasqueClient$' -v .
python3 tests/run-client-wrapper-interop.py --masque-vpn-root /path/to/masque-vpn --release
python3 tests/run-cf-client-interop.py --masque-vpn-root /path/to/masque-vpn --release
```

Read [the wrapper harness](../tests/clients/README.md) and
[the generic CF fixture](../tests/cf-clients/README.md) first. The combined
Mac/Killswitch/NF matrix expects 24 distinct cases; the independent CF
generic frontend expects eight. They verify portable protocol cores and
process contracts, not native macOS Network.framework, PF, utun or GUI
acceptance. The generic CF fixture does not test Cloudflare's live WARP
service.

For real kernel acceptance, follow [the existing end-to-end script](../tests/e2e-netns.sh)
on a suitable isolated privileged Linux host. Its basic invocation is:

```sh
sudo tests/e2e-netns.sh
```

For the strict release gate, provide the optimized Rust client through
`CLIENT_BIN`, a built `tests/netsim` executable through `NETSIM`, and
`REQUIRE_ALL_TESTS=1`, explicitly preserving those values through sudo as
described in the README/workflow. Do not run routing/firewall experiments on
the only production management path. Missing IPv6/simulator/kernel support
is not a strict gate pass.

The retained evidence has different dates and environments:

| Record | Reported evidence | Boundary |
| --- | --- | --- |
| [Caddy/Go compatibility report](compatibility-2026-10-11.md) | Historical 229 strict kernel end-to-end passes, 75 independent wire cases, both Go lines and wrapper/build checks | Applies to that tested source/artifact, not an automatic rerun for later main |
| [Comprehensive recheck](comprehensive-recheck-2026-10-18.md) | Both Go lines: 183 main top-level plus 161 nested passes; expanded transport/UDP controls; 41 portable client scenarios | Main suite has helper/privileged skips; native kernel/macOS/arm64 limits remain |
| [All-client follow-up](all-client-compatibility-2026-10-18.md) | 24 wrapper cases plus eight independent CF cases, client-side standards findings | Core interoperability is not native Apple integration or live WARP |
| [Client IETF audit](client-ietf-conformance-2026-10-18.md) | Client-specific malformed/edge-case findings and source/wire boundaries | Do not describe compatibility as complete client standards conformance |

The comprehensive recheck also records GitHub validation jobs prevented from
starting by an Actions budget. Those jobs did not run tests and are not green
CI. Local passing suites do not replace unavailable privileged/native gates.
Current workflow configuration is a test requirement, not evidence that its
latest run succeeded. This guide adds no fresh performance or deployment
claim.

HTTP/3 takeover does not accept 0-RTT or apply Caddy UDP
`packet_conn_wrappers`; Alt-Svc advertisement is scoped to sites with the
`masque` directive. Benchmark results vary by path and build. Reproduce
performance measurements on your own representative path, including loss,
MTU, outage recovery and sustained load.

## Upgrade, rollback and remove

For a source upgrade:

1. Back up the private Caddyfile, unit/drop-ins, site files, current binary
   and checksum, Caddy data/config directories and host network baseline.
2. Review changelog, required toolchain and fork-verification changes. Build
   and validate the candidate without replacing the active executable.
3. Run the appropriate test gates and inspect failures/skips; verify required
   modules in the exact candidate executable.
4. Schedule a restart for binary changes. Stop cleanly, replace the binary,
   start the service and verify site, all required client transports, DNS,
   TCP/UDP forwarding, accounts and metrics.
5. To roll back, stop, restore the matching binary/configuration and restart.
   Preserve certificate/state directories and confirm the old schema accepts
   the restored configuration.

Do not conflate a compatible configuration reload with a binary replacement.
The installer itself rebuilds/restarts on rerun, so plan its downtime too.

To decommission a dedicated installation:

```sh
sudo systemctl disable --now caddy-masque
sudo systemctl status caddy-masque
sudo nft list table inet caddy-masque
ip link show masque0
```

For the last two commands, the expected clean result is that the owned table
and TUN do not exist; distinguish that from permission/tool errors. Compare
forwarding sysctls with the saved baseline. After confirming cleanup and
that no other service uses the files, remove the dedicated unit and binary,
then run `systemctl daemon-reload`. Keep or deliberately delete private
config, tokens, certificates, state and logs according to your recovery
needs. The server may also host ordinary websites; removing it stops those
sites too. Never delete a shared Caddy installation or flush unrelated
firewall rules as part of uninstalling this module.
