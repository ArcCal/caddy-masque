# Caddy 2.11.7 and Go 1.27 compatibility verification

This report records the earlier x/net 0.59.0 compatibility repair. The
[subsequent HTTP/2 security repair](http2-security-2026-10-11.md) uses x/net
0.60.0 and fresh validation; its results supersede this report for security.

The repaired working tree supports the existing CONNECT-IP protocol on Go
1.26.9 and Go 1.27.2 without an additional HTTP/2 build tag. Caddy was upgraded
from 2.11.6 to [2.11.7](https://github.com/caddyserver/caddy/releases/tag/v2.11.7),
the official stable release published on 3 October 2026. The required clients
are masque-client, masque-vpn-mac and masque-vpn-killswitch; NF and Swift are
outside this repair's acceptance scope.

The Caddy working tree is based on `6e6e32e539243be22b810e29e5a3c1c47610754f`.
The current Rust checkout is based on
`faab6a65b33c563998d3ed35605d691e76b02b4f`. These are base commits, not commits
containing the uncommitted repair. The tested Linux amd64 server artifact has
SHA-256 `06ab8d91da4b5f6c00bd542fdb825a5990b43be52906f834aa32b88c76c876fc`.

## Repair and upgrade

The upstream x/net Go 1.27 wrappers delegate to the standard HTTP/2
implementation, which rejects the required extended-CONNECT client
pseudo-header on this path and lacks the patched stream-reset API. The local
fork now selects its existing patched server and transport on both supported
toolchains. Version-specific configuration and client-priority gates remain
intact. A compile-time assertion prevents silently selecting a writer without
`ResetStream`.

The existing reset and HTTP/3 Datagram rejection patches remain required.
`golang.org/x/net v0.59.0` and `github.com/quic-go/quic-go v0.63.0` remain pinned.
Custom main modules and xcaddy must explicitly replace both dependencies,
because Go does not inherit replacements from dependencies.

Caddy 2.11.7 fixes request-body deadline and idle-stream regressions from
2.11.6. Its response-writer wrappers still provide `Unwrap`, preserving access
to the reset API. This repair does not change CONNECT-IP forwarding,
authentication, routing, address assignment, capsules, MTU handling or session
algorithms.

An inherited HTTP/1-response diagnostic test intermittently failed on the
original checkout as well as the repaired fork. Only the fixture was changed:
response reads wait until request headers have been written. The original
malformed-header assertion and production transport retry logic remain intact.
Each supported Go version passed 1,000 race-enabled repetitions, with two
subcases per repetition and no diagnostic failures or data races.

## Results

| Check | Toolchain or target | Result |
| --- | --- | --- |
| Main module race suite, including real masque-client | Go 1.27.2, Caddy 2.11.7 | Passed |
| Main module race suite, including real masque-client | Go 1.26.9, Caddy 2.11.7 | Passed |
| Current Mac and Killswitch protocol-core matrix | Go 1.27.2, Caddy 2.11.7 | 16 passed, zero failed/skipped |
| Current Mac and Killswitch protocol-core matrix | Go 1.26.9, Caddy 2.11.7 | 16 passed, zero failed/skipped |
| Independent wire conformance | Final Go 1.27.2 binary, Caddy 2.11.7 | 75 passed, zero failed/skipped |
| Strict real-kernel end-to-end suite | Final Go 1.27.2 binary, Caddy 2.11.7 | 229 passed, zero failed/skipped |
| nftables ruleset suite | Isolated privileged Linux container | Three subcases passed, zero skipped |
| Patched HTTP/2, HPACK and HTTP/3 race suites | Go 1.26.9 and Go 1.27.2 | Passed |
| Exact HTTP/2 and HTTP/3 fork verification | Both Go versions | Passed |
| Capsule segmentation fuzzing | Go 1.27.2, Caddy 2.11.7 | 440,884 executions, passed |
| Module verification and vet | Go 1.27.2, Caddy 2.11.7 | Passed |
| Source vulnerability reachability scan | govulncheck 1.8.0 | Zero affected vulnerabilities; one module advisory outside the reachable code |
| Separate custom main build | Go 1.27.2, Caddy 2.11.7 | Passed; MASQUE modules registered |
| Actual xcaddy build with pinned Cloudflare plugin | xcaddy 0.4.7, Go 1.27.2, Caddy 2.11.7 | Passed; required modules and local replacements verified |
| Basic and wildcard/Cloudflare Caddyfile validation | Latest xcaddy artifact | Passed; no live Cloudflare operation |
| Workflow and shell syntax | Four YAML files, 25 shell blocks | Passed; remote Actions jobs not executed |

The unchanged protocol forks' full race suites were run after the build-selector
and fixture fixes. The Caddy upgrade then reran the main module, client matrix
and real-kernel gates. Earlier baseline evidence is retained separately:
the repaired Caddy 2.11.6 binary passed 75 wire and 229 kernel checks, with no
failures or skips. Baseline results are not substituted for the new run.

The outer host's nftables cases skip because it lacks kernel privileges; the
separate privileged container executed all three successfully. Other passing
test commands are not presented as having zero skips unless their runner
explicitly verifies that outcome.

## What the client and kernel checks cover

The independent probe checks RFC 9484, RFC 9297, RFC 8441 and RFC 9220 wire
behavior using its own requests, capsules and datagrams. Frame-level regressions
retain exact HTTP/2 error codes and unrelated-stream isolation, as well as
HTTP/3 Datagram rejection without disrupting ordinary website responses.

The kernel suite uses actual Linux TUN devices, network namespaces, nftables,
IPv4/IPv6 routing and the real Rust client. It checks checksummed transfers,
reload, revocation, isolation, 70-second HTTP/2 idle survival, vanished-client
cleanup, outages, reconnection, delay/loss, constrained paths, SOCKS and gateway
traffic.

Each 16-case wrapper matrix uses current app settings, public packet framing,
DNS probe and counted SOCKS APIs against real Caddy TLS/authentication and all
four modes: HTTP/3 Datagrams, HTTP/2, HTTP/1.1 and HTTP/3 DATAGRAM Capsules.
Both IPv4-only and dual-stack server configurations are tested. Cases verify
authentication isolation, concurrent VPN/SOCKS leases, 512 complete 1350-byte
bidirectional packets, accounting, MTU-probe survival and cancellation cleanup.
See [the reproducible runner](../tests/clients/README.md).

The wrapper harness uses channel-backed server TUN and native-host operations;
it does not execute private VPN counting adapters, macOS helpers, utun, system
routes/DNS, PF, GUI lifecycle or sleep/wake. Linux kernel testing does not prove
native macOS behavior. Native macOS and native arm64 execution remain unrun in
this amd64 cloud environment. The Rust client and wrapper builds used the debug
profile here; CI specifies optimized builds and both native Linux architectures.
These are correctness results, not release-profile throughput measurements.

## Integrity and reproducibility

Fork verification checks the pinned upstream checksum and hashes the actual
extracted source, replays the documented notice cleanup and Go formatting,
applies the recorded patch without fuzzy or offset matching, and compares every
file byte and directory. The shipped fork is never normalized during comparison.
Ten negative controls rejected tampering, unexpected/missing entries, symlinks,
incorrect pins and patch reapplication. `go mod tidy` removed the locally
replaced dependencies' upstream checksums during the upgrade; their four trusted
original checksum rows were restored so these independent integrity pins remain.

A token audit of 1,233 existing Go files found only the expected reset assertion
and test-fixture changes. Comments and build tags are outside that token audit;
build selection is verified separately by compilation and protocol tests.

Workspace evidence is retained under `/workspace/.onboarding/logs/caddy2117-*`,
`/workspace/.onboarding/kernel-compat/latest-caddy2117/`,
`/workspace/.onboarding/client-compat/` and
`/workspace/.onboarding/xcaddy-validation/`. Kernel evidence includes artifact
hashes, exact version/build information, timestamps and launcher exit codes.
