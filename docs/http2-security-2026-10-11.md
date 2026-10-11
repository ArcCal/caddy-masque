# HTTP/2 security repair, 11 October 2026

This repair fixes five inherited HTTP/2 vulnerabilities in the local x/net
replacement. The previous merged baseline was
`a0ac77a27e8d6a11f1f3f5a34c99c452ea3c6718`; updating Go alone did not repair
its separately vendored transport. Caddy remains at 2.11.7 and quic-go at
0.63.0. The HTTP/2 fork now uses checksum-verified x/net 0.60.0, the first
upstream release fixing all five advisories.

| Advisory | Retained upstream repair |
| --- | --- |
| [GO-2026-6603](https://pkg.go.dev/vuln/GO-2026-6603) | Account for each declared trailer field before allocating trailer metadata. |
| [GO-2026-6610](https://pkg.go.dev/vuln/GO-2026-6610) | Validate Content-Length and normalize forbidden response connection headers. |
| [GO-2026-6611](https://pkg.go.dev/vuln/GO-2026-6611) | Apply initial-window changes through shared accounting instead of visiting every active stream. |
| [GO-2026-6612](https://pkg.go.dev/vuln/GO-2026-6612) | Refund connection receive credit once when buffered body data is read or discarded, including reset streams. |
| [GO-2026-6617](https://pkg.go.dev/vuln/GO-2026-6617) | Defer HPACK table changes while a frame is being written; retain the smallest and final requested sizes. |

The recorded MASQUE patch still exposes ResetStream and selects the patched
server and transport on Go 1.26 and 1.27 without additional production build
tags. All surviving local patch additions and deletions are unchanged; only
the selector hunk for an upstream-deleted benchmark file was retired. The
reset API adds no separate flow-credit refund. CONNECT-IP, authentication,
Capsules, address assignment, routing and MTU algorithms are unchanged.

The complete source snapshot follows upstream 0.60.0, including its removal
of experimental x/net HTTP/3 code. Caddy and this module use the separate
quic-go fork for HTTP/3; that fork and its Datagram rejection patch are
unchanged. Independent review found identical Go tokens and compiler
directives in all 712 upstream Go files after the documented cleanup.

## Security evidence

The exact old baseline fails every advisory group using unchanged upstream
regression fixtures and the same bounded shared-window test as the fixed
control. Official x/net 0.60.0 passes all 31 required test events. The repaired
fork also passes 31 events under each supported Go patch release: 11 top-level
tests and 20 child cases, with zero failures or skips and the race detector
enabled. The supplemental window test uses 128 streams, positive and negative
window deltas, shrink and recovery. It checks shared-accounting correctness;
verified upstream source establishes the removal of per-update stream scans.
It is not an exhaustion benchmark or a claim of universal DoS resistance.

`tests/test-http2-security.py` first verifies the complete shipped fork, then
requires each named parent and child case, successful package completion,
valid JSON and no skips. Its test-only `http2legacy` tag selects upstream
internal fixtures on Go 1.27; ordinary server builds need no such tag.

Strict provenance checks verify the upstream module checksum, replay cleanup
and formatting, apply the recorded patch without fuzzy or offset matching,
and compare all actual file bytes and directories. Thirteen independent
negative controls rejected edited sources, missing/extra entries, symlinks,
nonregular files, cached-source tampering and offset patches. The recorded
HTTP/2 patch SHA-256 is
`7db335ab96b96156bc755945cc5a10a2b4e8e2c93e2be3427cce889a248cb97c`.

The validation and weekly workflows now query recorded upstream versions in
addition to scanning reachable code. The query checks the versions and actual
replacement directories selected by Go against the verified trees. This
prevents a local replacement from hiding an affected upstream version, or
testing a verified tree that production does not use. Any module advisory is
a review trigger, including advisories in unused packages or on other
platforms; it does not by itself prove reachable exploitation. The Cloudflare
build uses the latest patch of Go 1.26 instead of the old fixed 1.26.8 pin.

## Compatibility validation

| Check on the repaired source | Result |
| --- | --- |
| Named HTTP/2 security regressions, Go 1.26.9 and 1.27.2 | Each: 31 passes, zero failures/skips |
| Full HTTP/2 and HPACK race suites, both Go versions | Each: 506 top-level and 163 child passes; two original skips |
| Full HTTP/3 race suite, both Go versions | Each: 141 top-level and 211 child passes; zero failures/skips |
| Complete HTTP/2 and HTTP/3 provenance, both Go versions | Passed |
| Main module race suite with real masque-client, both Go versions | Each: 200 passing test events; all four real-client modes passed |
| Current Mac and Killswitch protocol-core matrix, both Go versions | Each: 16 passes, zero failures/skips |
| Independent RFC wire checks against the final Go 1.27.2 binary | 75 passes, zero failures/skips |
| Strict real-kernel end-to-end suite against that binary | 229 passes, zero failures/skips |
| Privileged nftables rulesets | Three modes passed, zero skipped |
| Final Linux amd64 server build, Go 1.26.9 and 1.27.2 | Passed; versions, modules and both replacements verified |
| Module verification and vet, both Go versions | Passed |
| Reachable source vulnerability scans, both Go versions | Zero affected/imported-package vulnerabilities; one uncalled required-module advisory |
| Selected transport source and upstream-version advisory gate, both Go versions | Correct replacement trees; zero transport advisories |
| Capsule segmentation fuzzing, Go 1.27.2 | 405,116 executions over 30 seconds, passed |
| Actual xcaddy and separate full custom main, with pinned Cloudflare | Built; modules and replacements verified; custom source scan passed |
| Workflow YAML and shell syntax | Four workflow files and 31 shell blocks parsed |

The two upstream race-suite skips are the external-network transport test and
the intentionally slow incremental HPACK test under the race detector. They
are distinct from required security, wire and interoperability cases.

Each main module run records four structural/platform skips: the subprocess
lifecycle helper outside its child-process invocation and three nftables modes
without host privileges. The parent lifecycle tests pass, and the separate
privileged container executes all three nftables modes successfully. Two
command/helper packages have no tests. None of the required real-client modes
is skipped. The Mac and Killswitch matrices use the current public app APIs,
all four transports and both IPv4-only and dual-stack server configurations;
the Rust clients use the debug profile in this cloud validation.

The strict kernel suite uses the real Rust client, Linux TUN, network
namespaces, nftables and IPv4/IPv6 routing. It verifies checksummed traffic,
website sharing, reload/revocation, scoped isolation, loss and outages,
constrained MTU, SOCKS/gateway behavior and shutdown/crash cleanup. The
HTTP/2 tunnel remains usable after 70 seconds idle without reconnecting;
a vanished client's server session ends after 31 seconds. These checks use
the final frozen artifact and freshly recorded results, rather than the
earlier compatibility artifact.

All 1,276 recorded Go, module, fork, Rust and harness input hashes remain
unchanged throughout both client acceptance runs. Local evidence is retained
under `/workspace/.onboarding/masque-http2-security/`,
`/workspace/.onboarding/logs/masque-security-*`,
`/workspace/.onboarding/kernel-compat/security-xnet060/`,
`/workspace/.onboarding/proofs/` and
`/workspace/.onboarding/masque-security-xcaddy/`. These are local cloud results;
workflow syntax validation does not establish that remote Actions jobs ran.

The final Linux amd64 Go 1.27.2 server artifact has SHA-256
`61c40f8a00c887782db1c664948f0661d6bc47c0b9ee4437483b1b9121e471bd`.
Actual xcaddy 0.4.7 also built Caddy 2.11.7 with the pinned Cloudflare plugin
and both local transport replacements. Its normal default storage build tags
were retained; no HTTP/2 selection tag was added. Basic and wildcard/Cloudflare
configuration validation passed without live DNS or ACME operations.
The default-tag custom main also built and passed module verification and a
reachable source vulnerability scan, with the same uncalled module advisory.
The Go 1.26.9 Linux amd64 server artifact has SHA-256
`37e3f35e72f7511264a4fd1747a2a0b3d213a52c42414fc261acb5b0ac6348d6`.

Native macOS utun, routes/DNS, PF, GUI lifecycle and sleep/wake, native arm64
execution and optimized-client performance are separate checks. Linux tests
and the public Mac/Killswitch protocol-core harness do not certify those
platform-specific behaviors. See the [harness scope](../tests/clients/README.md)
and the [earlier compatibility report](compatibility-2026-10-11.md), whose
0.59.0 artifact and results remain historical evidence.

## Reproduce and rebuild

Use Go 1.26.9 or 1.27.2, or a later reviewed patch of those supported lines:

```sh
python3 tests/verify-http2-fork.py
python3 tests/verify-http3-fork.py
python3 tests/check-transport-vulnerabilities.py
python3 tests/test-http2-security.py
```

Rebuild from updated main; the earlier artifact and release tag do not acquire
this repair automatically. On a Mac, from the repository checkout:

```sh
git switch main
git pull --ff-only
GOTOOLCHAIN=go1.27.2 CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
  go build -trimpath -o caddy-masque-linux-amd64 ./cmd/caddy
file caddy-masque-linux-amd64
go version -m caddy-masque-linux-amd64
```

The file must be a Linux x86-64 ELF binary. Its build information must show
Caddy 2.11.7, x/net 0.60.0 and both local transport replacements. Run it on
Linux; it is not a macOS executable. Custom main modules and xcaddy must keep
both explicit replacements as documented in [third_party](../third_party/README.md).
