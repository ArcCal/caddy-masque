# Production review — 2026-10-04

Baseline: `9dbb3ddd1d807d70015a95a7db517b442db61e8c`. The paired Rust
checkout starts at `d5d9084d7edef7dace634060c38d25346dd7c2c8` and includes
the transport/diagnostic fixes from the current review. This report covers
the new local runs; it does not claim a GitHub release or deployment.

## Changes

Supported server artifacts are Linux amd64 and arm64 only. The Darwin
artifact was removed. Release upload now depends on the complete test,
native-architecture end-to-end and build jobs. A release without the
`MASQUE_VPN_TOKEN` needed to read the Rust client repository fails instead
of passing through a skipped interoperability job. Upload no longer
silently overwrites an existing asset.

The required test job includes the reachable-dependency vulnerability scan.
Existing race, module/fork verification, fuzzing and patched HTTP/2/HPACK
tests remain. The rootless SOCKS kernel test copies its client into a private
temporary test directory so a 0700 source checkout does not prevent
execution; it does not loosen repository permissions.

No Caddy protocol implementation was changed in this review. Swift app-core
tests exposed an ordinary cover-page diagnosis difference in the Rust
client: an HTTP 200 page with content headers was correctly rejected but
did not mention checking credentials. The client now preserves rejection
and adds that diagnosis. IETF Masque's same app-core suite passes with both
actual server implementations after the fix.

## Validation performed

| Check | Result |
|---|---|
| Go 1.26.8 race tests over all packages | Passed |
| go vet / module integrity / pinned HTTP/2 fork verification | Passed |
| Patched upstream HTTP/2 and HPACK race tests | Passed |
| Capsule segmentation fuzzing | Passed, 30-second budget and 527,028 executions |
| Real kernel suite with optimized Rust client and netsim | 229 passed, 0 failed, 0 skipped |
| Swift app core with optimized current client and Caddy | 61 passed, 0 failed, no required end-to-end skips |
| Independent connect-ip-go client → Caddy | HTTP/3 IPv4 assignment, requested addresses, routes and small/1200-byte-payload pings passed |
| Linux arm64 cross-build, QEMU Go tests and module/version smoke test | Passed; this is emulation, not native ARM hardware |
| Workflow actionlint, shell syntax and diff checks | Passed |
| govulncheck | No affected symbols or imported packages |

The kernel suite exercises HTTP/3, HTTP/2 and HTTP/1.1, IPv4/IPv6, MTU probes,
malformed HTTP/2 stream resets, cover-site and credential handling, access
controls, source validation, reload/restart/crash behavior, idle/dead sessions,
address reuse/connection tracking, constrained paths and outages, SOCKS and
LAN gateway/DNS behavior. Early runs affected by missing container TUN nodes,
private source-directory permissions and Docker VFS disk exhaustion were
invalidated. The result above is the subsequent complete passing run.

Govulncheck reports module advisory GO-2026-5932 for the unmaintained OpenPGP
package in golang.org/x/crypto v0.57.0. It found no imported OpenPGP package
and no affected symbols. The module is required for other cryptography;
the advisory was not hidden with an ignore rule.

Logs and binary/source fingerprints are in `/workspace/production-review`.
The paired project has the detailed combined report in
`masque-vpn/docs/review-2026-10-04-production.md` and the platform/release
contract in `masque-vpn/docs/release.md`.

## Remaining release requirements

The local host is Linux x86_64. Native Linux arm64 kernel validation is a
required GitHub job and was not executed on actual ARM hardware here.
Linux Swift tests do not validate the IETF Masque SwiftUI app or native
macOS process/packaging behavior. The client/app release requires the
agreed self-hosted macOS 27 arm64 runner and SDK; that release is blocked
until its native gate passes. Configure cross-repository GitHub read
access before publishing from private repositories.

Local workflow validation does not mean these GitHub jobs have run.
Production-site certificates, DNS, firewall, MTU, forwarding and rollback
still require validation on the destination host. The completed checks
support the stated CONNECT-IP conformance/interoperability scope, rather
than a claim of flawless behavior for every possible peer and deployment.
