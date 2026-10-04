# Production readiness review — 2026-10-03

The review found defects in credential isolation, shutdown ordering, URI matching
performance, and deployment tooling. This branch fixes those defects and adds
repeatable regression and kernel lifecycle checks. Passing these checks does not
establish that an arbitrary production host, Cloudflare token, or client will work.

The subsequent [security and IETF audit](security-ietf-audit-2026-10-04.md)
identifies confirmed standards gaps and unresolved capacity risks. Its verdict
governs strict standards conformance and large-deployment readiness; the passing
checks recorded below do not close those findings.

## Changes and reasons

- Bind reconnect address reuse to the password hash as well as the username.
  Previously, a changed password could inherit the old credential's NAT state.
  A regression test failed before the fix and verifies connection-state cleanup.
- Wait for in-flight host repair before closing the network. Previously, repair
  could recreate firewall rules while shutdown removed them or restored sysctls.
  A blocked repair test verifies shutdown ordering.
- Reject impossible URI template suffixes early and avoid copying unescaped
  captures. The existing bounded-matching test failed under the race detector
  before the change; its original timing requirement is preserved.
- Validate replacement binaries and preserve every installed custom module.
  Installation now stages an executable on the destination filesystem and renames
  it atomically. The one-step installer accepts `CADDY_BIN` and restores the old
  binary when installation or service startup fails. Regression tests verify that
  missing modules and invalid configuration leave the working binary untouched.
- Remove the service's environment dump so environment-based DNS tokens are not
  logged at startup. Set its home directory to the existing state directory.
- Correct two flaky address tests: a spoofed source could be randomly leased
  to the client, and an allegedly unassigned destination could belong to either
  client. Spoofing now uses an address outside the pool; the unknown-destination
  check selects an address that neither client owns inside the pool.
- Read the configured tunnel interface before replacing the binary. UFW
  forwarding and iptables advice now use that interface, instead of always
  naming `masque0`. The service/installer test asserts the expected UFW command
  for a custom interface using a command spy; real UFW policy interaction still
  needs validation in the intended deployment topology.
- Add packet/capsule fuzzers, an opt-in isolated Linux network lifecycle test,
  and offline MASQUE + Cloudflare configuration provisioning. Native amd64 and
  arm64 artifact builds run the source tests and kernel test before publication.
  Their source ref follows the selected workflow ref instead of an old hardcoded
  commit; the artifact records its source commit and module versions.

## Local validation

- Go 1.26.8; race-enabled full suite with statement coverage: 167 tests/subtests
  passed and four privileged checks skipped locally. Root package coverage is
  88.7%; IP, protocol, authentication, pool, and route packages exceed 92%.
- Regression tests for shutdown, changed credentials, installation failure, and
  spoofing; the corrected spoofing test also passed 20 consecutive race runs.
- Three 30-second fuzz campaigns exercised approximately 2.4 million inputs
  without a failure.
- `go vet`, formatting, shell syntax, whitespace checks, and systemd unit
  validation (with the executable path mapped to a local test build).
- `govulncheck`: zero reachable vulnerabilities. One advisory occurs in a required
  module whose affected symbols are not called by this code.
- Offline Cloudflare configuration provisioning succeeds without real API
  credentials or DNS writes.
- The replacement helper was also exercised with real basic and combined Caddy
  binaries: it refused removal of Cloudflare without modifying the destination,
  then validated and installed the combined build with executable permissions.

## Production validation still required

- This workspace has no usable TUN device or privileged network namespace.
  GitHub's native Linux runners execute the new real TUN/firewall/sysctl lifecycle
  test; check those workflow results before installing an artifact.
- The existing original-client end-to-end job requires the `MASQUE_VPN_TOKEN`
  repository secret to read `ArcCal/masque-vpn`. A job that only prints the
  missing-secret notice has not tested the client.
- Live DNS challenge issuance and renewal require a real Cloudflare token with
  Zone Read and DNS Edit permissions for the intended zone. The offline smoke
  test checks module loading and provisioning, not ACME issuance.
- Native artifact builds also exercise the real systemd service's start, reload,
  restart and stop, plus a successful prebuilt install and rollback after a
  simulated startup failure. Inspect their results; local tests alone cover the
  replacement helper, not a service restart. Their local CA and stubbed public-IP
  discovery do not establish public ACME or production DNS behavior.
- Host routes, address collisions, security groups, host firewall interactions,
  TCP/UDP 443 reachability, and client traffic require staging checks with the
  intended deployment topology. No live server was changed during this review.

Keep the previous executable and configuration when deploying. Inspect the
artifact's source commit and checksum, validate the candidate, then verify HTTPS,
HTTP/3, client traffic, reload, restart, and certificate renewal in staging.

## Verified GitHub results — 2026-10-04 (Asia/Shanghai)

The tested source commit is `7d7faa2a23b0eb70e96027c0c74eb6ad76edda04`.

- [CI](https://github.com/ArcCal/caddy-masque/actions/runs/37166031150) passed
  the race-enabled suite, isolated kernel lifecycle test, bounded fuzz campaigns,
  and Linux amd64/arm64 and macOS arm64 builds. The original-client end-to-end
  step was skipped for the missing secret and is excluded from this claim.
- [Vulnerability scan](https://github.com/ArcCal/caddy-masque/actions/runs/37166031139)
  passed. The combined build was also scanned locally with zero reachable
  vulnerabilities.
- Native combined builds passed on
  [Linux amd64](https://github.com/ArcCal/caddy-masque/actions/runs/37166073230) and
  [Linux arm64](https://github.com/ArcCal/caddy-masque/actions/runs/37166074710).
  Each passed real TUN/firewall/forwarding setup, repair and cleanup, offline
  Cloudflare provisioning, real systemd start/reload/restart/stop, successful
  prebuilt installation, and restoration of the working binary after a simulated
  service startup failure.
- All three Linux test runs also passed `TestCaddyRealKernelTraffic`: real UDP
  packets traversed Caddy, TUN, IPv4/IPv6 NAT, and a separate origin namespace,
  and replies returned to the assigned addresses. The origin verified the
  server's WAN source address. HTTP/3, HTTP/2, HTTP/1.1, and an independent
  `connect-ip-go` client each passed both address families without a Rust-client
  secret. The local suite with these new opt-in tests also passed; its normal run
  skips the privileged test and subprocess helper.
- Both downloadable archives were fetched and their SHA-256 checksums verified.
  ELF inspection confirms static x86-64 and aarch64 binaries, and both record
  the tested source commit. The amd64 artifact's three custom modules are
  `masque`, `http.handlers.masque`, and `dns.providers.cloudflare`; the arm64
  artifact passed the same executable module checks on its native runner.
- Builds contain Caddy 2.11.6, Cloudflare provider 0.2.4, and Go 1.26.8. Artifact
  retention is 30 days; rebuilding the workflow creates a fresh download.

These results close the real kernel traffic, NAT, independent-client
interoperability, and systemd rollback testing gaps. Original Rust-client
interoperability, live DNS issuance/renewal, and validation of
the intended host topology remain prerequisites for a production deployment.

## Updated verification — 2026-10-04 (UTC)

Implementation commit: `3d7537ee375953d3ec5d9f1d3be67e4b20b056e7`.
It additionally rejects incompatible interface changes before any second host
network starts, and isolates the blocked-writer tests' Caddy fixtures.

- Local full race run: 172 tests/subtests passed, six skipped, zero failed.
  Three interface/reload regressions passed ten race repetitions; two blocked
  writer regressions passed twenty race repetitions.
- [CI](https://github.com/ArcCal/caddy-masque/actions/runs/37168812585) and
  [source vulnerability scan](https://github.com/ArcCal/caddy-masque/actions/runs/37168812583)
  passed. The original Rust client remains skipped for the missing secret.
- Native combined builds for
  [arm64](https://github.com/ArcCal/caddy-masque/actions/runs/37169055101) and
  [amd64](https://github.com/ArcCal/caddy-masque/actions/runs/37169056521)
  passed source race/vet checks, isolated real TUN/firewall/forwarding lifecycle,
  IPv4/IPv6 NAT and return traffic over HTTP/3, HTTP/2, HTTP/1.1 and the independent
  client, offline Cloudflare provisioning, real systemd lifecycle and installer
  startup rollback. Both downloaded SHA-256 checksums, static ELF architectures
  and recorded source commits were verified. The amd64 executable lists all
  three expected custom modules; arm64 checks them on its native runner.
- Download earlier baseline combined artifacts:
  [Linux arm64](https://github.com/ArcCal/caddy-masque/actions/runs/37169055101/artifacts/11290294711),
  [Linux amd64](https://github.com/ArcCal/caddy-masque/actions/runs/37169056521/artifacts/11289883856).
  Each contains Caddy 2.11.6, Cloudflare provider 0.2.4 and Go 1.26.8; retention is
  30 days. The artifact source is the implementation commit above, rather than
  the later documentation/diagnostic commit.
- Source-mode scans of this repository and the combined program report zero
  reachable vulnerabilities and one required-module advisory, GO-2026-5932.
  A binary-mode scan of the stripped arm64 artifact flags that same advisory
  while falling back to module metadata. See the security audit for its limits;
  the artifact has not been declared free of all vulnerability advisories.

The [security and IETF audit](security-ietf-audit-2026-10-04.md) records the confirmed HTTP/2 error-code gap, conntrack and remaining capacity
risks, and the unverified TTL delegation boundary. URI validation and basic
authentication/session/queue budgets were subsequently fixed below; successful
builds do not close the remaining gates. This revision is a tested candidate, not a strict
IETF or large-production sign-off.


## Resource budgets and real-client follow-up — 2026-10-04

Implementation: `d414d2a07eb5e9d305fbf7d82fc46efe8302dd18`.

- Reject template variables in fragments and invalid URI schemes; preserve fixed
  fragments outside the HTTP request target and encoded `%23` path literals.
- Add aggregate Argon2 memory reservations (default 128 MiB), quota-aware CPU
  admission and a five-second admission deadline. Configured hashes must fit;
  cancelled requests retain hashing resources until computation finishes.
- Add global session admission (default 1024) and queued-payload memory (default
  64 MiB), O(1) per-user limit checks and idempotent lease cleanup. Pending/revoked
  sessions count until cleanup; enqueue/cleanup races cannot leak reservations.
  These budgets exclude transport state, GC and in-flight writes, and are not RSS
  or bandwidth-fairness guarantees. Default IPv4 pool capacity is still about 253.
- Preserve dotted TUN/WAN names in sysctl paths and test PMTU/RA settings and
  restoration in the opt-in lifecycle test. Reject unusable gateway/pool settings
  and invalid Linux interface names during provisioning.
- Count full-queue/global-payload-budget drops. Give the privileged e2e script
  unique namespaces and temporary host interfaces, refuse existing topology and
  clean up only created namespaces. A command spy confirms refusal before any
  network mutation; the whole Rust kernel script remains unexecuted here.
- Build unmodified companion commit `ba82e36164a69c01a2a366153550aee2821c41b7`
  with Cargo.lock and Rust 1.99.0: 200 workspace tests pass. Real CLI SOCKS UDP
  exchange passes HTTP/3, HTTP/2 and HTTP/1.1 with IPv6 both enabled and disabled,
  including continued traffic beyond the H3 MTU-probe deadline. The server uses
  a fake TUN; macOS GUI, client TUN/gateway and real combined-Artifact compatibility
  remain separate gates. The fixture uses a proper CA/leaf certificate chain and
  keeps rustls certificate validation enabled.
- Local Go 1.26.8 full race suite with the real client enabled: 204 tests/subtests
  pass, six skips, zero failures. Resource/queue and authentication/cancellation
  cases each pass ten repeated race runs. `go vet`, module verification, format,
  shell syntax and whitespace checks pass.
- The new [source vulnerability workflow](https://github.com/ArcCal/caddy-masque/actions/runs/37173506345)
  passes. The known required-module advisory/scanner limitations remain documented.

See [current audit](security-ietf-audit-2026-10-04.md), [client version/matrix](client-compatibility.md)
and [follow-up diagnostic output](audit-followup-output-2026-10-04.txt).
S1 HTTP/2 stream errors are still reproduced; conntrack scaling, complete TTL
semantics, live DNS renewal and intended-platform/load validation remain open.
The PR remains draft and has not been merged or deployed to production.


Latest implementation CI: [37173506367](https://github.com/ArcCal/caddy-masque/actions/runs/37173506367)
passes source/race/vet, both isolated kernel checks and three 20-second parser
fuzz campaigns. Its private Rust-client job still skips; local original-client
results above are independent evidence.

Native [Linux arm64 combined build](https://github.com/ArcCal/caddy-masque/actions/runs/37173519441)
passes source checks, the dotted-interface sysctl/RA lifecycle, actual IPv4/IPv6
TUN/NAT return traffic, all three HTTP transports and independent client, offline
Cloudflare provisioning, and the candidate executable's systemd/install rollback.
[Download Artifact](https://github.com/ArcCal/caddy-masque/actions/runs/37173519441/artifacts/11292746630).
Its static aarch64 architecture and full source commit were verified after download;
archive SHA-256: `4917e1aba08669e703d242537cfb3debf463aa3cb74b9a07ef544edcb2fb3a13`.
Caddy 2.11.6, Cloudflare provider 0.2.4, Go 1.26.8; 30-day retention. Kernel wire
checks run the source test binary; combined executable service/provisioning checks
do not establish a full original-client/combined-Artifact data path.


Native [Linux amd64 combined build](https://github.com/ArcCal/caddy-masque/actions/runs/37173520546)
passes the same checks. [Download Artifact](https://github.com/ArcCal/caddy-masque/actions/runs/37173520546/artifacts/11292397751).
Its SHA-256 (`980b5127b91383b02560790876784361da242aca027d2f756eba1a3277019d85`), static x86-64 architecture,
source commit and module registration were independently verified after download.
Both candidates contain the same pinned Caddy/Cloudflare/Go versions and source.
