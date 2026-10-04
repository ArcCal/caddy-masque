# Production readiness review — 2026-10-03

The review found defects in credential isolation, shutdown ordering, URI matching
performance, and deployment tooling. This branch fixes those defects and adds
repeatable regression and kernel lifecycle checks. Passing these checks does not
establish that an arbitrary production host, Cloudflare token, or client will work.

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
