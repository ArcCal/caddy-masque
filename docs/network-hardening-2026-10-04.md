# Network lifecycle and kernel validation — 2026-10-04

Candidate source: `2455ab70af40af6c8f364bc270265e97de27a3d6`.
Network implementation: `e649126e66d07016e4eac0716367cb1006af489b`.
The candidate additionally preserves the systemd runtime directory and tests
its identity across restart/stop. Dates refer to Asia/Shanghai.

This round follows the same three requirements: IETF semantics, security and
reliability at scale, and compatibility with the actual ArcCal/masque-vpn client.
It does not approve production deployment. The unresolved findings in the
[security audit](security-ietf-audit-2026-10-04.md) remain release prerequisites.

## Changes

- Acquire a namespace-specific process lock before creating the TUN or modifying
  forwarding/firewall state. Reject unsafe directory/file ownership, writable
  paths, symlinks and hard links. Keep ownership until cleanup completes; a
  process crash releases it automatically.
- Keep lock inodes stable. Never unlink a lock during normal cleanup, and set
  `RuntimeDirectoryPreserve=yes`: otherwise a systemd stop could delete a file
  already locked by a successor and allow a third process to lock a new inode.
- Check nftables chain policies, hooks, priorities, ordered rules and expressions
  against the JSON read back after installation. Ignore only handles/metainfo.
  Restore partial flushes and additional rules, not just a missing table. An
  inspection error does not prove absence; successful table enumeration is
  required before treating a failed inspection as deletion.
- Bound individual network commands to five seconds and 64 KiB of captured
  output, including stderr. Limit pipe waiting after a child exits. The output
  regression caught a draft implementation that embedded `bytes.Buffer` and
  exposed `ReadFrom`, bypassing `Write`; the committed implementation keeps the
  buffer private and passes the subprocess overflow check.
- Make shutdown idempotent, aggregate cleanup errors and report them to Caddy.
  Read a sysctl before changing it, and restore its earlier value only when the
  observed current value still matches this process's installed value. Account
  for a firewall transaction that might have committed before a timeout lost
  its acknowledgement. The service allows 45 seconds for repair/cleanup.
- Extend isolated real-kernel traffic tests with IPv4 TTL/IPv6 Hop Limit 1, 64,
  255, ICMP Time Exceeded and local Echo destinations. Keep the wire protocol and
  packet adaptation unchanged; Linux continues to perform IP routing.

## Local evidence

- Full race suite with the actual Rust CLI: **225 tests/subtests passed, eight
  skipped, zero failed**. Skips are privileged/tool-dependent cases and opt-in
  subprocess helper entry points; packages without tests are not counted as
  covered. Linux kernel execution is recorded separately below.
- Host-network unit/fault tests passed **three race repetitions** after the
  final Go changes. They cover cross-process contention, crash recovery, unsafe
  paths, concurrent close, sysctl restoration, command deadlines/output bounds,
  rule fingerprint changes and read-only behavior on failed inspection.
- Real client commit `ba82e36164a69c01a2a366153550aee2821c41b7`, Rust 1.99.0:
  all six HTTP/3, HTTP/2 and HTTP/1.1 × IPv6 on/off CLI combinations passed. The
  H3/IPv6-off case remained usable after the ten-second MTU probe deadline.
  This is SOCKS UDP with simulated server TUN/origin, not macOS/TUN/gateway or
  actual combined-artifact interoperability. The earlier 200 Rust workspace
  tests were not rerun for these server-only changes.
- `go mod verify`, `go vet`, gofmt, whitespace and shell syntax checks passed;
  macOS arm64 cross-build succeeded. No live host or DNS record was changed.
- The HTTP/2 frame diagnostic still observed `NO_ERROR` for malformed ipproto
  and `INTERNAL_ERROR` for a malformed Capsule. RFC 9113 requires
  `PROTOCOL_ERROR`; the diagnostic's PASS only means measurement completed.

## Real Linux kernel evidence

[CI on the network implementation](https://github.com/ArcCal/caddy-masque/actions/runs/37176808547)
passed real TUN/sysctl/firewall setup, restoration and cleanup, cross-process
exclusion before TUN creation, an independently usable network namespace, and
repair after each input/forward/postrouting chain was emptied or an extra rule
inserted. Healthy and repaired rule snapshots remained stable.

The UDP origin runs in a separate namespace and reports the source IP and the
TTL/Hop Limit received through socket ancillary data. Both address families
passed these assertions over HTTP/3, HTTP/2 and HTTP/1.1:

| Traffic | Observed result |
| --- | --- |
| Client starts at 64 | Origin receives 63, with server WAN source after NAT |
| Client starts at 255 | Origin receives 254, without wraparound |
| Origin explicitly replies at 64 | Client receives 63 and the assigned destination |
| Client starts at 1 toward origin | ICMP Time Exceeded, correct quoted source/destination |
| Client starts at 1 toward local gateway | Echo Reply, locally generated reply remains 64 |

The independent `connect-ip-go` client also passed IPv4/IPv6 NAT and return
traffic. It decrements the outgoing packet before sending it; its origin therefore
receives 62/253. The test explicitly accounts for this additional client hop,
rather than interpreting it as an extra server decrement. These measurements
validate the tested Linux external-router boundary under RFC 9484 §7.2; they
do not certify every RFC requirement or another external routing implementation.

## Deployment boundaries and remaining gates

- Managers sharing a network namespace must share `/run/caddy-masque`, including
  containers with separate mount namespaces. Different runtime directories do
  not coordinate. Keep the reserved `inet caddy-masque` table under this manager's
  ownership; locks do not arbitrate unrelated firewall programs or old versions
  that do not participate.
- The 30-second watcher has a repair window after an external firewall flush.
  Compare-before-restore sysctls is best effort, not an atomic transaction with
  administrators. Linux forwarding has system-wide side effects; real UFW,
  Docker, firewalld, VPC/LAN routes and namespace topology still need staging.
  A crash releases the lock/TUN descriptors but cannot run cleanup or restore
  original sysctl values held only in memory; the next start replaces stale
  reserved rules, without a durable record of pre-crash forwarding values.
  Crash-state recovery needs explicit testing and a defined ownership policy.
- HTTP/2 explicit stream error support remains the strict IETF blocker. Fixing
  only the development executable or using private-field reflection would not
  meet the requirement for consistent ordinary/xcaddy/combined builds.
- Conntrack deletion still reads the complete address-family table. Keep failure
  isolation and measure/fix the large-table path before promising large-scale
  reconnect capacity. Real constrained RSS, CPU, fairness, p95/p99 and soak tests
  remain prerequisites despite the existing admission and queue budgets.
- Cloudflare 0.2.4 can interpolate an invalid token in a provisioning error.
  Upstream remediation and live DNS challenge issuance/renewal remain outstanding.
- Real macOS application, Rust TUN/gateway, low-MTU/failure paths and actual
  combined Artifact interoperability remain outstanding. The GitHub private
  client job still skips without `MASQUE_VPN_TOKEN`; green CI does not cover it.

## Final candidate and downloads

For `2455ab70af40af6c8f364bc270265e97de27a3d6`, [CI](https://github.com/ArcCal/caddy-masque/actions/runs/37176965685)
and [source vulnerability scan](https://github.com/ArcCal/caddy-masque/actions/runs/37176965624)
passed. CI ran the real kernel checks and three 20-second parser fuzz campaigns;
its private Rust-client job skipped for the missing secret. Source scanning
reported zero reachable vulnerabilities and one required-module advisory; this
does not establish that every dependency is safe.

Native combined builds for [arm64](https://github.com/ArcCal/caddy-masque/actions/runs/37176981769)
and [amd64](https://github.com/ArcCal/caddy-masque/actions/runs/37176982669) both
passed source race/vet checks, real kernel lifecycle/TTL/ICMP checks, offline
Cloudflare provisioning and the actual candidate binary's service/installer
checks. The latter verified `RuntimeDirectoryPreserve=yes`, stable runtime
directory identity through restart and stop, normal service reload, restored
forwarding/TUN/rules, and rollback after a simulated startup failure. Kernel
traffic runs the source test executable; it does not run the actual combined
Artifact against the Rust client.

Both downloaded archives passed SHA-256 verification, static ELF architecture
checks and recorded-source checks. Versions are Caddy **2.11.6**, Cloudflare
**0.2.4** (pinned commit `a8737d095ad5a48ca031cea6ab704057dbc2d250`) and Go
**1.26.8**. The amd64 executable additionally passed local version/module and
offline DNS provisioning checks; arm64 executes these checks on its native runner.

| Architecture | Download Artifact | Archive SHA-256 |
| --- | --- | --- |
| Linux arm64 | [11293153543](https://github.com/ArcCal/caddy-masque/actions/runs/37176981769/artifacts/11293153543) | `30a64f391df6203b4e39c3cf6424e64127317b336fae074adacc7adb516d6bd0` |
| Linux amd64 | [11293379328](https://github.com/ArcCal/caddy-masque/actions/runs/37176982669/artifacts/11293379328) | `26fa4596066c0fbde47b96ea0bdcb332d95d45038154e50574c6ab11dcc6a755` |

Artifacts are retained for 30 days. [Measured output](network-hardening-output-2026-10-04.txt)
records the local results, frame diagnostic, kernel measurements, scan and
candidate checks. PR #21 remains draft; the unresolved gates above prevent a
strict IETF/large-production sign-off.
