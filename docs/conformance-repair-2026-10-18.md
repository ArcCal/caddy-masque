# Standards audit remediation and compatibility evaluation

Date: 18 October 2026. Baseline: `94eae65ba1cf23a9122d1abd9d38594f9bcf4f4e`.
The repaired source is the commit containing this report. Local measurements
below refer to that source before commit, with its dirty-tree build metadata.

## Acceptance policy and scope

Mandatory IETF behavior takes precedence over camouflage and other design
goals. Compatibility is evaluated against the unchanged ArcCal/masque-vpn
checkout at `886a4cc71edee0b52991ea4c95df9e1ab406c58a`. No changes were made
to that repository. The server keeps HTTP/3 Datagrams, HTTP/2, HTTP/1.1 Upgrade
and HTTP/3 DATAGRAM Capsules, existing password hashes and client configuration.

The baseline audit reviewed first-party documentation, implementation, tests,
deployment scripts and workflows; the complete HTTP/3 source; and the relevant
HTTP/2, HPACK and QUIC transport paths. Entire dependency trees were also
compared with checksum-verified upstream sources and recorded patches. This
does not constitute a line-by-line audit of every unrelated x/net package,
Caddy, transitive dependencies or the Go standard library.

The baseline was functional but contained confirmed receiver-validation,
error-scope and transport-budget defects. Its claim that arbitrary refusals
look exactly like successful website responses conflicted with CONNECT
semantics. The repairs below address the reproduced defects while retaining
the existing architecture. They do not establish formal IETF certification or
prove that no undiscovered defect exists.

## Findings and resulting behavior

The F-numbers identify the findings in the baseline audit. Tests preserve valid
controls as well as rejecting invalid inputs; a blanket connection refusal is
not considered a successful repair.

| Finding | Baseline behavior | Repaired behavior and normative basis |
| --- | --- | --- |
| F01: refused CONNECT and malformed Upgrade | A website's 2xx response could announce a successful tunnel; malformed anonymous Upgrade requests reached the site. | Refused HTTP/2 and HTTP/3 CONNECT-IP responses retain website bodies but convert final 2xx to 404. Existing error/redirect statuses remain. Caddy error routes cannot bypass this guard. Recognized malformed upgrades/content headers are checked before authentication. RFC 9484 §§4.2, 4.5; RFC 9297 §3.2. |
| F02: QUIC amplification | Admission checked whether the budget was already exhausted, then could send a whole packet beyond the remaining allowance. | Actual remaining bytes constrain normal, coalesced, ACK-only, PTO and close datagrams. Padding counts. No undersized Initial is emitted to consume a small remainder. Unvalidated close packets are not retained by a retransmitter without budget accounting. RFC 9000 §8.1. |
| F03: HTTP/3 SETTINGS | Reserved HTTP/2 identifiers were ignored; invalid H3_DATAGRAM values used the wrong error. | Identifiers 0x2–0x5 and invalid setting values produce H3_SETTINGS_ERROR (0x109). Duplicate settings and invalid ENABLE_CONNECT_PROTOCOL values are also covered. Unknown/GREASE settings remain accepted. RFC 9114 §7.2.4.1; RFC 9297 §2.1.1. |
| F04: QPACK critical streams | Peer encoder/decoder streams were abandoned after their type was read. | Their lifetime and instructions are monitored. Critical-stream closure uses H3_CLOSED_CRITICAL_STREAM (0x104). Static-only/zero-capacity limits are enforced with the appropriate QPACK encoder/decoder stream errors. Valid idle critical streams remain open. RFC 9204 §§3, 4.3, 5. |
| F05: QPACK decompression scope | A decompression error reset one stream, allowing the connection to continue. | Request, response and trailer decompression failure closes the connection with QPACK_DECOMPRESSION_FAILED (0x200). Ordinary malformed HTTP fields retain stream scope. RFC 9204 §4.5. |
| F06: HTTP/3 message and frame validation | Missing scheme, erased empty Content-Length, body underflow, clean frame truncation and invalid frame ordering could be accepted. | Required control data and declared lengths are checked. Incomplete frame payloads produce H3_FRAME_ERROR (0x106); prohibited known frames produce H3_FRAME_UNEXPECTED (0x105); malformed messages use H3_MESSAGE_ERROR (0x10e). Trailer syntax, ordering and payload decoding are enforced without treating a read timeout as malformed content. RFC 9114 §§4.1, 4.3, 7, 8. |
| F07: HTTP/2 malformed messages | Incomplete extended-CONNECT pseudo-headers could reach the tunnel; some detected invalid fields returned an ordinary 400 without the required reset. | Required scheme/authority, protocol/method context, forbidden connection fields, TE lists and leading/trailing field whitespace are validated. Malformed messages reset the affected stream with PROTOCOL_ERROR (0x1); another stream remains usable. Undeclared trailers are covered. The asterisk target is restricted to OPTIONS. RFC 9113 §§8.1.1, 8.2.1, 8.3; RFC 8441 §4. |
| F08: explicit address requests | An unfulfilled explicit address/prefix request was answered using its request ID but a different assigned address. | An exact existing host assignment or an unspecified preference can be granted. Otherwise the request ID receives the all-zero rejection and the actual assignment is separately advertised with ID zero. RFC 9484 §4.7.2. |
| F09: optional URI-template scope | Omitted form-query variables were treated like malformed values. | Legitimately absent optional target/ipproto variables use wildcard scope. Present empty or invalidly encoded values remain distinguishable and fail validation. Refusal before variable extraction remains permitted. RFC 9484 §§4.1, 4.6. |
| F10: link-local isolation | Pool/gateway additions could reinsert link-local space after policy exclusion. | Overlapping link-local pools are rejected; exclusions follow route additions; unicast link-local source/destination traffic is dropped in both forwarding directions. RFC 9484 §7.2. |
| F11: IPv4 checksum | A corrupt header could elicit a local ICMP error before the kernel saw it. | Header checksums are validated before local ICMP or forwarding. Invalid packets are silently discarded, and a following valid packet still works. RFC 1812 §§4.2.2.5, 4.3.2.7. |
| F12: HTTP/3 takeover configuration | Reloaded header limits and the configured HTTP idle lifetime were not applied faithfully. | Each new connection snapshots the current header limit and HTTP idle timeout. The same header limit supplies advertised SETTINGS and enforcement. Existing connection settings and active tunnel lifetime are preserved. |
| F13: current-client wrapper gate | A stale lockfile prevented the official command from running; generated workspaces omitted the clients' H3 patches. | The server-owned harness lock matches current Mac/Killswitch package versions. Its workspace selects the clients' existing vendored h3/h3-quinn sources and verifies selected manifests with locked Cargo metadata. No client source or client lockfile changes. |
| F14: packaged artifact identity | Release packaging rebuilt a different executable after kernel/wire validation. | Validation hashes the final optimized executable, rechecks it after testing, and uploads it for packaging. Standard and manual Cloudflare jobs verify that checksum and package those exact bytes. Architecture, source revision and module checks remain. |
| F15: peer UDP receive size | A valid smaller max_udp_payload_size could leave a larger effective packet minimum. | The peer limit clamps packet size, PMTU initialization/reset and sender/pacer state. Migration retains this constraint. RFC 9000 §§14, 18.2. |
| F16: DATAGRAM capacity | An accepted boundary payload could exceed the actual packet packer's capacity. | The estimate reserves maximum CID, packet-number, encryption and DATAGRAM framing overhead. Sixteen CID/packet-number combinations verify that advertised boundary payloads pack successfully. HTTP Datagram startup sizing also reserves the full quarter-stream-ID width. RFC 9221 §5. |
| F17: unnegotiated QUIC DATAGRAM | The receiver used FRAME_ENCODING_ERROR. | Both DATAGRAM frame types produce PROTOCOL_VIOLATION (0xa) when support was not advertised. Malformed negotiated frames retain their proper handling. RFC 9221 §3. |
| F18: congestion credit | An ordinary admitted packet could cross the remaining congestion-window byte limit. | Ordinary sends reserve a full packet of credit; PMTU probes require credit for their actual larger size before marking discovery state in flight. PTO retains its protocol-defined exception. RFC 9002 §7. |

Additional practical repairs:

* **Failed reloads preserve live sessions.** Shared authentication, routes,
  quotas and MTU-probe policy are staged while the candidate starts. Caddy's
  active-context swap precedes the old app's Stop call, which commits the new
  policy. Failed candidates leave the previous policy intact. Both busy UDP
  startup failure and repeated busy TCP failure preserve pre-existing tunnels;
  successful removal/route withdrawal still takes effect after commit.
* **Large-pool history is bounded.** Exact returned-address history has a
  65,536-entry bound. Once exceeded, subsequent allocations conservatively
  require conntrack cleanup instead of assuming forgotten addresses are fresh.
  Small/default pools keep their existing allocation policy. This trades extra
  cleanup work for bounded retained history without weakening isolation.
* **Successful CONNECT HTTP semantics are retained.** Tunnel DATA is allowed
  for every successful 2xx, including 204. Content-Length is ignored by the
  client even when empty, invalid or contradictory, as RFC 9110 §9.3.6 requires.
  Ordinary and refused responses remain strict. Successful tunnels do not
  emit HTTP trailers or acquire an implicit Content-Type through sniffing.
  HEAD and 304 retain their ordinary Content-Length exceptions.
* **Timing claims are qualified.** Unknown names incur default-cost password
  verification. Custom PHC parameters can have different costs; the code no
  longer claims unconditional username timing equivalence. Existing accepted
  hashes remain compatible.

## Design goals and mandatory Cloudflare builds

The introduction and design document now state the standards-first priority
and the status-code limit on response camouflage. A conforming refusal cannot
promise an arbitrary website's successful status. Ordinary website routing,
bodies, trailers, TLS and reverse proxies remain part of the regression scope.

`github.com/caddy-dns/cloudflare v0.2.4` is a direct, checksum-pinned dependency
(reviewed upstream commit `a8737d095ad5a48ca031cea6ab704057dbc2d250`). The MASQUE
package registers it, so importing MASQUE in a custom main also registers
`dns.providers.cloudflare`; this does not depend on remembering another blank
import in a build script. The default command, installer, documented xcaddy
command and both artifact workflows include it. Module checks are mandatory.
Credentials are needed only when deploying Cloudflare DNS challenges.

Both protocol forks retain their pinned upstream versions. New conformance
changes and tests are recorded as separate patches. Verification applies them
without offsets/fuzz and compares the complete shipped trees. No whole-library
upgrade or unrelated dependency refresh was used to repair these defects.

## Validation method and results

Tests run on Linux amd64 with official checksum-verified Go 1.26.9 and 1.27.2,
Rust 1.99.0, Caddy v2.11.7, x/net v0.60.0 and quic-go v0.63.0. TLS certificate
verification, module checksums and frozen Cargo locks remain enabled.

The in-process suites use real TLS/TCP/QUIC listeners with a channel-backed
server TUN. Raw HTTP/2 tests write HPACK/HEADERS directly; raw HTTP/3 tests
write HTTP/3 and QPACK bytes directly rather than depending on a high-level
client to permit malformed inputs. QUIC tests measure actual UDP output as
well as exercising production packet accounting and packing.

Counts below distinguish top-level tests from events including subtests.
Exact local logs are retained under `/workspace/fix-validation`.

| Check | Final result |
| --- | --- |
| Main module, `go test -mod=readonly -race -count=1 -json ./...`, both Go versions | Each: 174 passing top-level tests / 307 passing events, zero failures. All four real masque-client modes pass. Four test skips are identified below. |
| Official current Mac/Killswitch runner, `--release`, both Go versions | Each: all 16 distinct cases pass under Go race checking; zero failures/skips. Matrix: 2 apps × 2 IP configurations × 4 transports. |
| Full HTTP/2, HPACK and httpcommon race suites, both Go versions | Each: 516 passing top-level tests / 780 passing events; zero failures; two existing skips below. |
| Full HTTP/3 and qlog race suites, both Go versions | Each: 167 passing top-level tests / 490 passing events; zero failures/skips. |
| Four affected QUIC transport unit packages, both Go versions | Normal and race runs pass. Go 1.27 ledger: 703 top-level / 1,379 total passes normally; 702 / 1,376 with race. Two socket-buffer skips and the separate allocation instrumentation exception are identified below. |
| Real UDP QUIC integrations, Go 1.26 | Ten top-level tests pass, covering DATAGRAM negotiation/sizes/loss, long certificates, handshake loss, migration, Initial sizing, PMTU and close. |
| Independent QUIC amplification wire measurement | One 1,200-byte received Initial permits exactly 3,600 sent bytes: `[1397, 1397, 806]`. No extra budget-consuming transmission. |
| Independent HTTP/2 Caddy frame replay | All 11 subcases pass, including valid controls, exact malformed-message errors and anonymous malformed HTTP/1.1 Upgrade. |
| Independent raw HTTP/3 replay | All 20 leaf cases pass under race, including the valid GET control. |
| Actual Caddy HTTP/3 audit replay | Ten cases pass: eight required rejection/scope cases and two valid controls. One observation helper needed a harness-only correction, explained below. |
| HTTP/2 security regression gate, both Go versions | Each: all 31 required test/subtest events pass; zero failures/skips. |
| Capsule segmentation fuzzing | 30-second requested run, two workers, 103,683 executions and 11 new coverage-interesting inputs; pass. No throughput interpretation is attached to fuzzing speed. |
| Fork reconstruction and module verification | Both complete forks match their checksummed upstreams plus documented patches exactly; module verification passes on both Go versions. |
| Static analysis and advisory checks | `go vet ./...` passes on both Go versions. Source govulncheck v1.8.0 reports zero affected and zero imported-package vulnerabilities on both; selected transport-version query reports zero advisories. Required-module caveat below. |
| Builds and Cloudflare | Optimized default builds pass on both Go versions; all three required modules register. A separate custom main importing MASQUE without an explicit Cloudflare import also registers all three. |
| README wildcard/Cloudflare example | Both default binaries pass `caddy validate`, replacing the documented hash/token/path placeholders with a known test hash and a syntactically valid non-secret dummy token. No DNS update or issuance is attempted. |
| Workflow and installer checks | All three workflows pass actionlint v1.7.12; workflow shell blocks and installer pass shell syntax checks. The saved development installation script is replayed successfully. |

The wrapper matrix exercises settings, DNS, authentication isolation,
concurrent VPN/SOCKS operation, 512 full-MTU bidirectional packets per case,
IPv4 host-state behavior, probe stability and cancellation. It selects the
actual current clients' transport patches with `cargo metadata --locked`.

The main-suite skips are the three `TestRuleset` privileged subcases and the
ordinary parent invocation of `TestSeriousLifecycleExitHelper`. Its process
lifecycle tests execute the helper in their intended subprocess context.
Packages reported as having no tests are not counted as executed tests.
HTTP/2 skips are `TestTransportExternal` and `TestSlowIncrementalDecode`.
QUIC skips are `TestForcingReceiveBufferSize` and `TestForcingSendBufferSize`.

The baseline `TestFrameParserAllocs/STREAM` fails its zero-allocation assertion
under race instrumentation. An overlay with the original parser reproduces
the failure; the ordinary complete suite includes and passes that assertion.
The final QUIC race command excludes only the allocation-count test with
`-skip '^TestFrameParserAllocs$'`. Functional parser and conformance assertions
remain enabled. This is an explicit coverage qualification, not a race failure
silently reclassified as a pass.

The original Caddy QPACK scope observation test received the correct remote
connection error 0x200, then fatally tried to open another stream before its
expected-closure assertion. Its original nonzero log is preserved. A separate
copy corrects only that helper: it requires both error 0x200 and inability to
open another stream. The corrected primary suite passes 6/6; the unchanged
extra suite passes 4/4. The exact helper diff and both logs are retained in
`http3/CADDY-AUDIT-REPLAY.md` and accompanying files. No protocol assertion was
weakened to accept a successful malformed request.

Source scans also identify required-module advisory
[GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932), concerning the unmaintained
`golang.org/x/crypto/openpgp` package in x/crypto v0.57.0. That package is
outside imported packages and called code; the advisory lists no fixed
version. This is distinct from the zero reachable/imported-package findings.
Local transport replacements additionally receive explicit upstream-version
advisory queries because a source scan alone can obscure their version.

Local Linux amd64 executable SHA-256 values (`-trimpath -ldflags '-s -w'`):

| Toolchain | SHA-256 |
| --- | --- |
| Go 1.26.9 | `13980b87e781f6cd39d3689d21ff094d1305c5cb003abb2fdc66e66029e37dc9` |
| Go 1.27.2 | `bf7e35ebfb19fe471aae440a85f553c7a9b99e68ad50d0cbc506140d89654cc1` |

These are development working-tree artifacts, not published release hashes.
CI builds after commit must acquire their own checksums and pass its strict
kernel/wire gates before packaging. The custom-main helper outside a Git
checkout uses `-buildvcs=false`; release builds retain revision stamping.

Representative reproduction commands, after activating the toolchain and
using writable XDG/cache directories:

```sh
go mod verify
python3 tests/verify-http2-fork.py
python3 tests/verify-http3-fork.py
go vet ./...
MASQUE_CLIENT=/path/to/unchanged/masque-client go test -mod=readonly -race -count=1 ./...
python3 tests/run-client-wrapper-interop.py --masque-vpn-root /path/to/masque-vpn --release
go -C third_party/xnet test -race ./http2 ./http2/hpack ./internal/httpcommon
go -C third_party/quic-go test -race ./http3/...
go -C third_party/quic-go test . ./internal/ackhandler ./internal/congestion ./internal/wire
go -C third_party/quic-go test -race -skip '^TestFrameParserAllocs$' . ./internal/ackhandler ./internal/congestion ./internal/wire
python3 tests/test-http2-security.py
python3 tests/check-transport-vulnerabilities.py
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
go test ./internal/proto -run '^$' -fuzz '^FuzzCapsuleStream$' -fuzztime=30s -parallel=2
go build -mod=readonly -trimpath -ldflags '-s -w' -o /tmp/caddy ./cmd/caddy
/tmp/caddy list-modules
```

## Limitations and remaining deployment validation

This environment has no root/sudo, CAP_NET_ADMIN or `/dev/net/tun`. It cannot
validate real kernel forwarding, nftables installation, network namespaces or
a production systemd deployment. The strict kernel and wire CI gates remain
required; they were not disabled or relabeled as locally passed.

Native macOS utun, PF, route/DNS restoration, GUI lifecycle and sleep/wake were
not run. The Mac/Killswitch matrix evaluates their real protocol cores with
packet channels, not native host integration. Native arm64 execution and
physical-path throughput/loss benchmarks were not performed here. Cross-builds
or prior historical results would not substitute for those checks.

Cloudflare module registration and configuration validation do not prove live
DNS updates or ACME issuance with an operator's credentials. No deployment
credential is required for this development workflow.

The takeover's documented packet-connection-wrapper, 0-RTT and Alt-Svc scope
limitations remain. Raw target encoding strictness was not promoted from an
ambiguous receiver-obligation observation into a breaking compatibility change.
Congestion admission can leave less than one packet of unused credit until an
ACK/PTO; this is a deliberate conservative choice, not a throughput claim.
