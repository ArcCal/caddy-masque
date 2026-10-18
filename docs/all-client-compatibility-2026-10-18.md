# All-client interoperability and standards follow-up

Date: 18 October 2026. Server baseline: `b454ebb67155ca64f4f05861b4a5e1fe2729b0e8`.
Client source: ArcCal/masque-vpn
`e10a6ec9fcf0e005d36572830539802df36f6638`, the remote HEAD observed for this
follow-up. The original client checkout at `886a4cc` and the new dependency
checkout both remain unchanged. All fixes, new harnesses and lockfile changes
are in caddy-masque or external development/evidence directories.

This report extends the [standards repair report](conformance-repair-2026-10-18.md)
with the complete current client inventory, additional server defects and
client-side conformance findings. Earlier HTTP/2, QUIC, reload, build and
Cloudflare changes remain in the baseline; they are not attributed to this
follow-up.

The later [standalone client IETF audit](client-ietf-conformance-2026-10-18.md)
provides detailed evidence and refined attribution, including the actual WARP
egress path, the interpretive duplicate-status subcase, and precise ABI-versus-wire
limits. Its client-specific scope distinctions supplement this overview.

## Acceptance and complete client inventory

Mandatory IETF behavior takes precedence. The goal is interoperability with
every current client, including independent implementations and practical
startup, cancellation, reload and packet-delivery behavior. Passing a protocol
core on Linux does not establish native macOS acceptance or prove the absence
of every possible defect. This report identifies those boundaries explicitly.

| Client or artifact | Actual transport implementation | Acceptance coverage |
| --- | --- | --- |
| `masque-client`, Linux system/SOCKS/LAN gateway and macOS CLI | Shared Rust `masque_vpn::client::Client`; vendored h3/h3-quinn, h2 and Hyper | Real unchanged CLI subprocesses against Caddy over all four transport modes; IPv4/IPv6, MTU probes, idle survival and cleanup. Privileged Linux system/gateway checks remain a separate required gate. |
| IETF Masque GUI | Swift settings/process controller launches the same `masque-client` | Source review of configuration and process construction; real CLI `--config -` with configuration plus NUL, held stdin and EOF shutdown, including healthy Auto. The Swift GUI runtime itself is not executed on Linux. |
| `masque-vpn-mac` | Native host/counting adapters around shared Rust Client | Existing public settings, packet and counted SOCKS APIs; simultaneous sessions, full-MTU packets, authentication isolation, probes and cancellation. Native utun/routes/DNS restoration remains separate. |
| `masque-vpn-killswitch` | Shared Rust Client with native routing/PF and lifecycle adapters | Same portable matrix plus unchanged source delegation review. Native PF protection and failure recovery remain separate. |
| Masque NF | Independent production Rust HTTP/CONNECT-IP/SOCKS core; Apple Network.framework supplies native socket/TLS/QUIC I/O | New real-Caddy matrix uses that unchanged production core and the client's existing portable test bridge. Covers both families, TCP/UDP/DNS, small Datagram capacities, legal stream 4 behind idle stream 0, authentication and cancellation. It is not a Network.framework runtime test. |
| CF gateway's embedded `masque-frontend::client::Client` | Separate generic client fixture, with its own local h3/h3-quinn/h3-datagram forks | New independent locked workspace and eight-case real-Caddy matrix, including certificate negatives, full-MTU traffic, probe survival and actual credential-revocation/reconnect. |

The current repository's macOS build driver builds four apps: IETF Masque,
Mac, Killswitch and NF. The standalone Swift transport was removed; treating
it as another current implementation, or excluding NF because it is native,
would misstate the inventory.

The CF-MASQUE project itself is an experimental Linux **gateway server**, not
a desktop client. Its generic embedded client is tested here because it is a
distinct implementation present in the repository. Its production WARP egress
uses Cloudflare enrollment, device authentication, endpoint pinning and a
service-specific `cf-connect-ip` dialect. That is not a standard Basic-auth
CONNECT-IP client for arbitrary Caddy endpoints. This service-contract
difference is not, by itself, evidence of violating an IETF requirement.

Source review does identify concrete departures in the production WARP
profile (`rfc: false`): private H2 bare-IP Capsules omit the standard Context
ID, absent H2 TLS ALPN is accepted, and H3 sends `:protocol` without requiring
peer Extended CONNECT permission. These differ from standard CONNECT-IP payloads (RFC 9484 §§5–6, carried by
RFC 9297 §3.5), RFC 9113 §3.3 and RFC 8441/RFC 9220 respectively.
RFC 9297 §3.5 alone leaves payload semantics to the extension; a private bare-IP
payload is a protocol-format difference, not by itself a generic Capsule violation. They are a documented private
dialect, not proof of standard Caddy interoperability. No live Cloudflare
session was run and no endpoint emulation or enrollment was added.

The design assessment has two distinct results. The exercised portable
protocol paths preserve the shared website/VPN listener, existing client
configuration, authentication, address exchange, all four carriers and
mandatory Cloudflare inclusion. Standards priority also means refused
extended CONNECT cannot masquerade as a successful 2xx tunnel; that baseline
decision remains in force. Native host/network acceptance is still incomplete,
and the client defects below prevent an honest claim of universal RFC
interoperability with every possible conforming peer.

Runtime edits in this follow-up are limited to `handler.go` and three
vendored HTTP/3 files. The rest is regression coverage, server-owned client
fixtures, strict CI gates, the reproducible patch record and documentation.
Production dependency versions and client sources are unchanged.

## Server changes and why they are necessary

### Delayed HTTP/3 SETTINGS must not disable negotiated Datagrams

The baseline waited three seconds for peer SETTINGS and then permanently
selected Capsules. QUIC delivers streams independently: a request can arrive
while the control stream's bytes are delayed. The server could return 200,
later receive valid `SETTINGS_H3_DATAGRAM=1`, and silently ignore every QUIC
Datagram because the receive loop was never started.

An independent raw-QUIC positive control forwarded the same packet when
SETTINGS arrived promptly; delaying SETTINGS reproduced the failure after
the baseline's three-second success response. This is a server defect, not
evidence of a client violating RFC 9297 section 2.1.1. A sender can have sent
its setting and received its peer's setting while the recipient still awaits
delivery of the sender's control-stream bytes.

The server now waits for actual peer SETTINGS before accepting that tunnel.
The pending request already owns a lease subject to the configured session
quota (default eight; explicitly unlimited configurations also remain bounded
by their address pools). Request cancellation, credential revocation, core
shutdown and route-policy changes
terminate the wait and release the address and quota slot. A failure before
the response starts returns 503 without Capsule success headers, preventing
an implicit 200 when the handler returns. An unchanged reload preserves the
pending request. Once negotiation completes, normal Datagram or Capsule
selection is retained.

Raw-wire regressions cover immediate SETTINGS and a 3.1-second delay,
bidirectional packets, one-session quota enforcement, unchanged reloads,
cancellation, revocation, shutdown and withdrawal of the requested scope.
A retry after withdrawal receives 403; an allowed scope can reuse the released
slot. The implementation does not add a fixed delay to normal connections.

### CONNECT framing and Capsule validation require different treatment

The HTTP/3 client must ignore Content-Length for successful CONNECT framing
(RFC 9110 section 9.3.6). Erasing the field entirely, however, prevents a
Capsule application from enforcing RFC 9297 section 3.2, which prohibits any
Content-Length on Capsule messages. The parser now preserves raw field values
in the response header map while still ignoring their numeric, duplicate and
length-delimiting semantics for generic successful CONNECT. Existing invalid
numeric/duplicate CONNECT cases retain their original wire behavior, and
regressions also require exact metadata preservation.

Capsule responses with status 204, 205 or 206 are specifically forbidden by
RFC 9297 section 3.2. The clients' rejection of those statuses is correct and
is not listed as a defect, despite generic CONNECT accepting other 2xx
responses. This distinction also applies to the existing generic HTTP/3 tests.

### HTTP/3 field validation must reject malformed input and accept valid lists

The baseline's general header-value helper accepted leading/trailing SP and
HTAB. RFC 9114 section 10.3 requires the RFC 9110 field-content grammar, which
excludes those bytes at field edges. Its TE check also rejected valid
case-insensitive or repeated `trailers` list members while accepting TE in
responses. RFC 9114 section 4.2 permits TE only in request headers; RFC 9110
sections 10.1.4 and 5.6.1.2 define its list and empty-member handling.

The parser now applies these rules to requests, responses and trailers.
TE comparison uses ASCII case-insensitivity, so a Unicode long-s lookalike
cannot pass as `trailers`. Outgoing regular fields trim edge SP/HTAB without
changing caller-owned maps; the response writer omits TE. This keeps ordinary
API-generated messages valid
under the stricter receiver checks. Existing internal whitespace, empty field
values and permitted opaque bytes retain their semantics.

Fifteen raw-wire cases cover both directions, prohibited trailers, exact
H3_MESSAGE_ERROR resets, valid TE casing, repeated fields and empty members.
The baseline fails eleven of these cases; four valid/invalid controls already
pass. Additional parser and writer regressions cover normalization and header
map ownership. No unrelated HTTP/2 or QUIC packet code changes in this
follow-up; their earlier repairs and regression gates remain in place.

### Supported Caddy website responses must remain valid HTTP/3

Caddy's `static_response` handler with `close: true` sets `Connection: close`
for its HTTP/1 writer. The baseline HTTP/3 writer serialized it unchanged.
An actual shared-listener Caddy test therefore failed both an ordinary 201
page and a 404 CONNECT-IP refusal: the strict HTTP/3 client rejected the
connection-specific field instead of receiving the configured cover page.
This affected normal supported configuration, not just malicious input.

The writer now omits the standard connection-specific fields and response TE,
plus valid field names nominated by legacy Connection values. Outgoing
trailers apply the same exclusions, including Upgrade, which the inherited
generic trailer helper did not prohibit. RFC 9114 §4.2 and RFC 9110 §7.6.1
govern the conversion. Application header maps remain intact. The permanent
real-Caddy regression uses the same QUIC connection for the website and
refusal checks, preserving status, body, an end-to-end header and an ordinary
trailer. Additional writer tests cover mixed casing, repeated Connection
values, nominated fields and trailer filtering.

## Client-side standards findings

Findings C1–C5 concern receiver behavior on malformed peer input. A conforming
Caddy server does not send those malformed messages. C6 and C7 instead concern
legal informational responses and empty DATA frames, which the normal Caddy
CONNECT-IP handler does not emit. These findings do not justify weakening
server validation or claim
that the ordinary valid exchanges in the matrices failed. No client source
was patched or substituted to make interoperability pass.

The diagnostic project imports the unchanged NF adapter, current vendored h3
and, where stated, the full production NF Client. A synthetic ABI host feeds
HTTP/3 bytes and records native CLOSE requests. It does not execute Apple
QUIC/TLS or capture native network packets. A duplicate-QPACK-stream control
correctly requests 0x103, demonstrating delivery to the active driver.
Eleven diagnostic tests reproduce the stated behavior and that control;
their passing status means successful characterization, not conformance.

| Finding | Required behavior | Confirmed observation and scope |
| --- | --- | --- |
| C1: QPACK critical streams are not monitored | RFC 9204 §§4.2–4.4: critical-stream closure uses 0x104; invalid zero-capacity encoder/decoder instructions use 0x201/0x202. | NF adapter plus shared h3 ignores encoder/decoder FIN, encoder capacity 1 at advertised maximum zero, and a decoder acknowledgment with no dynamic section. Source stores the streams without an instruction/lifetime reader. CLI/IETF/Mac/Killswitch share this h3 source. The independent CF fork has the same relevant reader code; that extension is source-confirmed rather than separately malicious-wire tested. |
| C2: malformed response fields can be accepted | RFC 9114 §§4.1.2, 4.2, 4.3 explicitly reject invalid/request-only pseudo-fields and connection-specific fields. Duplicate-status acceptance is separately interpreted against §4.3.2 single-status semantics; no explicit duplicate-response MUST sentence is asserted. | The NF/shared parser accepts duplicate `:status`, request-only `:path` in a response and `connection: close`. CF's separate parser already fixes the first two; its response connection-field filtering gap remains source-confirmed. Do not transfer the duplicate-field finding to CF. |
| C3: detected malformed responses use the wrong termination code | RFC 9114 §4.1.2 requires H3_MESSAGE_ERROR (0x10e); RFC 9297 §3.2 requires forbidden Capsule content fields to be treated as malformed. | Missing `:status` returns a Rust H3_MESSAGE_ERROR but requests ABI STOP_SENDING/CLOSE 0x10c. The full NF Client detects a forbidden Content-Type response but drops resources with code-zero CLOSE rather than the required message-error reset. The missing-status library branch is shared by the other h3 clients; the full-Client Content-Type observation is specifically proven through NF. |
| C4: HEADERS after successful CONNECT is accepted as trailer EOF | RFC 9114 §4.4 and RFC 9297 §3.2 require CONNECT framing; prohibited HEADERS requires connection error 0x105. | NF/shared h3 returns ordinary EOF with no 0x105. The CF fork has an opt-in trailer guard, but its generic client does not enable it; the corresponding CF conclusion is based on source review. |
| C5: malformed HTTP Datagram prefixes are dropped silently | RFC 9297 §2.1 requires connection error H3_DATAGRAM_ERROR (0x33) for an unparseable Quarter Stream ID or one above 2^60−1. | Full production NF Client consumes an empty Datagram and an encoded Quarter Stream ID of 2^60 without the required close. Its native Datagram loop treats decode/range failure like a valid unrelated-stream Datagram. This finding is specific to NF; it is not transferred to CF's separate h3-datagram decoder. |
| C6: legal informational responses prematurely fail CONNECT-IP | RFC 9110 §15.2 requires clients to parse one or more 1xx responses before the final response; RFC 9114 §4.1 permits them. | An independent full-NF-Client diagnostic connects with final 200 plus valid Capsules, but refuses the identical exchange when preceded by legal 100 or 103 HEADERS. Shared and CF client code each calls `recv_response` once and immediately validates its status; those extensions are source-confirmed. This can break interoperability with a conforming intermediary that emits 1xx; ordinary Caddy acceptance needs no workaround. |
| C7: a legal empty DATA frame is treated as tunnel EOF | RFC 9114 §§4.1, 7.2.1 permit zero-length DATA and delimit the response by stream closure; RFC 9297 §3.1 defines Capsule bytes across DATA frames. | Full unchanged NF Client connects with final 200 and valid address/route Capsules, but reports “tunnel ended before an address was assigned” when a zero-length DATA frame precedes the identical Capsules, without peer FIN. Shared h3 returns None for the empty frame and its callers treat it as EOF; CLI/IETF/Mac/Killswitch use that same source path. CF's separate fork already loops past empty frames and is not affected by this finding. |

Source locations in the pinned client tree:

* C1: `vendor/h3/src/connection.rs`, peer QPACK stream handling around lines
  448–462; the associated receive fields have no instruction/lifetime poller.
* C2: `vendor/h3/src/proto/headers.rs`, pseudo-field conversion and response
  construction around lines 109–120 and 228–306.
* C3: `vendor/h3/src/client/stream.rs`, response field conversion around lines
  177–192; NF `Core/src/client.rs`, `open_h3` and `check_response`; NF
  `Core/src/quic.rs`, native stop-sending forwarding.
* C4: `vendor/h3/src/connection.rs`, `poll_recv_data` HEADERS branch around
  lines 874–877; NF `Core/src/tunnel.rs`, HTTP/3 read pump.
* C5: `masque-nf/Core/src/client.rs`, native Datagram association check around
  lines 269–273.
* C6: NF `Core/src/client.rs` lines 252–263; shared
  `crates/masque-vpn/src/client.rs` lines 476–489; CF
  `masque-vpn-cf-masque/vendor/masque-frontend/src/client.rs` lines 452–459;
  their h3 `client/stream.rs` returns the first HEADERS response.
* C7: shared `vendor/h3/src/connection.rs` around line 869 and
  `crates/masque-vpn/src/tunnel.rs` around line 153; NF
  `Core/src/tunnel.rs` consumes the same receive result. CF's corresponding
  connection code uses a loop instead of the shared fork's single `if`.

The separate informational-response diagnostic has one passing
characterization test containing the final-200 positive control and both
interim-status reproductions. It uses an external project copy; neither
client checkout nor the original eleven-test diagnostic project was changed.
Another independent single-test diagnostic reproduces C7 with and without
the empty frame. Both diagnostics retain final-200 success controls, isolating
the legal framing difference from credentials, addressing or policy.

The shared Client's address, Capsule, transport negotiation and unused-IPv6
probe paths were reviewed separately. No additional confirmed fault causing
ordinary current-Caddy interoperability failure was established in those
paths. An unchanged client unit regression confirms its correct Capsule
response checks. NF's unchanged ordinary portable suites also pass 76 tests:
43 library, 9 FFI lifecycle and 24 native-boundary memory tests. Those suites
do not eliminate the malformed-input findings above.

## Reload stress diagnosis and test reliability

An earlier full Go 1.27 race run failed
`TestCaddyEndsTunnelsBlockedOnNewRoutes` with an unexpected EOF. Diagnostic
logging reproduced the exact failure on HTTP/1.1's first response, after TLS
and request-header writing, rather than in route withdrawal or tunnel DATA.
Direct 500-connection reload stress produced seven such EOFs on Go 1.27 and
one on Go 1.26. Overlaying the exact previously committed `handler.go` still
produced three in 500 on Go 1.27. The new HTTP/3 changes are not necessary to
trigger it.

Caddy 2.11.7 overlaps listener generations and signals that its shutdown
goroutine started before calling the old server's Shutdown
(`modules/caddyhttp/app.go` lines 779–784 and 850–853). Go's HTTP/1 server can
then finish reading a request but return without a response when shutdown
begins (`net/http/server.go`: Go 1.27 lines 2075–2083; Go 1.26 around 2014).
Waiting for a listener reference count of one did not remove the window.
Existing established-tunnel lifecycle assertions are a separate check.

The test helper already retried dialing/TLS ECONNRESET. Its HTTP/1 response
setup now additionally peeks one byte, retrying only EOF/unexpected EOF/reset
while **zero response bytes** have arrived. It closes failed connections and
uses at most five attempts with a 50 ms delay. Once any byte arrives, parser
errors fail immediately. Certificate failures, parsed refusal statuses,
Capsules and lifecycle assertions retain their original requirements.
Both Go versions pass 500 immediate-reload connections through this helper,
including 101, ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT, plus ten repetitions
of the original affected test. Failed diagnostic runs remain in the evidence.
This is a test-fixture correction; the upstream fresh-connection shutdown
window itself was not changed by a Caddy dependency fork.

A later full Go 1.27 run caught another inherited fixture defect:
`TestNetworkPacketsReachTheirClient` called `10.89.0.250` “nobody's address”,
but the production pool randomly allocates that address to real sessions.
When Bob owns it, receiving the packet is correct. Two adjacent tests made
similar assumptions that `.200` was a spoofed source and `.77` differed from
the client's assigned address. The fixtures now choose an actually unused
pool address excluding their current leases. Packet isolation, drop counters
and explicit-address refusal assertions are preserved. Deterministic forced
leases reproduce the old mistakes; this correction changes no allocator or
packet-forwarding behavior. Both toolchains pass 100 repetitions of the
packet-delivery test and 20 each of the source-drop and address-request tests.
Forced `.250`/`.251` leases also exercise both exclusions before selecting
`.252`.

A separate DEBUG/event-subscriber stress diagnostic exposed an inherited
Caddy TLS race: `caddytls.TLS.Start` writes background-context fields while
event emission calls value-receiver `TLS.CaddyModule`, copying that value
(`modules/caddytls/tls.go` around 424; `modules/caddyevents/app.go` around
207–240). It is recorded separately from ordinary ERROR-level test runs,
which report no race. No suppression or dependency patch was added. This
upstream finding remains a limit on claiming race-free behavior under every
logging/event configuration.

## Validation ledger

The final portable acceptance used Linux amd64, Go 1.26.9 and 1.27.2,
Rust 1.99.0, optimized locked Rust harnesses, and Go race checking. Production
source remained fixed during these final matrices. Later test-source changes
corrected the separately diagnosed HTTP/1 response and random-address
fixtures; the full main suite was restarted on those final fixtures.
Source manifests and log hashes
record the distinction. Counts below distinguish top-level tests from nested
cases; they must not be added to the 41 client matrix cases as independent
coverage.

| Gate | Go 1.26.9 | Go 1.27.2 |
| --- | --- | --- |
| Full main `go test -mod=readonly -race -count=1 -json ./...`, real current CLI enabled | 178 top-level + 145 nested passes; zero failures | 178 top-level + 145 nested passes; zero failures |
| Full patched HTTP/3 and qlog `-race ./http3/...` | 546 pass events; zero failure/skip | 546 pass events; zero failure/skip |
| Actual unchanged CLI, including five stdin/EOF GUI-process cases | 9/9 required cases | 9/9 required cases |
| Mac/Killswitch/NF official combined matrix | 24/24 distinct cases; zero failure/skip | 24/24 distinct cases; zero failure/skip |
| Independent CF generic frontend | 8/8 distinct cases; zero failure/skip | 8/8 distinct cases; zero failure/skip |
| Final HTTP/1 helper, 500 immediate reloads with assignment/routes | 500/500 | 500/500 |
| `go vet ./...`, optimized normal build and required module registration | Passed | Passed |

Each NF matrix additionally completes 14 H3 controls, for 22 packet/TCP/DNS
subruns and eight authentication negatives per toolchain. The HTTP/3 total is
161 top-level plus 367 nested HTTP/3 passes, and 13 top-level plus five nested
qlog passes. The 15-case raw field group checks exact wire errors, not just
local parser return values.

The main suite's four expected test skips are explicit: three nft ruleset
syntax cases because `nft` is unavailable, and the ordinary invocation of a
subprocess-only lifecycle helper, whose parent tests execute the helper in
its intended mode. Two packages with no test files are reported separately.
No CLI, wrapper, NF or CF matrix case is skipped. Privileged kernel and native
acceptance remain unrun locally, as described below.

`go mod verify` and both full-tree fork verifiers pass. The HTTP/3 patch record
was regenerated from the original pinned baseline, including earlier repairs,
and reconstructs every shipped dependency byte without fuzzy/offset matching.
Independent review and `git diff --check` pass; all changed Go files and both
Go overlays are formatted. Actionlint passes all four workflows; 32 embedded
Bash blocks and both Python runners pass syntax/compile checks. CI now requires
all nine CLI, 24 wrapper and eight CF cases, rejects skipped/missing cases,
and checks that the client source checkout remains clean. Strict native
architecture, kernel/wire and exact-artifact promotion gates are retained.

The local optimized Linux amd64 builds both register `masque`,
`http.handlers.masque` and `dns.providers.cloudflare` (v0.2.4):

| Toolchain | Working-tree executable SHA-256 |
| --- | --- |
| Go 1.26.9 | `181e4e4948a2d017ba00269c5a68c2b2f13b5ddf59e1a9ab72c217ccf1c28e76` |
| Go 1.27.2 | `7406748101e4f7b0b563e3d86c4471e9b9746e6d092ce8983b20342274fd61e5` |

These hashes identify local build checks, not a claim that a native kernel or
Apple release gate ran on those executables. The CI release procedure tests
and packages its exact artifact without rebuilding it afterward.

From the repository root, repeat the affected acceptance with each Go version:

```sh
MASQUE_CLIENT=/path/to/unchanged/masque-client go test -mod=readonly -race -count=1 ./...
python3 tests/run-client-wrapper-interop.py --masque-vpn-root /path/to/masque-vpn --release
python3 tests/run-cf-client-interop.py --masque-vpn-root /path/to/masque-vpn --release
(cd third_party/quic-go && go test -race -count=1 ./http3/...)
go vet ./...
go mod verify
python3 tests/verify-http2-fork.py
python3 tests/verify-http3-fork.py
```

Build the current real CLI with its unchanged upstream locked manifest before
setting `MASQUE_CLIENT`. Harness lockfiles intentionally fail on incompatible
client dependency drift; refresh only the server-owned harness after review.
Detailed final logs, source identities and JSON summaries are under
`/workspace/fix-validation/all-clients`; reproduction diagnostics are also in
`/workspace/fix-validation/blocked-routes-diagnosis`, `review`, `http3` and
`client-rfc`. Client-defect projects are characterization evidence, not
passing client conformance suites. The evidence archive is
`/workspace/caddy-masque-all-client-validation-2026-10-18.tar.gz`.

## Practical limits and remaining native acceptance

The portable NF matrix deliberately retains H3 when a usable native Datagram
capacity of 0, 1168, 1172 or 1288 bytes selects Capsules. A 1289-byte control
uses QUIC Datagrams. A separate case retains unwritten stream 0 while the
actual request uses stream 4; this is legal QUIC behavior, not a client RFC
violation. Tests also retain default GREASE, open QPACK streams and original
client deadlines. They do not hide forced-H3 failures by changing transports
or disabling MTU checks.

The client repository documents an unresolved native Network.framework H3
incident. An apparent local write, model test, replacement transport or one
historical native admission cannot establish that incident is repaired.
Supported Apple-silicon/macOS 27/Xcode 27 execution is still needed for native
TLS/QUIC, GUI lifecycle, utun/PF/routes/DNS restoration, sleep/network changes,
and sustained TCP/UDP/DNS exchanges against this exact server revision.
Swift/Network.framework are not available in this Linux environment. Thus
this work does not claim perfect native interoperability or certification.

Linux kernel forwarding, nftables and system/LAN-gateway acceptance also
require TUN/CAP_NET_ADMIN, unavailable here. Strict CI kernel/wire gates remain
enabled. Native arm64 and physical-network benchmarks were not substituted
with cross-compilation or in-memory packet tests.

Dual-stack admission remains atomic across configured address families: an
exhausted IPv6 pool can reject a wildcard request even when IPv4 addresses
remain. This is an existing availability policy, not a mandatory RFC failure;
silently degrading address families could change host routing/isolation
expectations. No such policy change was introduced. Configure both pools with
adequate capacity.

Cloudflare DNS remains mandatory in every build. No credential, certificate
verification, default IPv6 MTU protection or production dependency pin was
relaxed to accommodate a client defect.
